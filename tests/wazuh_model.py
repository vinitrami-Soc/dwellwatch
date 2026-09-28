"""A small model of Wazuh evaluating DwellWatch's generated rules, for equivalence tests.

It reproduces what the generated rules depend on, as Wazuh 4.14.8's own ruleset shows it:

- Field names: the eventchannel decoder puts System values under win.system and EventData values
  under win.eventdata in lowerCamelCase (Image -> win.eventdata.image).
- Values stay JSON-escaped: backslashes arrive doubled and quotes as \\" (the events in Wazuh's
  ruleset/testing/tests/sysmon_eid_1.ini).
- Parents: <if_group>sysmon_event1</if_group> is reached by Sysmon event 1 at severity
  INFORMATION (rules 60004, 61600, 61603), and sysmon_event_10 and sysmon_event_11 likewise by
  events 10 and 11 (61612, 61613); <if_sid>60103</if_sid> by a Security event at severity
  AUDIT_SUCCESS (rules 60001, 60103).

Fields are matched with the PCRE2 library itself, as Wazuh's type="pcre2" does.

Wazuh tries sibling rules from the highest level down, built-in rules first on a tie, and stops at
the first match. rivals() lists the built-in siblings that could therefore take an event from a
DwellWatch rule, so the tests can show that none does.
"""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import pcre2

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYSTEM_FIELDS = {"EventID": "eventID", "Channel": "channel", "Computer": "computer",
                 "Provider_Name": "providerName", "TimeCreated": "systemTime"}


def wazuh_event(event):
    """A flat event from replay.load_events, as Wazuh's decoded fields."""
    fields = {}
    for key, value in event.items():
        if key in SYSTEM_FIELDS:
            fields[f"win.system.{SYSTEM_FIELDS[key]}"] = value
        else:
            fields[f"win.eventdata.{key[:1].lower()}{key[1:]}"] = value.replace("\\", "\\\\").replace('"', '\\"')
    fields["win.system.severityValue"] = "AUDIT_SUCCESS" if event.get("Channel") == "Security" else "INFORMATION"
    return fields


@dataclass
class WazuhRule:
    id: int
    level: int
    if_group: str | None
    if_sid: str | None
    fields: list  # (field name, compiled pattern)


def load_rules(xml_texts):
    rules = []
    for text in xml_texts:
        for rule in ET.fromstring(f"<root>{text}</root>").iter("rule"):
            rules.append(WazuhRule(
                id=int(rule.get("id")),
                level=int(rule.get("level")),
                if_group=rule.findtext("if_group"),
                if_sid=rule.findtext("if_sid"),
                # untyped fields are Wazuh's own regex type; the only one used here is ^4688$
                fields=[(field.get("name"), pcre2.compile(field.text)) for field in rule.iter("field")],
            ))
    return rules


def reaches(rule, fields):
    """Whether the event gets as far as this rule's parent."""
    channel, event_id = fields.get("win.system.channel"), fields.get("win.system.eventID")
    severity = fields["win.system.severityValue"]
    sysmon_event = {"sysmon_event1": "1", "sysmon_event_10": "10", "sysmon_event_11": "11"}
    if rule.if_group in sysmon_event:
        return (channel, event_id, severity) == (SYSMON, sysmon_event[rule.if_group], "INFORMATION")
    if rule.if_sid == "60103":
        return (channel, severity) == ("Security", "AUDIT_SUCCESS")
    raise ValueError(f"rule {rule.id} has a parent the model does not know")


def fires(rule, fields):
    return reaches(rule, fields) and all(
        name in fields and pattern.search(fields[name]) is not None for name, pattern in rule.fields)


# --- Wazuh's own rules beside DwellWatch's ----------------------------------------------------

# Every rule under 60103 (successful Security events) in Wazuh 4.14.8, with its level and the event
# IDs it matches (0580-win-security_rules.xml and 0955-WEF-baseline_rules.xml). All of them test
# the event ID, most of them nothing else, so matching the ID is enough to say one could match.
SECURITY_SUCCESS_RIVALS = [
    (60115, 9, {"644", "4740"}),
    (60109, 8, {"624", "626", "4720", "4722"}),
    (60110, 8, {"628", "642", "685", "4738", "4781"}),
    (60111, 8, {"630", "629", "4725", "4726"}),
    (60112, 8, {"612", "643", "4719", "4907", "4912"}),
    (60114, 8, {"640"}),
    (60208, 8, {"4646"}), (60211, 8, {"4983", "4984"}), (60213, 8, {"4961", "4962"}), (60214, 8, {"4963"}),
    (60219, 8, {"5453"}), (60224, 8, {"4710"}), (60227, 8, {"6416"}),
    (60116, 7, {"513", "4609"}), (60216, 7, {"4976"}), (60217, 7, {"4977"}), (60218, 7, {"4978"}),
    (60113, 5, {"4728", "4729", "4732", "4733", "4735", "4737", "4755", "4756", "4757", "4764", "4766",
                "4745", "4746", "4747", "4750", "4751", "4752", "4760", "4761", "4762"}),
    (60121, 5, {"4741", "4742", "4743"}), (60132, 5, {"520", "4616"}), (60133, 5, {"671", "4767"}),
    (60138, 5, {"4727", "4731", "4754", "4744", "4749", "4759"}),
    (60139, 5, {"4730", "4734", "4758", "4748", "4753", "4763"}),
    (60212, 4, {"4960"}), (60215, 4, {"4965"}), (60228, 4, {"4698"}), (60229, 4, {"5136"}),
    (60230, 4, {"5137"}), (60231, 4, {"5141"}),
    (60106, 3, {"528", "540", "673", "4624", "4769"}), (60108, 3, {"682", "683", "4778", "4779"}),
    (60136, 3, {"4608"}), (60137, 3, {"538", "551", "4634", "4647"}),
    (67017, 3, {"5140"}), (67025, 3, {"5142"}), (67026, 3, {"5144"}), (67027, 3, {"4688"}), (67028, 3, {"4672"}),
]


def _name(path):
    return path.rsplit("\\", 1)[-1].lower()


def _base(event, key):
    return _name(event.get(key, ""))


def _low(event, key):
    return event.get(key, "").lower()


SYSTEM_PROCESSES = {"svchost.exe", "lsm.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "wininit.exe", "smss.exe",
                    "taskhost.exe", "services.exe", "dllhost.exe", "explorer.exe"}
SCRIPT_OR_BINARY = re.compile(r"\.(exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|lnk|msi|vbe)", re.I)

# The built-in rules at level 10 or more that hang beside DwellWatch's, by parent group, from
# Wazuh 4.14.8's 0800-sysmon_id_1.xml, 0595-win-sysmon_rules.xml (and its copy 0330),
# 0910-ms-exchange-proxylogon_rules.xml, 0945-sysmon_id_10.xml and 0830-sysmon_id_11.xml.
# Each test is looser than the rule it stands for: it may say a rule could match when Wazuh's
# would not, never the reverse.
RIVALS = {
    "sysmon_event1": [
        (92016, 13, lambda e: _low(e, "OriginalFileName") == "certutil.exe"),  # renamed certutil
        (92018, 13, lambda e: _low(e, "OriginalFileName") == "certutil.exe"),  # certutil decode
        (92019, 13, lambda e: _low(e, "OriginalFileName") == "msmpeng.exe"),  # Defender from an odd path
        (92046, 12, lambda e: _base(e, "ParentImage") == "fodhelper.exe"),
        (92047, 12, lambda e: _low(e, "OriginalFileName") == "mshta.exe"),
        (92049, 12, lambda e: "verclsid" in _low(e, "CommandLine")),
        (92051, 12, lambda e: _low(e, "OriginalFileName") == "wscript.exe"),
        (92053, 12, lambda e: "jscript" in _low(e, "ParentCommandLine")),
        (92054, 14, lambda e: "svchost.exe -k netsvcs" in _low(e, "ParentCommandLine")),
        (92055, 12, lambda e: _low(e, "OriginalFileName") in ("computerdefaults.exe", "fodhelper.exe")),
        (92057, 12, lambda e: _base(e, "ParentImage") == "powershell.exe"
            and re.search(r"powershell\.exe.+ -e", _low(e, "CommandLine"))),
        (92058, 12, lambda e: _low(e, "OriginalFileName") == "sdbinst.exe"),
        (92060, 15, lambda e: "\u202e" in e.get("ParentImage", "")),
        (92062, 14, lambda e: _base(e, "ParentImage") == "control.exe" and _base(e, "Image") == "powershell.exe"),
        (92064, 15, lambda e: "\u202e" in e.get("Image", "")),
        (92074, 12, lambda e: _low(e, "OriginalFileName") in ("curl.exe", "wget.exe")),
        (92075, 12, lambda e: _low(e, "OriginalFileName") == "certutil.exe"),
        (92077, 10, lambda e: "securitycenter2" in _low(e, "CommandLine")),
        (92078, 10, lambda e: "cmd.exe" in _low(e, "CommandLine")),  # its E:\ working-directory test dropped
        (92081, 15, lambda e: _low(e, "OriginalFileName") == "rundll32.exe"
            and re.search(r'.(html|htm|txt|png|jpg|pdf)[\\"]*,#', _low(e, "CommandLine"))),
        # 61618 to 61640: a system process's name on the wrong binary or under the wrong parent
        (61618, 12, lambda e: _base(e, "Image") in SYSTEM_PROCESSES
            or _base(e, "ParentImage") in ("lsm.exe", "lsass.exe")),
        (91000, 12, lambda e: _base(e, "ParentImage") == "umworkerprocess.exe"),
        (91006, 12, lambda e: "microsoft.exchange" in _low(e, "CommandLine")),
        (91007, 12, lambda e: "system.net.sockets.tcpclient" in _low(e, "CommandLine")),
    ],
    "sysmon_event_10": [
        (92900, 12, lambda e: _base(e, "TargetImage") == "lsass.exe"),  # 0x1010 or 0x40, not from Program Files
        (92910, 12, lambda e: _base(e, "TargetImage") == "explorer.exe"),
        (92920, 14, lambda e: _base(e, "TargetImage") == "mstsc.exe"),
    ],
    "sysmon_event_11": [
        (92206, 12, lambda e: _base(e, "Image") == "spoolsv.exe"),
        (92207, 12, lambda e: "\\users\\public\\" in _low(e, "TargetFilename")
            and SCRIPT_OR_BINARY.search(e.get("TargetFilename", ""))),
        (92211, 14, lambda e: _base(e, "Image") == "rundll32.exe"
            and SCRIPT_OR_BINARY.search(e.get("TargetFilename", ""))),
        (92212, 14, lambda e: _base(e, "Image") == "powershell.exe"
            and re.search(r"\.(7z|zip|rar)", _low(e, "TargetFilename"))),
        (92213, 15, lambda e: "\\appdata\\local\\temp\\" in _low(e, "TargetFilename")
            and SCRIPT_OR_BINARY.search(e.get("TargetFilename", ""))),
        (92214, 15, lambda e: _base(e, "Image") in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")),
        (92215, 12, lambda e: _base(e, "Image") == "mshta.exe"),
    ],
}


def rivals(rule, event):
    """The built-in rules that Wazuh would try before `rule` and that could match `event`."""
    if rule.if_sid == "60103":
        return [rival for rival, level, event_ids in SECURITY_SUCCESS_RIVALS
                if level >= rule.level and event.get("EventID") in event_ids]
    if rule.if_group not in RIVALS:
        raise ValueError(f"rule {rule.id} has a parent the model does not know")
    return [rival for rival, level, could_match in RIVALS[rule.if_group]
            if level >= rule.level and could_match(event)]
