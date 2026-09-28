"""A small model of Wazuh evaluating DwellWatch's generated rules, for equivalence tests.

It reproduces what the generated rules depend on, as Wazuh 4.14.8's own ruleset shows it:

- Field names: the eventchannel decoder puts System values under win.system and EventData values
  under win.eventdata in lowerCamelCase (Image -> win.eventdata.image).
- Values stay JSON-escaped: backslashes arrive doubled and quotes as \\" (the events in Wazuh's
  ruleset/testing/tests/sysmon_eid_1.ini).
- Parents: <if_group>sysmon_event1</if_group> is reached by Sysmon event 1 at severity
  INFORMATION (rules 60004, 61600, 61603); <if_sid>60103</if_sid> by a Security event at severity
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
    if rule.if_group == "sysmon_event1":
        return (channel, event_id, severity) == (SYSMON, "1", "INFORMATION")
    if rule.if_sid == "60103":
        return (channel, severity) == ("Security", "AUDIT_SUCCESS")
    raise ValueError(f"rule {rule.id} has a parent the model does not know")


def fires(rule, fields):
    return reaches(rule, fields) and all(
        name in fields and pattern.search(fields[name]) is not None for name, pattern in rule.fields)


# --- Wazuh's own rules beside DwellWatch's ----------------------------------------------------

# Every child of rule 60103 in Wazuh 4.14.8 is at level 9 or below (60115, account locked out).
SECURITY_SUCCESS_MAX_LEVEL = 9


def _name(path):
    return path.rsplit("\\", 1)[-1].lower()


def _fields(event):
    return (_name(event.get("Image", "")), event.get("OriginalFileName", "").lower(),
            _name(event.get("ParentImage", "")), event.get("CommandLine", "").lower(),
            event.get("ParentCommandLine", "").lower())


SYSTEM_PROCESSES = {"svchost.exe", "lsm.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "wininit.exe", "smss.exe",
                    "taskhost.exe", "services.exe", "dllhost.exe", "explorer.exe"}

# The built-in Sysmon event 1 rules at level 10 or more that hang beside DwellWatch's, from
# 0800-sysmon_id_1.xml, 0595-win-sysmon_rules.xml (and its copy 0330) and
# 0910-ms-exchange-proxylogon_rules.xml. Each test is looser than the rule it stands for: it may
# say a rule could match when Wazuh's would not, never the reverse.
SYSMON_1_RIVALS = [
    (92016, 13, lambda img, ofn, par, cl, pcl: ofn == "certutil.exe"),  # renamed certutil
    (92018, 13, lambda img, ofn, par, cl, pcl: ofn == "certutil.exe"),  # certutil decode
    (92019, 13, lambda img, ofn, par, cl, pcl: ofn == "msmpeng.exe"),  # Defender from an odd path
    (92046, 12, lambda img, ofn, par, cl, pcl: par == "fodhelper.exe"),
    (92047, 12, lambda img, ofn, par, cl, pcl: ofn == "mshta.exe"),
    (92049, 12, lambda img, ofn, par, cl, pcl: "verclsid" in cl),
    (92051, 12, lambda img, ofn, par, cl, pcl: ofn == "wscript.exe"),
    (92053, 12, lambda img, ofn, par, cl, pcl: "jscript" in pcl),
    (92054, 14, lambda img, ofn, par, cl, pcl: "svchost.exe -k netsvcs" in pcl),
    (92055, 12, lambda img, ofn, par, cl, pcl: ofn in ("computerdefaults.exe", "fodhelper.exe")),
    (92057, 12, lambda img, ofn, par, cl, pcl: par == "powershell.exe" and re.search(r"powershell\.exe.+ -e", cl)),
    (92058, 12, lambda img, ofn, par, cl, pcl: ofn == "sdbinst.exe"),
    (92060, 15, lambda img, ofn, par, cl, pcl: "\u202e" in par),
    (92062, 14, lambda img, ofn, par, cl, pcl: par == "control.exe" and img == "powershell.exe"),
    (92064, 15, lambda img, ofn, par, cl, pcl: "\u202e" in img),
    (92074, 12, lambda img, ofn, par, cl, pcl: ofn in ("curl.exe", "wget.exe")),
    (92075, 12, lambda img, ofn, par, cl, pcl: ofn == "certutil.exe"),
    (92077, 10, lambda img, ofn, par, cl, pcl: "securitycenter2" in cl),
    (92078, 10, lambda img, ofn, par, cl, pcl: "cmd.exe" in cl),  # its E:\ working-directory test dropped
    (92081, 15, lambda img, ofn, par, cl, pcl: ofn == "rundll32.exe"),
    # 61618 to 61640: a system process's name on the wrong binary or under the wrong parent
    (61618, 12, lambda img, ofn, par, cl, pcl: img in SYSTEM_PROCESSES or par in ("lsm.exe", "lsass.exe")),
    (91000, 12, lambda img, ofn, par, cl, pcl: par == "umworkerprocess.exe"),
    (91006, 12, lambda img, ofn, par, cl, pcl: "microsoft.exchange" in cl),
    (91007, 12, lambda img, ofn, par, cl, pcl: "system.net.sockets.tcpclient" in cl),
]


def rivals(rule, event):
    """The built-in rules that Wazuh would try before `rule` and that could match `event`."""
    if rule.if_sid == "60103":
        return [] if rule.level > SECURITY_SUCCESS_MAX_LEVEL else ["a child of 60103"]
    if rule.if_group != "sysmon_event1":
        raise ValueError(f"rule {rule.id} has a parent the model does not know")
    fields = _fields(event)
    return [rival for rival, level, could_match in SYSMON_1_RIVALS if level >= rule.level and could_match(*fields)]
