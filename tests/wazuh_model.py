"""A small model of Wazuh evaluating DwellWatch's generated rules, for equivalence tests.

It reproduces what the generated rules depend on, as Wazuh 4.14.8's own ruleset shows it:

- Field names: the eventchannel decoder puts System values under win.system and EventData values
  under win.eventdata in lowerCamelCase (Image -> win.eventdata.image).
- Values stay JSON-escaped: backslashes arrive doubled and quotes as \\" (the events in Wazuh's
  ruleset/testing/tests/sysmon_eid_1.ini).
- Parents: <if_group>sysmon_event1</if_group> is reached by Sysmon event 1 at severity
  INFORMATION (rules 60004, 61600, 61603); <if_sid>60103</if_sid> by a Security event at severity
  AUDIT_SUCCESS (rules 60001, 60103).

Fields are matched with the PCRE2 library itself, as Wazuh's type="pcre2" does. The model does
not decide between sibling rules that both match; convert.py's choice of levels covers that.
"""

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
