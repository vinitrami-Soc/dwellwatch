"""The replay engine itself: reading event files, normalising them, and evaluating Sigma."""

import json
import textwrap
from datetime import UTC, datetime

import pytest

from dwellwatch.models import Stage
from dwellwatch.replay import UnsupportedRule, event_time, load_events, load_rule, replay

from conftest import ROOT, process_event

SYSMON_XML = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>"
    "<EventID>1</EventID><TimeCreated SystemTime='2021-01-22T20:43:31.123456700Z'/>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>dc01.lab.local</Computer></System>"
    "<EventData><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
    "<Data Name='CommandLine'>cmd /c \"a &amp; b\"</Data><Data Name='User'>LAB\\admin</Data></EventData></Event>"
)


def test_reads_windows_event_xml(tmp_path):
    path = tmp_path / "sysmon.log"
    path.write_text(SYSMON_XML + "\n" + SYSMON_XML + "\n")
    events = list(load_events(path))
    assert len(events) == 2
    assert events[0] == {
        "Provider_Name": "Microsoft-Windows-Sysmon",
        "EventID": "1",
        "TimeCreated": "2021-01-22T20:43:31.123456700Z",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "dc01.lab.local",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": 'cmd /c "a & b"',
        "User": "LAB\\admin",
    }


def test_reads_evtx_dump_json_lines(tmp_path):
    record = {"Event": {
        "System": {
            "EventID": {"#attributes": {"Qualifiers": 0}, "#text": 4688},
            "Channel": "Security",
            "Computer": "dc01.lab.local",
            "TimeCreated": {"#attributes": {"SystemTime": "2023-10-03T15:53:57.998961Z"}},
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
        },
        "EventData": {"NewProcessName": "C:\\Windows\\System32\\vssadmin.exe", "ProcessId": 5756,
                      "CommandLine": "vssadmin delete shadows /all", "TargetUserName": None},
    }}
    path = tmp_path / "security.jsonl"
    path.write_text(json.dumps(record) + "\n\n")
    [event] = load_events(path)
    assert event["EventID"] == "4688"
    assert event["ProcessId"] == "5756"
    assert event["TimeCreated"] == "2023-10-03T15:53:57.998961Z"
    assert "TargetUserName" not in event


def test_reads_a_json_array_of_flat_events(tmp_path):
    path = tmp_path / "planted.json"
    path.write_text(json.dumps([process_event("whoami", "C:\\Windows\\System32\\whoami.exe")]))
    [event] = load_events(path)
    assert event["CommandLine"] == "whoami"


def security_4688(**fields):
    return {"EventID": "4688", "Channel": "Security", "Computer": "dc01.lab.local",
            "TimeCreated": "2023-10-03T15:53:57.9989617Z", "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet", "SubjectUserName": "helpdesk1",
            "SubjectDomainName": "LAB", "TargetUserName": "-", "TargetDomainName": "-", **fields}


def test_security_4688_is_matched_with_sysmon_field_names(stage5_vssadmin):
    [signal] = replay([security_4688()], [stage5_vssadmin])
    assert signal.user == "LAB\\helpdesk1"
    # When 4688 names a target account, the process ran as that account.
    [signal] = replay([security_4688(TargetUserName="svc_backup", TargetDomainName="LAB")], [stage5_vssadmin])
    assert signal.user == "LAB\\svc_backup"


def test_rules_only_see_the_events_their_logsource_covers(stage5_vssadmin):
    event = process_event("vssadmin delete shadows /all", "C:\\Windows\\System32\\vssadmin.exe")
    assert len(replay([event], [stage5_vssadmin])) == 1
    assert replay([{**event, "EventID": "11"}], [stage5_vssadmin]) == []  # a file event, not a process
    assert replay([{**event, "Channel": "Application"}], [stage5_vssadmin]) == []


def test_event_times_are_utc_and_tolerate_windows_precision():
    assert event_time({"TimeCreated": "2021-01-22T20:43:31.1234567Z"}) == \
        datetime(2021, 1, 22, 20, 43, 31, 123456, tzinfo=UTC)
    assert event_time({"UtcTime": "2021-01-22 20:43:31.068"}) == \
        datetime(2021, 1, 22, 20, 43, 31, 68000, tzinfo=UTC)
    with pytest.raises(ValueError, match="no timestamp"):
        event_time({"EventID": "1"})


@pytest.fixture
def stage5_vssadmin():
    return load_rule(ROOT / "sigma" / "stage5_backup_destruction" / "vssadmin_shadow_delete.yml")


# --- Sigma features, through small rules written for the test --------------------------------

RULE = """\
title: Test rule
id: 11111111-2222-4333-8444-555555555555
tags: [{tags}]
logsource: {{category: {category}, product: windows}}
detection:
{detection}
level: medium
"""


def write_rule(tmp_path, detection, *, folder="stage2_remote_discovery", tags="attack.discovery, attack.t1087.002",
               category="process_creation"):
    path = tmp_path / folder / "rule.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(RULE.format(tags=tags, category=category, detection=textwrap.indent(detection, "  ")))
    return path


def matches(rule, **fields):
    event = process_event(fields.pop("CommandLine", ""), fields.pop("Image", "C:\\x.exe"))
    event.update(fields)
    return bool(replay([event], [rule]))


def test_rule_takes_its_stage_from_its_folder_and_technique_from_its_tags(tmp_path):
    rule = load_rule(write_rule(tmp_path, "sel: {CommandLine: x}\ncondition: sel"))
    assert rule.stage is Stage.REMOTE_DISCOVERY
    assert rule.attack_technique == "T1087.002"


def test_one_of_and_not(tmp_path):
    rule = load_rule(write_rule(tmp_path, textwrap.dedent("""\
        img_net: {Image|endswith: '\\net.exe'}
        img_net1: {Image|endswith: '\\net1.exe'}
        cli: {CommandLine|contains: 'domain admins'}
        filter_user: {User: 'LAB\\admin'}
        condition: 1 of img_* and cli and not filter_user
    """)))
    assert matches(rule, Image="C:\\Windows\\net1.exe", CommandLine='net group "Domain Admins" /domain')
    assert not matches(rule, Image="C:\\Windows\\net1.exe", CommandLine="net user")
    assert not matches(rule, Image="C:\\Windows\\net.exe", CommandLine='net group "domain admins"',
                       User="LAB\\admin")


def test_numbers_null_and_cased_strings(tmp_path):
    rule = load_rule(write_rule(tmp_path, textwrap.dedent("""\
        sel: {LogonType: 3, TargetDomainName: null, CommandLine|cased: 'Exact'}
        condition: sel
    """)))
    assert matches(rule, LogonType="3", CommandLine="Exact")
    assert not matches(rule, LogonType="10", CommandLine="Exact")
    assert not matches(rule, LogonType="3", CommandLine="exact")
    assert not matches(rule, LogonType="3", CommandLine="Exact", TargetDomainName="LAB")


@pytest.mark.parametrize("kwargs, detection, reason", [
    ({}, "sel: {SourceIp|cidr: 10.0.0.0/8}\ncondition: sel", "SigmaCIDRExpression"),
    ({}, "keywords: [mimikatz]\ncondition: keywords", "keyword"),
    ({"category": "process_access"}, "sel: {CommandLine: x}\ncondition: sel", "not mapped"),
    ({"tags": "attack.discovery"}, "sel: {CommandLine: x}\ncondition: sel", "technique tag"),
    ({"folder": "correlation"}, "sel: {CommandLine: x}\ncondition: sel", "stageN_"),
])
def test_rules_replay_cannot_evaluate_are_refused_when_loaded(tmp_path, kwargs, detection, reason):
    with pytest.raises(UnsupportedRule, match=reason):
        load_rule(write_rule(tmp_path, detection, **kwargs))
