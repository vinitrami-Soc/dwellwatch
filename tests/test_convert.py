"""Conversion to Wazuh, Splunk and Sentinel.

The Splunk and Sentinel tests pin the shape of what pySigma's backends produce. The Wazuh rules
are generated here, so they are held to more: on planted and on real events, they must fire on
exactly the events the replay engine flags.
"""

import base64
import textwrap
from pathlib import Path

import pcre2
import pytest
import yaml
from sigma.types import SigmaString

from dwellwatch import convert as conv
from dwellwatch.convert import UnsupportedForTarget, convert, render_all
from dwellwatch.replay import load_events, load_rules, replay

import wazuh_model
from conftest import ROOT, dataset, process_event, security_event

STAGE5 = ROOT / "sigma" / "stage5_backup_destruction"
VSSADMIN = STAGE5 / "vssadmin_shadow_delete.yml"
GROUP_ADD = ROOT / "sigma" / "stage1_helpdesk" / "privileged_group_member_added.yml"


def test_vssadmin_converts_to_each_target():
    splunk = convert(VSSADMIN, "splunk")
    assert 'Image="*\\\\vssadmin.exe" OR OriginalFileName="VSSADMIN.EXE"' in splunk
    assert 'CommandLine="*delete*" CommandLine="*shadows*"' in splunk

    sentinel = convert(VSSADMIN, "sentinel")
    assert sentinel.splitlines()[2] == "imProcessCreate"
    assert 'TargetProcessName endswith "\\\\vssadmin.exe"' in sentinel
    assert 'TargetProcessFileOriginalName =~ "VSSADMIN.EXE"' in sentinel
    assert 'TargetProcessCommandLine contains "delete"' in sentinel

    wazuh = convert(VSSADMIN, "wazuh")
    assert "<if_group>sysmon_event1</if_group>" in wazuh
    assert 'name="win.eventdata.image" type="pcre2">(?s)^(?i:.*\\\\{1,2}vssadmin\\.exe$)</field>' in wazuh
    assert 'name="win.eventdata.originalFileName" type="pcre2">(?s)^(?i:VSSADMIN\\.EXE$)</field>' in wazuh
    assert 'name="win.eventdata.commandLine" type="pcre2">(?s)^(?=(?i:.*delete))(?=(?i:.*shadows))<' in wazuh
    # Security 4688 has no OriginalFileName, so only the Image branch is generated for it.
    assert '<field name="win.eventdata.newProcessName" type="pcre2">' in wazuh
    assert wazuh.count("<rule ") == 3


def test_a_security_log_rule_converts_to_each_target():
    splunk = convert(GROUP_ADD, "splunk")
    # Splunk evaluates OR before AND, so the group alternatives all sit under the EventID filter.
    assert splunk.startswith('EventID IN (4728, 4732, 4756) TargetSid IN ("*-512", ')
    assert ' OR TargetUserName IN ("Domain Admins", ' in splunk

    sentinel = convert(GROUP_ADD, "sentinel")
    assert sentinel.splitlines()[2] == "SecurityEvent"
    # The event IDs are compared as numbers: SecurityEvent's EventID is an integer column.
    assert "| where (EventID in (4728, 4732, 4756)) and (" in sentinel
    assert 'TargetSid endswith "-512"' in sentinel

    wazuh = convert(GROUP_ADD, "wazuh")
    assert wazuh.count("<if_sid>60103</if_sid>") == wazuh.count("<rule ") == 2  # one per field tested
    assert '<field name="win.system.eventID" type="pcre2">(?s)^(?:(?:4728$)|(?:4732$)|(?:4756$))</field>' in wazuh
    # Suffixes and whole SIDs are alternatives on one field, so they share a rule.
    assert "(?i:.*\\-512$)|" in wazuh and "|(?i:S\\-1\\-5\\-32\\-544$)|" in wazuh


def test_every_rule_converts_to_every_target():
    files, skipped = render_all()
    assert skipped == []
    rules = sorted((ROOT / "sigma").glob("stage*_*/*.yml"))
    assert len(files) == 3 * len(rules)


def test_committed_conversions_are_up_to_date():
    # converted/ is generated; this fails when a rule changed and `python -m dwellwatch.convert` was not run.
    assert conv.main(["--check"]) == 0


# --- what a target cannot express is refused, never emitted -----------------------------------


RULE = """\
title: Test rule
id: 11111111-2222-4333-8444-555555555555
tags: [attack.t1087]
logsource: {{category: {category}, product: windows}}
detection:
{detection}
level: medium
"""


def write_rule(tmp_path, detection, category="process_creation"):
    path = tmp_path / "stage2_remote_discovery" / "rule.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(RULE.format(category=category, detection=textwrap.indent(detection, "  ")))
    return path


def test_a_sysmon_only_log_source_is_refused_for_sentinel(tmp_path):
    # Named pipes (Sysmon 17 and 18) have no ASIM table, so there is nothing to query in Sentinel.
    rule = write_rule(tmp_path, "sel: {PipeName|contains: 'msagent_'}\ncondition: sel", category="pipe_created")
    with pytest.raises(UnsupportedForTarget, match="cannot convert to sentinel"):
        convert(rule, "sentinel")


def test_a_regex_inside_an_or_is_refused_for_splunk(tmp_path):
    rule = write_rule(tmp_path, textwrap.dedent("""\
        sel:
          - CommandLine|re|i: 'recoveryenabled\\s+no'
          - CommandLine|re|i: 'bootstatuspolicy\\s+ignoreallfailures'
        condition: sel
    """))
    with pytest.raises(UnsupportedForTarget, match="regex inside an OR"):
        convert(rule, "splunk")


@pytest.mark.parametrize("detection, reason", [
    ("sel: {CommandLine: x}\nfilter: {User: y}\ncondition: sel and not filter", "negated"),
    ("sel: {CommandLine|re: 'C:\\\\\\\\Temp'}\ncondition: sel", "literal backslash"),
])
def test_what_the_wazuh_generator_cannot_express_is_refused(tmp_path, detection, reason):
    with pytest.raises(UnsupportedForTarget, match=reason):
        convert(write_rule(tmp_path, detection), "wazuh")


def test_a_rule_without_a_wazuh_id_block_is_an_error(tmp_path):
    rule = write_rule(tmp_path, "sel: {CommandLine: x}\ncondition: sel")
    with pytest.raises(conv.ConversionError, match="wazuh-ids.yml"):
        convert(rule, "wazuh")


# --- the generated Wazuh rules --------------------------------------------------------------


def wazuh_texts():
    return [text for path, text in render_all()[0].items() if path.parts[0] == "wazuh"]


def test_wazuh_rule_ids_are_unique_and_in_the_local_range():
    ids = [rule.id for rule in wazuh_model.load_rules(wazuh_texts())]
    assert len(ids) == len(set(ids))
    assert all(100000 <= rule_id <= 119999 for rule_id in ids)
    blocks = yaml.safe_load((ROOT / "sigma" / "wazuh-ids.yml").read_text())
    assert len(set(blocks.values())) == len(blocks)
    assert all(block % 10 == 0 for block in blocks.values())


def test_wazuh_levels_outrank_wazuhs_own_rules_beside_them():
    # Wazuh tries the highest level first and stops at the first match. Its own rules under 60103
    # (successful Security events) go up to level 9 (60115, account locked out); its Sysmon event 1
    # rules that match these commands go up to 12 (92057, encoded PowerShell).
    for rule in wazuh_model.load_rules(wazuh_texts()):
        assert rule.level > (12 if rule.if_group == "sysmon_event1" else 9), rule.id


WAZUH_RULES = wazuh_model.load_rules(wazuh_texts())
SIGMA_ID_BY_BLOCK = {block: str(sigma_id) for sigma_id, block
                     in yaml.safe_load((ROOT / "sigma" / "wazuh-ids.yml").read_text()).items()}
RULES = load_rules()


def assert_wazuh_agrees_with_replay(events):
    """Per event, the Sigma rules Wazuh would fire on are the ones replay fires on."""
    fired = 0
    for event in events:
        expected = {signal.rule_id for signal in replay([event], RULES)}
        fields = wazuh_model.wazuh_event(event)
        fired_rules = [rule for rule in WAZUH_RULES if wazuh_model.fires(rule, fields)]
        actual = {SIGMA_ID_BY_BLOCK[rule.id - rule.id % 10] for rule in fired_rules}
        assert actual == expected, (event.get("CommandLine"), event.get("Image"))
        fired += bool(expected)
    return fired


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def encoded(script):
    return "powershell.exe -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()


PLANTED = [
    process_event("vssadmin delete shadows /all /quiet", "C:\\Windows\\System32\\vssadmin.exe"),
    process_event("svc.exe delete shadows /all", "C:\\Users\\Public\\svc.exe", original_file_name="VSSADMIN.EXE"),
    process_event("vssadmin list shadows", "C:\\Windows\\System32\\vssadmin.exe"),
    process_event('bcdedit /set {default} recoveryenabled "No"', "C:\\Windows\\System32\\bcdedit.exe"),
    process_event("bcdedit /set {default} recoveryenabled yes", "C:\\Windows\\System32\\bcdedit.exe"),
    process_event("wmic path win32_shadowcopy delete", "C:\\Windows\\System32\\wbem\\WMIC.exe"),
    process_event("wmic shadowcopy call create Volume=C:\\", "C:\\Windows\\System32\\wbem\\WMIC.exe"),
    process_event('pwsh -c "gwmi win32_shadowcopy | rwmi"', "C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
    process_event(encoded("Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}"), PS),
    process_event(encoded("Get-CimInstance Win32_ShadowCopy | Select-Object ID"), PS),
    process_event('cmd.exe /c "vssadmin.exe delete shadows /all /quiet"', "C:\\Windows\\System32\\cmd.exe"),
    security_event(4688, NewProcessName="C:\\Windows\\System32\\wbadmin.exe", CommandLine="wbadmin delete catalog",
                   SubjectUserName="helpdesk1", SubjectDomainName="LAB"),
    security_event(4724, TargetUserName="jdoe", TargetDomainName="LAB", SubjectUserName="helpdesk1"),
    security_event(4723, TargetUserName="jdoe", TargetDomainName="LAB", SubjectUserName="jdoe"),
    security_event(4728, TargetUserName="Domain Admins", TargetSid="S-1-5-21-1-2-3-512"),
    security_event(4732, TargetUserName="DnsAdmins", TargetSid="S-1-5-21-1-2-3-1101"),
    security_event(4732, TargetUserName="Administrators", TargetSid="BUILTIN\\Administrators"),
    security_event(4732, TargetUserName="Users", TargetSid="BUILTIN\\Users"),
    security_event(4729, TargetUserName="Domain Admins", TargetSid="S-1-5-21-1-2-3-512"),
]


def test_wazuh_agrees_with_replay_on_planted_events():
    assert assert_wazuh_agrees_with_replay(PLANTED) == 11


@pytest.mark.parametrize("relative, alerts", [
    ("T1490/atomic_red_team/windows-sysmon.log", 6),
    ("T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log", 2),
    ("T1003.003/atomic_red_team/windows-sysmon.log", 0),
    ("T1098/windows_multiple_passwords_changed/windows_multiple_passwords_changed.log", 40),
    ("T1098/account_manipulation/xml-windows-security.log", 24),
    ("T1098/dnsadmins_member_added/windows-security.log", 1),
    ("T1136.001/atomic_red_team/xml-windows-security.log", 1),
])
def test_wazuh_agrees_with_replay_on_real_events(relative, alerts):
    assert assert_wazuh_agrees_with_replay(load_events(dataset(relative))) == alerts


@pytest.mark.parametrize("value", [
    "C:\\Users\\Public\\x.exe",  # as Windows records it
    "C:\\\\Users\\\\Public\\\\x.exe",  # as Wazuh stores it
])
def test_wazuh_patterns_match_a_path_whether_or_not_its_backslashes_arrive_doubled(value):
    # The stage 5 rules only have a backslash at the start of a value, where one backslash always
    # matches; a backslash mid-path is what needs "one or two".
    contains = SigmaString("*\\Users\\Public\\\\*")  # Sigma for: contains \Users\Public\
    pattern = pcre2.compile("(?s)^" + conv._wazuh_value(contains, VSSADMIN))
    assert pattern.search(value)
    assert not pattern.search(value.replace("Public", "Private"))


def test_every_generated_file_names_its_source():
    sources = {path.stem: path.relative_to(ROOT).as_posix() for path in (ROOT / "sigma").glob("stage*_*/*.yml")}
    for path, text in render_all()[0].items():
        if path.parts[0] != "splunk":  # SPL has no comment syntax every Splunk version accepts
            assert sources[Path(path).stem] in text
