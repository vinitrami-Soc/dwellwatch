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


def test_every_rule_converts_to_every_target_except_sysmon_10_for_sentinel():
    files, skipped = render_all()
    # Sentinel has no table for Sysmon's process-access events: ASIM defines none, and pySigma's
    # Azure Monitor pipeline maps only SecurityEvent. Everything else converts everywhere.
    assert [(skip.path.name, skip.target) for skip in skipped] == [("lsass_memory_access.yml", "sentinel")]
    assert "Unable to determine table name" in skipped[0].reason
    rules = sorted((ROOT / "sigma").glob("stage*_*/*.yml"))
    assert len(files) == 3 * len(rules) - 1


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
    ("keywords: [mimikatz]\ncondition: keywords", "keyword"),
    ("sel: {CommandLine|re: 'C:\\\\\\\\Temp'}\ncondition: sel", "literal backslash"),
])
def test_what_the_wazuh_generator_cannot_express_is_refused(tmp_path, detection, reason):
    with pytest.raises(UnsupportedForTarget, match=reason):
        convert(write_rule(tmp_path, detection), "wazuh")


def test_a_negated_condition_becomes_a_negative_lookahead():
    wazuh = convert(ROOT / "sigma" / "stage3_credential_theft" / "dcsync_by_non_dc_account.yml", "wazuh")
    field = '<field name="win.eventdata.subjectUserName" type="pcre2">(?s)^(?!(?i:.*\\$$))</field>'
    assert field in wazuh
    pattern = pcre2.compile("(?s)^(?!(?i:.*\\$$))")
    assert pattern.search("Administrator") and not pattern.search("AR-WIN-DC$")


def test_a_negated_field_the_source_never_has_is_dropped_as_always_true(tmp_path, monkeypatch):
    # Security 4688 has no OriginalFileName, so "not OriginalFileName x" holds for every 4688 event.
    monkeypatch.setattr(conv, "_wazuh_ids", lambda: {"11111111-2222-4333-8444-555555555555": 119990})
    rule = write_rule(tmp_path, "sel: {CommandLine|contains: secret}\nfilter: {OriginalFileName: x.exe}\n"
                                "condition: sel and not filter")
    wazuh = convert(rule, "wazuh")
    sysmon, security = wazuh.split("<!-- Security event 4688 -->")
    assert "win.eventdata.originalFileName" in sysmon and "(?!" in sysmon
    assert "originalFileName" not in security and "win.eventdata.commandLine" in security


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


WAZUH_RULES = wazuh_model.load_rules(wazuh_texts())
SIGMA_ID_BY_BLOCK = {block: str(sigma_id) for sigma_id, block
                     in yaml.safe_load((ROOT / "sigma" / "wazuh-ids.yml").read_text()).items()}
RULES = load_rules()


def assert_wazuh_agrees_with_replay(events):
    """Per event, the Sigma rules Wazuh would fire on are the ones replay fires on, and no built-in
    Wazuh rule that is tried first could take the event."""
    fired = 0
    for event in events:
        expected = {signal.rule_id for signal in replay([event], RULES)}
        fields = wazuh_model.wazuh_event(event)
        fired_rules = [rule for rule in WAZUH_RULES if wazuh_model.fires(rule, fields)]
        actual = {SIGMA_ID_BY_BLOCK[rule.id - rule.id % 10] for rule in fired_rules}
        assert actual == expected, (event.get("CommandLine"), event.get("Image"))
        for rule in fired_rules:
            assert not wazuh_model.rivals(rule, event), (rule.id, event.get("CommandLine"))
        fired += bool(expected)
    return fired


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
LSASS = "C:\\Windows\\system32\\lsass.exe"
REPLICATE = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"  # DS-Replication-Get-Changes-All


def sysmon_event(event_id, **fields):
    return {"EventID": str(event_id), "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "dc01",
            "TimeCreated": "2025-04-24T09:00:00Z", **fields}


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
    process_event("AnyDesk.exe --local-service", "C:\\Users\\jdoe\\Downloads\\AnyDesk.exe"),
    process_event("nltest /domain_trusts /all_trusts", "C:\\Windows\\System32\\nltest.exe"),
    process_event("nltest /dsgetdc:lab.local", "C:\\Windows\\System32\\nltest.exe"),
    process_event('net1 group "Domain Admins" /domain', "C:\\Windows\\System32\\net1.exe"),
    process_event("net view /domain", "C:\\Windows\\System32\\net.exe"),
    process_event("net user /domain", "C:\\Windows\\System32\\net.exe"),
    process_event("adf.exe -f (objectcategory=person)", "C:\\Temp\\adf.exe", original_file_name="AdFind.exe"),
    sysmon_event(10, SourceImage="C:\\Tools\\m.exe", TargetImage=LSASS, GrantedAccess="0x1010", CallTrace="x"),
    sysmon_event(10, SourceImage="C:\\Windows\\System32\\csrss.exe", TargetImage=LSASS, GrantedAccess="0x1fffff",
                 CallTrace="x"),  # a negated condition that holds
    sysmon_event(11, Image="C:\\Tools\\p.exe", TargetFilename="C:\\Windows\\Temp\\lsass.dmp"),
    sysmon_event(11, Image="C:\\Windows\\System32\\lsass.exe", TargetFilename="C:\\Windows\\NTDS\\ntds.dit"),
    security_event(4662, SubjectUserName="jdoe", AccessMask="0x100", Properties=REPLICATE),
    security_event(4662, SubjectUserName="DC02$", AccessMask="0x100", Properties=REPLICATE),
    process_event("PsExec.exe \\\\fs01 -accepteula cmd.exe", "C:\\Tools\\PsExec.exe"),
    process_event("PsExec.exe -accepteula -s C:\\Windows\\System32\\cmd.exe", "C:\\Tools\\PsExec.exe"),  # local
    security_event(4624, LogonType="10", TargetUserName="jdoe", TargetDomainName="LAB"),
    security_event(4624, LogonType="3", TargetUserName="jdoe", TargetDomainName="LAB"),
    security_event(4624, LogonType="9", LogonProcessName="seclogo", TargetUserName="jdoe", TargetDomainName="LAB"),
    sysmon_event(11, Image="C:\\Tools\\x.exe", TargetFilename="C:\\Shares\\HOW_TO_DECRYPT.txt"),
    sysmon_event(11, Image="C:\\Tools\\x.exe", TargetFilename="C:\\Shares\\dwellwatch-canary-a.xlsx.enc"),
    process_event("manage-bde -protectors -delete C:", "C:\\Windows\\System32\\manage-bde.exe"),
    process_event("manage-bde -status", "C:\\Windows\\System32\\manage-bde.exe"),
]


def test_wazuh_agrees_with_replay_on_planted_events():
    assert assert_wazuh_agrees_with_replay(PLANTED) == 25


@pytest.mark.parametrize("relative, alerts", [
    ("T1490/atomic_red_team/windows-sysmon.log", 6),
    ("T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log", 2),
    ("T1003.003/atomic_red_team/windows-sysmon.log", 3),
    ("T1098/windows_multiple_passwords_changed/windows_multiple_passwords_changed.log", 40),
    ("T1098/account_manipulation/xml-windows-security.log", 24),
    ("T1098/dnsadmins_member_added/windows-security.log", 1),
    ("T1136.001/atomic_red_team/xml-windows-security.log", 1),
    ("T1219/atomic_red_team/windows-sysmon.log", 15),
    ("T1219/screenconnect/screenconnect_sysmon.log", 5),
    ("T1482/atomic_red_team/windows-sysmon.log", 7),
    ("T1087.002/AD_discovery/windows-sysmon.log", 10),
    ("T1003.001/atomic_red_team/windows-sysmon.log", 66),
    ("T1003.006/mimikatz/xml-windows-security.log", 4),
    ("T1003.006/impacket/windows-security-xml.log", 0),
    ("T1021.002/atomic_red_team/windows-sysmon.log", 1),
    ("T1047/atomic_red_team/windows-sysmon.log", 1),
    ("T1021.001/rdp_session_established/4624_10_logon.log", 16),
    ("T1486/dcrypt/windows-sysmon.log", 3),
    ("T1486/bitlocker_sus_commands/bitlocker_sus_commands.log", 1),
    ("T1486/sam_sam_note/windows-sysmon.log", 0),
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


@pytest.mark.parametrize("raw, matches", [
    ("PsExec.exe \\\\fs01 cmd.exe", True),  # a \\host argument
    ("PsExec.exe -s C:\\Windows\\System32\\cmd.exe", False),  # single backslashes only
])
def test_a_run_of_backslashes_is_told_apart_from_a_single_escaped_one(raw, matches):
    # Wazuh stores a single backslash as two characters, so "one or two per backslash" would make
    # a pattern for \\ match every path. A run is matched in the escaped form only.
    contains = SigmaString("*\\\\\\\\*")  # Sigma for: contains \\
    pattern = pcre2.compile("(?s)^" + conv._wazuh_value(contains, VSSADMIN))
    assert bool(pattern.search(raw.replace("\\", "\\\\"))) is matches


def test_every_generated_file_names_its_source():
    sources = {path.stem: path.relative_to(ROOT).as_posix() for path in (ROOT / "sigma").glob("stage*_*/*.yml")}
    for path, text in render_all()[0].items():
        if path.parts[0] != "splunk":  # SPL has no comment syntax every Splunk version accepts
            assert sources[Path(path).stem] in text
