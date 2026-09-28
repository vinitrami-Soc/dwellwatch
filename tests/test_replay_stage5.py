"""Stage 5 (backup destruction): each rule must fire on the attack and stay quiet on the admin.

The planted events pin down each rule's edges. The attack_data tests then replay real
Atomic Red Team telemetry: the T1490 run must produce exactly the expected signals, and
a T1003.003 run, which uses the same binaries to create shadow copies rather than delete
them, must produce none.
"""

import pytest

from dwellwatch.models import Severity, Stage
from dwellwatch.replay import load_events, load_rule, load_rules, replay

from conftest import ROOT, dataset, process_event

STAGE5 = ROOT / "sigma" / "stage5_backup_destruction"
VSSADMIN = load_rule(STAGE5 / "vssadmin_shadow_delete.yml")
WBADMIN = load_rule(STAGE5 / "wbadmin_delete_catalog.yml")
BCDEDIT = load_rule(STAGE5 / "bcdedit_recovery_disabled.yml")

SYS32 = "C:\\Windows\\System32\\"


def fires(rule, event):
    return len(replay([event], [rule])) == 1


@pytest.mark.parametrize("rule, command_line, image", [
    (VSSADMIN, "vssadmin.exe delete shadows /all /quiet", "vssadmin.exe"),
    (VSSADMIN, "VSSADMIN DELETE SHADOWS /For=C: /Oldest", "VSSADMIN.EXE"),
    (WBADMIN, "wbadmin delete catalog -quiet", "wbadmin.exe"),
    (BCDEDIT, "bcdedit.exe /set {default} recoveryenabled no", "bcdedit.exe"),
    (BCDEDIT, "bcdedit /set {default} RecoveryEnabled Off", "bcdedit.exe"),
    (BCDEDIT, "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures", "bcdedit.exe"),
])
def test_fires_on_planted_attack(rule, command_line, image):
    assert fires(rule, process_event(command_line, SYS32 + image))


@pytest.mark.parametrize("rule, command_line, image", [
    # The routine backup work that shares each binary with the attack.
    (VSSADMIN, "vssadmin list shadows", "vssadmin.exe"),
    (VSSADMIN, "vssadmin create shadow /for=C:", "vssadmin.exe"),
    (VSSADMIN, "vssadmin list shadowstorage", "vssadmin.exe"),
    (WBADMIN, "wbadmin start backup -backupTarget:E: -include:C: -quiet", "wbadmin.exe"),
    (WBADMIN, "wbadmin get versions", "wbadmin.exe"),
    (WBADMIN, "wbadmin delete systemstatebackup -keepVersions:3", "wbadmin.exe"),
    (BCDEDIT, "bcdedit /enum", "bcdedit.exe"),
    (BCDEDIT, "bcdedit /set {default} recoveryenabled yes", "bcdedit.exe"),
    (BCDEDIT, "bcdedit /set {default} bootstatuspolicy displayallfailures", "bcdedit.exe"),
])
def test_stays_quiet_on_benign_backup_admin(rule, command_line, image):
    assert not fires(rule, process_event(command_line, SYS32 + image))


def test_the_launching_shell_is_not_a_second_alert():
    # cmd.exe /c "vssadmin delete shadows" carries the same words; only vssadmin itself should fire.
    shell = process_event('cmd.exe /c "vssadmin.exe delete shadows /all /quiet"', SYS32 + "cmd.exe")
    assert replay([shell], load_rules()) == []


def test_a_renamed_binary_is_still_caught_by_its_original_file_name():
    renamed = process_event("svc.exe delete shadows /all /quiet", "C:\\Users\\Public\\svc.exe",
                            original_file_name="VSSADMIN.EXE")
    assert fires(VSSADMIN, renamed)


def test_signal_carries_the_rule_and_the_event():
    [signal] = replay([process_event("vssadmin delete shadows /all", SYS32 + "vssadmin.exe")], [VSSADMIN])
    assert signal.stage is Stage.BACKUP_DESTRUCTION
    assert signal.attack_technique == "T1490"
    assert signal.severity is Severity.HIGH
    assert signal.rule_id == VSSADMIN.id
    assert (signal.host, signal.user) == ("WS01.lab.local", "LAB\\jdoe")


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------


def titles(signals):
    by_id = {rule.id: rule.title for rule in load_rules()}
    return sorted(by_id[s.rule_id] for s in signals)


def test_t1490_sysmon_run_fires_each_rule_and_nothing_else():
    events = list(load_events(dataset("T1490/atomic_red_team/windows-sysmon.log")))
    signals = replay(events, load_rules())
    assert len(events) == 285
    # One vssadmin, one wbadmin and two bcdedit commands; their cmd.exe parents stay quiet.
    # wmic and PowerShell shadow-copy deletion are in this run too, but no rule covers them yet.
    assert titles(signals) == sorted([VSSADMIN.title, WBADMIN.title, BCDEDIT.title, BCDEDIT.title])
    assert all(s.stage is Stage.BACKUP_DESTRUCTION and s.attack_technique == "T1490" for s in signals)
    assert {s.host for s in signals} == {"win-dc-770.attackrange.local"}
    assert {s.user for s in signals} == {"ATTACKRANGE\\Administrator"}
    assert signals == sorted(signals, key=lambda s: s.timestamp)


def test_t1490_security_4688_run_fires_on_vssadmin_only():
    events = list(load_events(dataset("T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log")))
    signals = replay(events, load_rules())
    assert len(events) == 4
    assert titles(signals) == [VSSADMIN.title]
    assert signals[0].user == "ATTACKRANGE\\Administrator"  # the creator: 4688 has no target account


def test_shadow_copy_creation_for_ntds_theft_is_not_backup_destruction():
    events = list(load_events(dataset("T1003.003/atomic_red_team/windows-sysmon.log")))
    command_lines = [e.get("CommandLine", "") for e in events]
    # Guard against a vacuous pass: the near misses really are in this control.
    assert any("vssadmin.exe  create shadow" in c for c in command_lines)
    assert any("wmic  shadowcopy call create" in c for c in command_lines)
    assert len(events) == 7010
    assert replay(events, load_rules()) == []
