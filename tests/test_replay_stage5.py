"""Stage 5 (backup destruction): each rule must fire on the attack and stay quiet on the admin.

The planted events pin down each rule's edges. The attack_data tests then replay real
Atomic Red Team telemetry: the T1490 run must produce exactly the expected signals, and
a T1003.003 run, which uses the same binaries to create shadow copies rather than delete
them, must produce no stage 5 signal.
"""

import base64

import pytest

from dwellwatch.models import Severity, Stage
from dwellwatch.replay import load_events, load_rule, load_rules, replay

from conftest import ROOT, dataset, process_event

STAGE5 = ROOT / "sigma" / "stage5_backup_destruction"
VSSADMIN = load_rule(STAGE5 / "vssadmin_shadow_delete.yml")
WBADMIN = load_rule(STAGE5 / "wbadmin_delete_catalog.yml")
BCDEDIT = load_rule(STAGE5 / "bcdedit_recovery_disabled.yml")
WMIC = load_rule(STAGE5 / "wmic_shadowcopy_delete.yml")
POWERSHELL = load_rule(STAGE5 / "powershell_shadowcopy_delete.yml")
POWERSHELL_ENCODED = load_rule(STAGE5 / "powershell_encoded_shadowcopy_delete.yml")

SYS32 = "C:\\Windows\\System32\\"
PS = "WindowsPowerShell\\v1.0\\powershell.exe"
REVIL = "Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}"  # as decoded from REvil's runs


def encoded(script):
    """A PowerShell command line hiding `script` the way -EncodedCommand does: base64 of UTF-16LE."""
    return "powershell.exe -NoProfile -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()


def fires(rule, event):
    return len(replay([event], [rule])) == 1


@pytest.mark.parametrize("rule, command_line, image", [
    (VSSADMIN, "vssadmin.exe delete shadows /all /quiet", "vssadmin.exe"),
    (VSSADMIN, "VSSADMIN DELETE SHADOWS /For=C: /Oldest", "VSSADMIN.EXE"),
    (WBADMIN, "wbadmin delete catalog -quiet", "wbadmin.exe"),
    (BCDEDIT, "bcdedit.exe /set {default} recoveryenabled no", "bcdedit.exe"),
    (BCDEDIT, "bcdedit /set {default} RecoveryEnabled Off", "bcdedit.exe"),
    (BCDEDIT, "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures", "bcdedit.exe"),
    (WMIC, "wmic shadowcopy delete", "wbem\\WMIC.exe"),
    (WMIC, "wmic.exe /node:localhost shadowcopy where \"ID='{5B1E}'\" delete /nointeractive", "wbem\\WMIC.exe"),
    (WMIC, "wmic path win32_shadowcopy delete", "wbem\\WMIC.exe"),
    (POWERSHELL, f"powershell.exe & {{{REVIL}}}", PS),
    (POWERSHELL, "powershell.exe Get-CimInstance Win32_ShadowCopy | Remove-CimInstance", PS),
    (POWERSHELL, "powershell -c \"Get-WmiObject Win32_ShadowCopy | Remove-WmiObject\"", PS),
    (POWERSHELL, "pwsh -c \"gwmi win32_shadowcopy | rwmi\"", "PowerShell\\7\\pwsh.exe"),
    (POWERSHELL_ENCODED, encoded(REVIL), PS),
    (POWERSHELL_ENCODED, encoded("Get-CimInstance Win32_ShadowCopy | Remove-CimInstance"), PS),
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
    (WMIC, "wmic shadowcopy list brief", "wbem\\WMIC.exe"),
    (WMIC, "wmic shadowcopy call create Volume=C:\\", "wbem\\WMIC.exe"),
    (WMIC, "wmic process where name='notepad.exe' delete", "wbem\\WMIC.exe"),
    (POWERSHELL, "powershell.exe & {(gwmi -list win32_shadowcopy).Create('C:\\','ClientAccessible')}", PS),
    (POWERSHELL, "powershell -c \"Get-CimInstance Win32_ShadowCopy | Select-Object ID, InstallDate\"", PS),
    (POWERSHELL, "powershell -c \"Get-ChildItem C:\\Temp\\old | Remove-Item\"", PS),
    (POWERSHELL_ENCODED, encoded("(gwmi -list win32_shadowcopy).Create('C:\\','ClientAccessible')"), PS),
    (POWERSHELL_ENCODED, encoded("Get-CimInstance Win32_ShadowCopy | Select-Object ID"), PS),
    (POWERSHELL_ENCODED, encoded("& chcp.com 65001 > $null"), PS),  # what Atomic Red Team's runner encodes
])
def test_stays_quiet_on_benign_backup_admin(rule, command_line, image):
    assert not fires(rule, process_event(command_line, SYS32 + image))


@pytest.mark.parametrize("command_line, title", [
    (f"powershell.exe & {{{REVIL}}}", POWERSHELL.title),
    (encoded(REVIL), POWERSHELL_ENCODED.title),
])
def test_plain_and_encoded_powershell_each_raise_one_alert(command_line, title):
    assert titles(replay([process_event(command_line, SYS32 + PS)], load_rules())) == [title]


@pytest.mark.parametrize("command_line", [
    'cmd.exe /c "vssadmin.exe delete shadows /all /quiet"',
    'cmd.exe /c "wmic.exe shadowcopy delete"',
    f'cmd.exe /c "powershell.exe & {{{REVIL}}}"',
])
def test_the_launching_shell_is_not_a_second_alert(command_line):
    # The shell carries the same words; only the process that does the deleting should fire.
    assert replay([process_event(command_line, SYS32 + "cmd.exe")], load_rules()) == []


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


def test_every_stage5_rule_reports_t1490_first():
    # Rules may carry extra technique tags (T1059.001, T1027.010); the signal names the stage's own.
    assert {rule.attack_technique for rule in load_rules() if rule.stage is Stage.BACKUP_DESTRUCTION} == {"T1490"}


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------


def titles(signals):
    by_id = {rule.id: rule.title for rule in load_rules()}
    return sorted(by_id[s.rule_id] for s in signals)


def test_t1490_sysmon_run_fires_each_rule_and_nothing_else():
    events = list(load_events(dataset("T1490/atomic_red_team/windows-sysmon.log")))
    signals = replay(events, load_rules())
    assert len(events) == 285
    # One each of vssadmin, wbadmin, wmic and PowerShell, and two bcdedit commands; the cmd.exe
    # processes that launched them stay quiet. `wbadmin delete systemstatebackup` is in this run
    # too, and no rule covers it yet.
    assert titles(signals) == sorted([VSSADMIN.title, WBADMIN.title, BCDEDIT.title, BCDEDIT.title,
                                      WMIC.title, POWERSHELL.title])
    assert all(s.stage is Stage.BACKUP_DESTRUCTION and s.attack_technique == "T1490" for s in signals)
    assert {s.host for s in signals} == {"win-dc-770.attackrange.local"}
    assert {s.user for s in signals} == {"ATTACKRANGE\\Administrator"}
    assert signals == sorted(signals, key=lambda s: s.timestamp)


def test_t1490_security_4688_run_fires_on_vssadmin_and_wmic():
    events = list(load_events(dataset("T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log")))
    signals = replay(events, load_rules())
    assert len(events) == 4
    assert titles(signals) == sorted([VSSADMIN.title, WMIC.title])
    assert {s.user for s in signals} == {"ATTACKRANGE\\Administrator"}  # the creator: no target account


def test_shadow_copy_creation_for_ntds_theft_is_not_backup_destruction():
    events = list(load_events(dataset("T1003.003/atomic_red_team/windows-sysmon.log")))
    command_lines = [e.get("CommandLine", "") for e in events]
    # Guard against a vacuous pass: the near misses really are in this control.
    assert any("vssadmin.exe  create shadow" in c for c in command_lines)
    assert any("wmic  shadowcopy call create" in c for c in command_lines)
    assert any("win32_shadowcopy).Create" in c for c in command_lines)
    assert any("-EncodedCommand" in c for c in command_lines)
    assert len(events) == 7010
    signals = replay(events, load_rules())
    assert [s for s in signals if s.stage is Stage.BACKUP_DESTRUCTION] == []
    # The same run steals the AD database, which stage 3 catches (see test_replay_stage3.py).
    assert {s.stage for s in signals} == {Stage.CREDENTIAL_THEFT}
