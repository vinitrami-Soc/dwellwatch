"""Stage 4 (lateral movement): PsExec and Impacket-style remote execution, WMI process creation
on another host, RDP logons and pass-the-hash logons.

The planted events pin down each rule's edges: local PsExec, local WMI, and WMI calls that are
not process creation must stay quiet. The attack_data tests replay real PsExec, WMI and RDP runs.
"""

from collections import Counter

import pytest

from dwellwatch.models import Severity, Stage
from dwellwatch.replay import load_events, load_rule, load_rules, replay

from conftest import ROOT, dataset, process_event, security_event

STAGE4 = ROOT / "sigma" / "stage4_lateral_movement"
REMOTE_EXEC = load_rule(STAGE4 / "remote_exec_psexec_impacket.yml")
WMI = load_rule(STAGE4 / "wmi_remote_process.yml")
RDP = load_rule(STAGE4 / "rdp_logon.yml")
PTH = load_rule(STAGE4 / "pass_the_hash_logon.yml")

SYS32 = "C:\\Windows\\System32\\"
PSEXEC = "C:\\Tools\\PsExec.exe"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"


def fires(rule, event):
    return len(replay([event], [rule])) == 1


def logon(logon_type, process="User32", user="jdoe", ip="10.0.0.5"):
    return security_event(4624, LogonType=str(logon_type), LogonProcessName=process, TargetUserName=user,
                          TargetDomainName="LAB", IpAddress=ip)


@pytest.mark.parametrize("rule, event", [
    (REMOTE_EXEC, process_event("PsExec.exe \\\\fs01 -accepteula cmd.exe", PSEXEC)),
    (REMOTE_EXEC, process_event("s.exe \\\\10.0.0.9 cmd.exe", "C:\\Temp\\s.exe", original_file_name="psexec.c")),
    (REMOTE_EXEC, process_event("C:\\Windows\\PSEXESVC.exe", "C:\\Windows\\PSEXESVC.exe")),
    (REMOTE_EXEC, process_event("cmd.exe /Q /c whoami /all 1> \\\\127.0.0.1\\ADMIN$\\__1556656369.7 2>&1",
                                SYS32 + "cmd.exe")),  # Impacket wmiexec
    (REMOTE_EXEC, process_event("cmd.exe /Q /c echo whoami ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > "
                                "%TEMP%\\execute.bat", SYS32 + "cmd.exe")),  # Impacket smbexec
    (WMI, process_event('wmic /node:fs01 process call create "cmd.exe /c whoami"', SYS32 + "wbem\\WMIC.exe")),
    (WMI, process_event("powershell Invoke-WmiMethod -ComputerName fs01 -Class Win32_Process -Name Create "
                        "-ArgumentList calc.exe", PS)),
    (WMI, process_event("pwsh -c Invoke-CimMethod -ComputerName fs01 -ClassName Win32_Process -MethodName Create",
                        "C:\\Program Files\\PowerShell\\7\\pwsh.exe")),
    (RDP, logon(10)),
    (RDP, logon(10, ip="127.0.0.1")),  # an RDP session tunnelled back to the machine itself
    (PTH, logon(9, process="seclogo")),
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_fires_on_planted_lateral_movement(rule, event):
    assert fires(rule, event)


@pytest.mark.parametrize("rule, event", [
    (REMOTE_EXEC, process_event("PsExec.exe -accepteula -s cmd.exe", PSEXEC)),  # local: SYSTEM, not another host
    (REMOTE_EXEC, process_event("PsExec.exe -s reg save HKLM\\security\\policy\\secrets C:\\t\\s", PSEXEC)),
    (REMOTE_EXEC, process_event("cmd.exe /c dir > C:\\Temp\\out.txt", SYS32 + "cmd.exe")),
    (REMOTE_EXEC, process_event("net use \\\\fs01\\C$ /user:LAB\\jdoe", SYS32 + "net.exe")),
    (WMI, process_event("wmic /node:fs01 shadowcopy call create Volume=C:\\", SYS32 + "wbem\\WMIC.exe")),
    (WMI, process_event("wmic process call create notepad.exe", SYS32 + "wbem\\WMIC.exe")),  # local
    (WMI, process_event("wmic /node:fs01 os get caption", SYS32 + "wbem\\WMIC.exe")),
    (WMI, process_event("powershell Get-WmiObject Win32_Process -ComputerName fs01", PS)),  # a query
    (RDP, logon(3, process="NtLmSsp")),
    (RDP, logon(2)),
    (RDP, security_event(4625, LogonType="10", TargetUserName="jdoe")),  # a failed RDP logon
    (PTH, logon(9, process="Advapi")),
    (PTH, logon(2, process="seclogo")),
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_stays_quiet_on_local_admin_work(rule, event):
    assert not fires(rule, event)


@pytest.mark.parametrize("rule, technique, severity", [
    (REMOTE_EXEC, "T1021.002", Severity.HIGH),
    (WMI, "T1047", Severity.MEDIUM),
    (RDP, "T1021.001", Severity.LOW),
    (PTH, "T1550.002", Severity.MEDIUM),
])
def test_each_rule_reports_its_stage_technique_and_severity(rule, technique, severity):
    assert (rule.stage, rule.attack_technique, rule.severity) == (Stage.LATERAL_MOVEMENT, technique, severity)


def test_logon_signals_name_the_account_that_logged_on():
    assert [s.user for s in replay([logon(10, user="jdoe")], [RDP])] == ["LAB\\jdoe"]


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------


def fired_on(relative):
    events, rules = list(load_events(dataset(relative))), load_rules()
    return events, [(event, signal) for event in events for signal in replay([event], rules)]


def test_psexec_to_a_host_fires_and_local_psexec_does_not():
    events, fired = fired_on("T1021.002/atomic_red_team/windows-sysmon.log")
    assert [(s.rule_id, e["CommandLine"].strip()) for e, s in fired] == [
        (REMOTE_EXEC.id, "C:\\PSTools\\PsExec.exe  \\\\localhost -accepteula -c C:\\Windows\\System32\\cmd.exe")]
    # The same run's local `PsExec -s reg save ...` takes SYSTEM on the same machine: quiet.
    assert any("-s reg save" in e.get("CommandLine", "") and "PsExec.exe" in e.get("Image", "") for e in events)


def test_wmi_process_creation_on_a_node_fires_and_local_wmi_does_not():
    events, fired = fired_on("T1047/atomic_red_team/windows-sysmon.log")
    assert len(events) == 6571
    assert [(s.rule_id, e["Image"].rsplit("\\", 1)[-1]) for e, s in fired] == [(WMI.id, "WMIC.exe")]
    assert "/node:" in fired[0][0]["CommandLine"] and "process call create" in fired[0][0]["CommandLine"]


def test_every_rdp_logon_fires_and_names_its_account():
    events, fired = fired_on("T1021.001/rdp_session_established/4624_10_logon.log")
    assert len(events) == len(fired) == 16
    assert {s.rule_id for _, s in fired} == {RDP.id}
    assert Counter(s.user for _, s in fired) == {"ATTACKRANGE\\Administrator": 9, "AR-WIN-DC-2\\Administrator": 7}
