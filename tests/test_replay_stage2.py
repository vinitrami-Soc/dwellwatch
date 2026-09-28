"""Stage 2 (remote tooling and discovery): remote-access tools starting, and the directory being
mapped with nltest, dsquery, net, AdFind, SharpHound, AD Explorer or PowerView.

The planted events pin down each rule's edges. The attack_data tests replay real Atomic Red Team
and ScreenConnect telemetry: every tool and query in them must fire once, and the shells and
downloads around them must not.
"""

from collections import Counter

import pytest

from dwellwatch.models import Severity, Stage
from dwellwatch.replay import load_events, load_rule, load_rules, replay

from conftest import ROOT, dataset, process_event

STAGE2 = ROOT / "sigma" / "stage2_remote_discovery"
REMOTE_TOOL = load_rule(STAGE2 / "remote_access_tool_started.yml")
TRUSTS = load_rule(STAGE2 / "domain_trust_discovery.yml")
RECON = load_rule(STAGE2 / "ad_recon_tool.yml")
NET = load_rule(STAGE2 / "net_domain_query.yml")

SYS32 = "C:\\Windows\\System32\\"
DOWNLOADS = "C:\\Users\\jdoe\\Downloads\\"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
PWSH = "C:\\Program Files\\PowerShell\\7\\pwsh.exe"


def fires(rule, event):
    return len(replay([event], [rule])) == 1


def product_event(command_line, image, product):
    return process_event(command_line, image) | {"Product": product}


@pytest.mark.parametrize("rule, event", [
    (REMOTE_TOOL, process_event(f'"{DOWNLOADS}AnyDesk.exe" --local-service', DOWNLOADS + "AnyDesk.exe")),
    (REMOTE_TOOL, product_event("svchostx.exe --silent", "C:\\ProgramData\\svchostx.exe", "AnyDesk")),  # renamed
    (REMOTE_TOOL, process_event("TeamViewer.exe", "C:\\Program Files\\TeamViewer\\TeamViewer.exe")),
    (REMOTE_TOOL, process_event("ScreenConnect.ClientService.exe", "D:\\ScreenConnect.ClientService.exe")),
    (REMOTE_TOOL, process_event("go.exe /S", DOWNLOADS + "go.exe", original_file_name="GoToOpener.exe")),
    (REMOTE_TOOL, process_event("rustdesk.exe --service", "C:\\Program Files\\RustDesk\\rustdesk.exe")),
    (REMOTE_TOOL, process_event("ngrok.exe tcp 3389", "C:\\Users\\Public\\ngrok.exe")),
    (REMOTE_TOOL, process_event("tailscaled.exe", "C:\\Program Files\\Tailscale\\tailscaled.exe")),
    (REMOTE_TOOL, process_event("AteraAgent.exe", "C:\\Program Files\\ATERA Networks\\AteraAgent.exe")),
    (TRUSTS, process_event("nltest /domain_trusts /all_trusts", SYS32 + "nltest.exe")),
    (TRUSTS, process_event("nltest  / DOMAIN_TRUSTS", SYS32 + "nltest.exe")),  # as typed in a Conti intrusion
    (TRUSTS, process_event("nltest /dclist:lab.local", SYS32 + "nltest.exe")),
    (TRUSTS, process_event("n.exe /domain_trusts", "C:\\Temp\\n.exe", original_file_name="nltestrk.exe")),
    (TRUSTS, process_event('dsquery * -filter "(objectClass=trustedDomain)" -attr *', SYS32 + "dsquery.exe")),
    (TRUSTS, process_event("powershell -c Get-DomainTrust", PS)),
    (TRUSTS, process_event("pwsh -c Get-DomainController", PWSH)),
    (TRUSTS, process_event("pwsh -c ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())"
                           ".GetAllTrustRelationships()", PWSH)),
    (RECON, process_event("AdFind.exe -f (objectcategory=computer)", "C:\\Temp\\AdFind.exe")),
    (RECON, process_event("adf.exe -gcb -sc trustdmp", "C:\\Temp\\adf.exe", original_file_name="AdFind.exe")),
    (RECON, process_event("SharpHound.exe -c All", DOWNLOADS + "SharpHound.exe")),
    (RECON, process_event('ADExplorer64.exe -snapshot "" C:\\Temp\\ad.dat', DOWNLOADS + "ADExplorer64.exe")),
    (RECON, process_event("powershell -c Get-DomainUser -SPN", PS)),
    (RECON, process_event("pwsh -c Invoke-ShareFinder -CheckShareAccess", PWSH)),
    (NET, process_event("C:\\Windows\\system32\\net1 user /domain", SYS32 + "net1.exe")),
    (NET, process_event("C:\\Windows\\system32\\net1 user /do", SYS32 + "net1.exe")),
    (NET, process_event('C:\\Windows\\system32\\net1 group "Domain Admins" /domain', SYS32 + "net1.exe")),
    (NET, process_event('C:\\Windows\\system32\\net1 group "Enterprise Admins" / domain', SYS32 + "net1.exe")),
    (NET, process_event("C:\\Windows\\system32\\net1 accounts /domain", SYS32 + "net1.exe")),
    (NET, process_event("net view /domain", SYS32 + "net.exe")),
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_fires_on_planted_discovery_and_tooling(rule, event):
    assert fires(rule, event)


@pytest.mark.parametrize("rule, event", [
    # the download and install around a remote tool, not the tool itself
    (REMOTE_TOOL, process_event(f"powershell.exe Invoke-WebRequest -OutFile {DOWNLOADS}AnyDesk.exe "
                                "https://download.anydesk.com/AnyDesk.exe", PS)),
    (REMOTE_TOOL, process_event(f'msiexec.exe /i "{DOWNLOADS}GoToOpener.msi" /q', SYS32 + "msiexec.exe")),
    (REMOTE_TOOL, process_event("NotAnyDesk.exe", "C:\\Tools\\NotAnyDesk.exe")),
    # everyday troubleshooting
    (TRUSTS, process_event("nltest /dsgetdc:lab.local", SYS32 + "nltest.exe")),
    (TRUSTS, process_event("nltest /sc_query:lab.local", SYS32 + "nltest.exe")),
    (TRUSTS, process_event("dsquery user -name jdoe", SYS32 + "dsquery.exe")),
    (TRUSTS, process_event("powershell -c Get-ADDomainController -Discover", PS)),
    (TRUSTS, process_event('cmd.exe /c "nltest /domain_trusts"', SYS32 + "cmd.exe")),  # the shell, not the tool
    (RECON, process_event("ADExplorer.exe", DOWNLOADS + "ADExplorer.exe")),  # browsing, no snapshot
    (RECON, process_event("powershell -c Get-ADUser -Filter *", PS)),
    (RECON, process_event('cmd.exe /c "AdFind.exe -f (objectcategory=person)"', SYS32 + "cmd.exe")),
    (NET, process_event("net user /domain", SYS32 + "net.exe")),  # its net1.exe child carries the alert
    (NET, process_event("C:\\Windows\\system32\\net1 user", SYS32 + "net1.exe")),  # local accounts
    (NET, process_event("C:\\Windows\\system32\\net1 localgroup administrators", SYS32 + "net1.exe")),
    (NET, process_event("net view", SYS32 + "net.exe")),
    (NET, process_event('C:\\Windows\\system32\\net1 stop "samss" /y', SYS32 + "net1.exe")),
    (NET, process_event("net use \\\\dc01\\sysvol", SYS32 + "net.exe")),
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_stays_quiet_on_admin_work_and_the_processes_around_the_attack(rule, event):
    assert not fires(rule, event)


def test_net_raises_one_alert_whichever_binary_was_typed():
    # `net user /domain` starts net.exe, which starts net1.exe with the same arguments.
    typed = process_event("net user /domain", SYS32 + "net.exe")
    child = process_event("C:\\Windows\\system32\\net1 user /domain", SYS32 + "net1.exe")
    assert len(replay([typed, child], load_rules())) == 1


@pytest.mark.parametrize("rule, technique, severity", [
    (REMOTE_TOOL, "T1219", Severity.MEDIUM),
    (TRUSTS, "T1482", Severity.MEDIUM),
    (RECON, "T1087.002", Severity.HIGH),
    (NET, "T1087.002", Severity.MEDIUM),
])
def test_each_rule_reports_its_stage_technique_and_severity(rule, technique, severity):
    assert (rule.stage, rule.attack_technique, rule.severity) == (Stage.REMOTE_DISCOVERY, technique, severity)


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------


def run(relative):
    events = list(load_events(dataset(relative)))
    signals = replay(events, load_rules())
    by_time = {event.get("UtcTime") or event.get("TimeCreated"): event for event in events}
    return events, signals, by_time


def images(events, signals, rule):
    """The image of each process `rule` fired on, matched back by rule and event."""
    fired = []
    for event in events:
        if replay([event], [rule]):
            fired.append(event["Image"].rsplit("\\", 1)[-1])
    assert len(fired) == sum(s.rule_id == rule.id for s in signals)
    return Counter(fired)


def test_atomic_remote_tool_installs_fire_on_the_tools_not_their_downloads():
    events, signals, _ = run("T1219/atomic_red_team/windows-sysmon.log")
    assert len(events) == 26
    assert {s.rule_id for s in signals} == {REMOTE_TOOL.id}
    # AnyDesk, TeamViewer (installer and client), and GoToAssist's launcher and six helper processes.
    fired = images(events, signals, REMOTE_TOOL)
    assert fired["AnyDesk.exe"] == 5 and fired["GoToAssist.exe"] == 2
    assert fired["TeamViewer.exe"] == 1 and fired["TeamViewer_Setup.exe"] == 1
    assert sum(count for image, count in fired.items() if image.startswith("g2ax_")) == 6
    assert sum(fired.values()) == 15
    # The PowerShell downloads, the msiexec install and the batch file around them stay quiet.
    assert not {"powershell.exe", "msiexec.exe", "cmd.exe"} & set(fired)


def test_screenconnect_fires_on_its_service_and_client():
    events, signals, _ = run("T1219/screenconnect/screenconnect_sysmon.log")
    fired = images(events, signals, REMOTE_TOOL)
    assert fired == {"ScreenConnect.ClientService.exe": 2, "ScreenConnect.WindowsClient.exe": 3}
    assert len(signals) == 5
    # The ClickOnce launcher that the browser downloads is not in the list; what it installs is.
    assert any(event.get("Image", "").endswith("\\ScreenConnect.Client.exe") for event in events)


def test_trust_discovery_run_fires_on_each_tool_once():
    events, signals, _ = run("T1482/atomic_red_team/windows-sysmon.log")
    assert len(events) == 515
    assert images(events, signals, TRUSTS) == {"nltest.exe": 3, "dsquery.exe": 1, "powershell.exe": 1}
    assert images(events, signals, RECON) == {"AdFind.exe": 2}
    assert len(signals) == 7  # the cmd.exe processes that launched them stay quiet


def test_account_discovery_run_fires_on_net1_and_powerview():
    events, signals, _ = run("T1087.002/AD_discovery/windows-sysmon.log")
    assert len(events) == 7070
    assert images(events, signals, NET) == {"net1.exe": 8}  # never also on the net.exe that started each
    assert images(events, signals, RECON) == {"powershell.exe": 2}  # Get-DomainUser, twice
    assert len(signals) == 10
    # Not covered, and pinned so a change shows: the ActiveDirectory module, dsquery and WMI listings.
    command_lines = [event.get("CommandLine", "") for event in events]
    assert any("Get-ADUser -Filter *" in c for c in command_lines)
    assert any(c.startswith("dsquery  user") for c in command_lines)
    assert any("ds_user" in c for c in command_lines)
