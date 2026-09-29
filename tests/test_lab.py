"""The live lab's configuration against the rules: it must record everything they read.

Nothing here runs Windows. It checks that the Sysmon configuration covers every Sysmon event the
rules read, the audit policy every Security event, the canaries sit where the canary rules look,
the Vagrantfile provisions every script, and replay reads what the export script writes.
"""

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

import pytest
import yaml

from dwellwatch.replay import LOGSOURCES, SYSMON, load_events, load_rules

from conftest import ROOT

LAB = ROOT / "lab"
SYSMON_CONFIG = ET.parse(LAB / "sysmon" / "dwellwatch-sysmon.xml").getroot()
AUDIT = (LAB / "provision" / "audit-policy.ps1").read_text(encoding="utf-8")
CANARIES = (LAB / "provision" / "canaries.ps1").read_text(encoding="utf-8")
VAGRANTFILE = (LAB / "Vagrantfile").read_text(encoding="utf-8")

SYSMON_ELEMENTS = {1: "ProcessCreate", 10: "ProcessAccess", 11: "FileCreate"}
# Which audit subcategory writes each Security event the rules read (Microsoft's auditpol GUIDs).
AUDIT_SUBCATEGORY = {
    4688: "0CCE922B", 4720: "0CCE9235", 4724: "0CCE9235", 4738: "0CCE9235",
    4728: "0CCE9237", 4732: "0CCE9237", 4756: "0CCE9237",
    4624: "0CCE9215", 4625: "0CCE9215", 4662: "0CCE923B",
}


def sysmon_rules(element):
    [found] = [e for e in SYSMON_CONFIG.iter(element)]
    return found


def test_the_sysmon_config_covers_every_sysmon_event_the_rules_read():
    read = {event_id for sources in LOGSOURCES.values() for channel, event_id in sources if channel == SYSMON}
    assert read == set(SYSMON_ELEMENTS)
    for event_id, element in SYSMON_ELEMENTS.items():
        assert sum(1 for _ in SYSMON_CONFIG.iter(element)) == 1, f"event {event_id}: one {element} block"


def test_processes_and_files_are_recorded_without_filters():
    # An empty exclude list records everything: a note in any folder, any process at all.
    for element in ("ProcessCreate", "FileCreate"):
        rules = sysmon_rules(element)
        assert rules.get("onmatch") == "exclude" and list(rules) == []


def test_process_access_is_recorded_into_lsass():
    rules = sysmon_rules("ProcessAccess")
    assert rules.get("onmatch") == "include"
    [target] = list(rules)
    assert (target.tag, target.get("condition"), target.text) == ("TargetImage", "end with", "\\lsass.exe")


def test_sysmon_records_the_sha256_the_webhook_sends():
    assert "SHA256" in SYSMON_CONFIG.findtext("HashAlgorithms").split(",")
    assert SYSMON_CONFIG.get("schemaversion") == "4.90"


def security_event_ids() -> set[int]:
    ids = {event_id for (_, _, service), sources in LOGSOURCES.items() for channel, event_id in sources
           if channel == "Security" and event_id is not None}
    for path in (ROOT / "sigma").glob("stage*_*/*.yml"):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        if rule["logsource"].get("service") == "security":
            ids |= {int(i) for i in re.findall(r"\b4\d{3}\b", yaml.safe_dump(rule["detection"]))}
    return ids


def test_the_audit_policy_turns_on_every_security_event_the_rules_read():
    enabled = set(re.findall(r'"\{([0-9A-F]{8})-69AE-11D9-BED3-505054503030\}"', AUDIT))
    needed = security_event_ids()
    assert needed >= {4624, 4662, 4688, 4724, 4728, 4732, 4756}
    for event_id in needed:
        assert AUDIT_SUBCATEGORY[event_id] in enabled, f"no audit subcategory turned on for {event_id}"


def test_4688_records_the_command_line():
    assert "ProcessCreationIncludeCmdLine_Enabled" in AUDIT and "SCENoApplyLegacyAuditPolicy" in AUDIT


def test_the_canaries_carry_the_token_and_sit_where_both_canary_rules_look():
    token = yaml.safe_load((ROOT / "sigma" / "stage6_encryption" / "canary_file_touched.yml").read_text())[
        "detection"]["selection"]["TargetFilename|contains"]
    names = re.findall(r'"(dwellwatch-canary[^"]+)"', CANARIES)
    assert names and all(token in name for name in names)
    folders = set(re.findall(r'"(C:\\[^"]+)"', CANARIES))
    watched = [d.text for d in ET.parse(ROOT / "wazuh" / "agent_syscheck.xml").getroot().iter("directories")]
    for folder in folders:
        assert any(folder.lower().startswith(w.lower()) for w in watched), f"{folder} is not watched by Wazuh FIM"


def test_the_vagrantfile_provisions_every_script_and_the_sysmon_config():
    provisioned = re.findall(r'provision "shell", path: "(provision/[^"]+)"', VAGRANTFILE)
    assert sorted(provisioned) == sorted(f"provision/{p.name}" for p in (LAB / "provision").glob("*.ps1"))
    assert provisioned.index("provision/audit-policy.ps1") == 0
    assert 'destination: "C:/DwellWatch/dwellwatch-sysmon.xml"' in VAGRANTFILE
    default = re.search(r'\$Config = "([^"]+)"', (LAB / "provision" / "sysmon.ps1").read_text()).group(1)
    assert default.replace("\\", "/") == "C:/DwellWatch/dwellwatch-sysmon.xml"
    assert 'ip: "192.168.56.' in VAGRANTFILE  # VirtualBox's host-only range


@pytest.mark.skipif(not shutil.which("ruby"), reason="ruby is not installed")
def test_the_vagrantfile_is_valid_ruby():
    subprocess.run(["ruby", "-c", str(LAB / "Vagrantfile")], check=True, capture_output=True)


@pytest.mark.skipif(not shutil.which("pwsh"), reason="PowerShell is not installed")
@pytest.mark.parametrize("script", sorted(LAB.rglob("*.ps1")), ids=lambda p: p.name)
def test_the_powershell_parses(script):
    parse = ("$t = $null; $e = $null; [System.Management.Automation.Language.Parser]::ParseFile("
             f"'{script}', [ref]$t, [ref]$e) | Out-Null; "
             "if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 }")
    result = subprocess.run(["pwsh", "-NoProfile", "-Command", parse], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_replay_reads_what_the_export_script_writes(tmp_path):
    # wevtutil qe /f:xml /e:Events: one <Events> root, namespaced events, UTF-8 without a BOM.
    export = tmp_path / "sysmon.xml"
    export.write_text(
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        '<Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>'
        '<TimeCreated SystemTime="2026-09-29T10:00:00.1234567Z"/>'
        '<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>ws01</Computer></System>'
        '<EventData><Data Name="Image">C:\\Windows\\System32\\vssadmin.exe</Data>'
        '<Data Name="OriginalFileName">VSSADMIN.EXE</Data>'
        '<Data Name="CommandLine">vssadmin delete shadows /all /quiet</Data></EventData></Event></Events>\n',
        encoding="utf-8")
    [event] = list(load_events(export))
    assert event["Computer"] == "ws01" and event["Image"].endswith("vssadmin.exe")
    from dwellwatch.replay import replay
    [signal] = replay([event], load_rules())
    assert signal.attack_technique == "T1490"
