"""Stage 3 (credential theft): LSASS read or dumped, the AD database or registry hives copied, and
DCSync.

The planted events pin down each rule's edges, including the system processes that hold LSASS
with full access every day. The attack_data tests replay real Atomic Red Team runs of every
common LSASS dumping method and NTDS.dit theft, and real mimikatz and Impacket DCSync.
"""

from collections import Counter

import pytest

from dwellwatch.models import Severity, Stage
from dwellwatch.replay import load_events, load_rule, load_rules, replay

from conftest import ROOT, dataset, process_event, security_event

STAGE3 = ROOT / "sigma" / "stage3_credential_theft"
LSASS_ACCESS = load_rule(STAGE3 / "lsass_memory_access.yml")
LSASS_COMMAND = load_rule(STAGE3 / "lsass_dump_command.yml")
NTDS = load_rule(STAGE3 / "ntds_database_copied.yml")
HIVES = load_rule(STAGE3 / "registry_hives_copied.yml")
DCSYNC = load_rule(STAGE3 / "dcsync_by_non_dc_account.yml")
DUMP_FILE = load_rule(STAGE3 / "credential_dump_file_written.yml")

SYS32 = "C:\\Windows\\System32\\"
TOOLS = "C:\\Tools\\"
GET_CHANGES_ALL = "%%7688\r\n\t\t{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"  # DS-Replication-Get-Changes-All


def fires(rule, event):
    return len(replay([event], [rule])) == 1


PLAIN = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\KERNELBASE.dll+2bfee"


def access(source, granted, call_trace=PLAIN, target=SYS32 + "lsass.exe"):
    """A planted Sysmon event 10: `source` opening `target`."""
    return {"EventID": "10", "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "DC01.lab.local",
            "TimeCreated": "2025-04-24T09:00:00Z", "SourceImage": source, "TargetImage": target,
            "GrantedAccess": granted, "CallTrace": call_trace}


def file_written(path, image=TOOLS + "procdump64.exe"):
    """A planted Sysmon event 11: `image` creating `path`."""
    return {"EventID": "11", "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "DC01.lab.local",
            "TimeCreated": "2025-04-24T09:00:00Z", "Image": image, "TargetFilename": path}


def replication(subject, properties=GET_CHANGES_ALL, access_mask="0x100"):
    return security_event(4662, SubjectUserName=subject, SubjectDomainName="LAB", AccessMask=access_mask,
                          ObjectType="%{19195a5b-6da0-11d0-afd3-00c04fd930c9}", Properties=properties)


DBGCORE = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\SYSTEM32\\dbgcore.DLL+6dd3"
COMSVCS = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|C:\\Windows\\System32\\comsvcs.dll+2d4a1"
UNKNOWN = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN(00007FF8DDCB3F41)"  # .NET code, as in any PowerShell


@pytest.mark.parametrize("rule, event", [
    (LSASS_ACCESS, access(TOOLS + "procdump64.exe", "0x1fffff", DBGCORE)),
    (LSASS_ACCESS, access(SYS32 + "rundll32.exe", "0x1410", COMSVCS)),  # dump functions, narrow access
    (LSASS_ACCESS, access(TOOLS + "m.exe", "0x1010")),  # mimikatz's own access mask
    (LSASS_ACCESS, access(TOOLS + "644c305e.exe", "0x1fffff")),  # full access, no dump functions
    (LSASS_ACCESS, access("C:\\Users\\Public\\csrss.exe", "0x1fffff")),  # a system name in the wrong folder
    (LSASS_COMMAND, process_event("procdump.exe -accepteula -ma lsass.exe C:\\t\\l.dmp", TOOLS + "procdump.exe")),
    (LSASS_COMMAND, process_event("x.exe -ma lsass.exe l.dmp", TOOLS + "x.exe", original_file_name="procdump")),
    (LSASS_COMMAND, process_event("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 l.dmp full",
                                  SYS32 + "rundll32.exe")),
    (LSASS_COMMAND, process_event("rundll32 comsvcs.dll, #24 624 C:\\t\\l.dmp full", SYS32 + "rundll32.exe")),
    (LSASS_COMMAND, process_event('m.exe "sekurlsa::logonpasswords" exit', TOOLS + "m.exe")),
    (LSASS_COMMAND, process_event('m.exe "lsadump::dcsync /user:krbtgt" exit', TOOLS + "m.exe")),
    (LSASS_COMMAND, process_event("rdrleakdiag.exe /p 668 /o C:\\t /fullmemdmp /snap", SYS32 + "rdrleakdiag.exe")),
    (LSASS_COMMAND, process_event("PPLdump.exe -v lsass lsass.dmp", TOOLS + "PPLdump.exe")),
    (NTDS, process_event('ntdsutil "ac i ntds" "ifm" "create full C:\\t\\ifm" q q', SYS32 + "ntdsutil.exe")),
    (NTDS, process_event("cmd /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy3\\Windows\\NTDS\\"
                         "ntds.dit C:\\t\\n.dit", SYS32 + "cmd.exe")),
    (NTDS, process_event("esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d n.dit", SYS32 + "esentutl.exe")),
    (HIVES, process_event("reg save HKLM\\SAM C:\\t\\sam", SYS32 + "reg.exe")),
    (HIVES, process_event("reg.exe save hklm\\security C:\\t\\sec /y", SYS32 + "reg.exe")),
    (HIVES, process_event("cmd /c copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\"
                          "config\\SAM C:\\t\\sam", SYS32 + "cmd.exe")),
    (DCSYNC, replication("Administrator")),
    (DCSYNC, replication("jdoe", "%%7688\r\n\t\t{89e95b76-444d-4c62-991a-0facbeda640c}")),
    (DUMP_FILE, file_written("C:\\Windows\\Temp\\lsass_dump.dmp")),
    (DUMP_FILE, file_written("C:\\Users\\jdoe\\AppData\\Local\\Temp\\lsass (2).DMP", SYS32 + "taskmgr.exe")),
    (DUMP_FILE, file_written("C:\\Windows\\Temp\\ifm\\Active Directory\\ntds.dit", SYS32 + "ntdsutil.exe")),
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_fires_on_planted_credential_theft(rule, event):
    assert fires(rule, event)


@pytest.mark.parametrize("rule, event", [
    # the processes that open LSASS every day
    (LSASS_ACCESS, access(SYS32 + "svchost.exe", "0x1400")),
    (LSASS_ACCESS, access(SYS32 + "csrss.exe", "0x1fffff")),
    (LSASS_ACCESS, access(SYS32 + "wininit.exe", "0x1fffff")),
    (LSASS_ACCESS, access(SYS32 + "wbem\\wmiprvse.exe", "0x1410")),
    (LSASS_ACCESS, access(SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "0x1410", UNKNOWN)),  # Get-Process
    (LSASS_ACCESS, access(TOOLS + "procdump64.exe", "0x1fffff", DBGCORE, target=SYS32 + "notepad.exe")),
    # the same tools against something else, and the shells around them
    (LSASS_COMMAND, process_event("procdump.exe -ma notepad.exe", TOOLS + "procdump.exe")),
    (LSASS_COMMAND, process_event('cmd.exe /c "procdump.exe -ma lsass.exe C:\\t\\l.dmp"', SYS32 + "cmd.exe")),
    (LSASS_COMMAND, process_event("powershell -c rundll32 comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full",
                                  SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe")),
    (LSASS_COMMAND, process_event("rundll32.exe comsvcs.dll,DllRegisterServer", SYS32 + "rundll32.exe")),
    (LSASS_COMMAND, process_event("rdrleakdiag.exe /p 668 /o C:\\t /snap", SYS32 + "rdrleakdiag.exe")),
    (NTDS, process_event('ntdsutil "ac i ntds" "files" "info" q q', SYS32 + "ntdsutil.exe")),
    (NTDS, process_event("vssadmin create shadow /for=C:", SYS32 + "vssadmin.exe")),
    (HIVES, process_event("reg save HKLM\\SOFTWARE\\Vendor C:\\t\\vendor.hiv", SYS32 + "reg.exe")),
    (HIVES, process_event("reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", SYS32 + "reg.exe")),
    # domain controllers replicating as themselves, and other directory reads
    (DCSYNC, replication("DC02$")),
    (DCSYNC, replication("Administrator", access_mask="0x10")),
    (DCSYNC, replication("helpdesk1", "{00299570-246d-11d0-a768-00aa006e0529}")),  # force password change
    # files that are not credential stores, and NTDS.dit where it lives
    (DUMP_FILE, file_written("C:\\Windows\\NTDS\\ntds.dit", SYS32 + "lsass.exe")),
    (DUMP_FILE, file_written("C:\\ProgramData\\Microsoft\\Windows\\WER\\memory.dmp", SYS32 + "WerFault.exe")),
    (DUMP_FILE, file_written("C:\\Windows\\Debug\\lsass.log", SYS32 + "lsass.exe")),
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_stays_quiet_on_what_windows_and_admins_do_every_day(rule, event):
    assert not fires(rule, event)


@pytest.mark.parametrize("rule, technique", [
    (LSASS_ACCESS, "T1003.001"), (LSASS_COMMAND, "T1003.001"), (NTDS, "T1003.003"), (HIVES, "T1003.002"),
    (DCSYNC, "T1003.006"), (DUMP_FILE, "T1003.001"),
])
def test_every_stage3_rule_is_high_and_names_its_technique(rule, technique):
    assert (rule.stage, rule.attack_technique, rule.severity) == (Stage.CREDENTIAL_THEFT, technique, Severity.HIGH)


def test_dcsync_names_the_account_that_asked():
    [signal] = replay([replication("jdoe")], [DCSYNC])
    assert signal.user == "LAB\\jdoe"


def test_sysmon_10_names_the_account_reaching_in_when_sysmon_records_it():
    event = access(TOOLS + "procdump64.exe", "0x1fffff", DBGCORE) | {"SourceUser": "LAB\\jdoe"}
    assert [s.user for s in replay([event], [LSASS_ACCESS])] == ["LAB\\jdoe"]
    assert [s.user for s in replay([access(TOOLS + "m.exe", "0x1010")], [LSASS_ACCESS])] == [None]


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------


def by_rule_and_process(relative):
    events, rules = list(load_events(dataset(relative))), load_rules()
    fired = Counter()
    for event in events:
        for signal in replay([event], rules):
            image = event.get("Image") or event.get("SourceImage") or ""
            fired[(signal.rule_id, image.rsplit("\\", 1)[-1])] += 1
    return events, fired


def test_every_lsass_dumping_method_in_the_atomic_run_is_caught():
    events, fired = by_rule_and_process("T1003.001/atomic_red_team/windows-sysmon.log")
    assert len(events) == 7960
    access_by = {image: count for (rule, image), count in fired.items() if rule == LSASS_ACCESS.id}
    # A mimikatz-like tool named by a GUID, which opens LSASS 38 times, and every dumping tool.
    assert access_by == {"644c305e-30f4-470b-b616-d924c3206d1d.exe": 38, "procdump64.exe": 4, "procdump.exe": 2,
                         "notprocdump64.exe": 2, "notprocdump.exe": 1, "Outflank-Dumpert.exe": 2,
                         "rundll32.exe": 2, "taskmgr.exe": 2}
    command_by = {image: count for (rule, image), count in fired.items() if rule == LSASS_COMMAND.id}
    # procdump twice per test (32- and 64-bit), the renamed copy, comsvcs, and mimikatz's command
    # line, which only its cmd.exe carries because mimikatz itself never started.
    assert command_by == {"procdump64.exe": 2, "procdump.exe": 2, "notprocdump64.exe": 1, "notprocdump.exe": 1,
                          "rundll32.exe": 1, "cmd.exe": 1}
    files_by = {image: count for (rule, image), count in fired.items() if rule == DUMP_FILE.id}
    # Dumpert names its file dumpert.dmp, which the file rule does not know; the access rule saw it.
    assert files_by == {"procdump64.exe": 2, "notprocdump64.exe": 1, "rundll32.exe": 1, "taskmgr.exe": 1}
    assert sum(fired.values()) == 66


def test_ntds_theft_run_is_caught_at_each_step():
    events, fired = by_rule_and_process("T1003.003/atomic_red_team/windows-sysmon.log")
    # ntdsutil's snapshot; one cmd.exe copying NTDS.dit and the SYSTEM hive out of a shadow copy,
    # which is both thefts; and reg.exe saving SYSTEM.
    assert fired == {(NTDS.id, "ntdsutil.exe"): 1, (NTDS.id, "cmd.exe"): 1, (HIVES.id, "cmd.exe"): 1,
                     (HIVES.id, "reg.exe"): 1}


def test_mimikatz_dcsync_is_caught_once_per_replication_right():
    events = list(load_events(dataset("T1003.006/mimikatz/xml-windows-security.log")))
    signals = replay(events, load_rules())
    assert [(s.rule_id, s.user) for s in signals] == [(DCSYNC.id, "ATTACKRANGE\\Administrator")] * 4


def test_impacket_dcsync_from_a_machine_account_is_a_known_blind_spot():
    # secretsdump run with the domain controller's own machine account looks like replication
    # between domain controllers. Pinned so that closing the gap shows up as a test change.
    events = list(load_events(dataset("T1003.006/impacket/windows-security-xml.log")))
    assert {e["SubjectUserName"] for e in events if e.get("EventID") == "4662"} == {"AR-WIN-DC$"}
    assert replay(events, load_rules()) == []
