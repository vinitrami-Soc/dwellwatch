"""Stage 6 (encryption, the backstop): ransom notes, the DwellWatch canary files, disk encryption
turned against the owner, and files encrypted with a passphrase on the command line.

The planted events pin down each rule's edges, including the READMEs and BitLocker commands that
ordinary software and administrators produce. The attack_data tests replay DiskCryptor and
BitLocker abuse, and a SamSam run whose only README is the log forwarder's own.
"""

from collections import Counter

import pytest

from dwellwatch.models import Severity, Stage
from dwellwatch.replay import load_events, load_rule, load_rules, replay

from conftest import ROOT, dataset, process_event

STAGE6 = ROOT / "sigma" / "stage6_encryption"
NOTE = load_rule(STAGE6 / "ransom_note_written.yml")
CANARY = load_rule(STAGE6 / "canary_file_touched.yml")
DISK = load_rule(STAGE6 / "disk_encryption_abuse.yml")
CLI = load_rule(STAGE6 / "files_encrypted_with_cli_tool.yml")

SYS32 = "C:\\Windows\\System32\\"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
BDE = SYS32 + "manage-bde.exe"
GPG = "C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe"


def fires(rule, event):
    return len(replay([event], [rule])) == 1


def written(path, image="C:\\Users\\Public\\x.exe"):
    """A planted Sysmon event 11: `image` creating or overwriting `path`."""
    return {"EventID": "11", "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "FS01.lab.local",
            "TimeCreated": "2025-04-24T09:00:00Z", "Image": image, "TargetFilename": path}


@pytest.mark.parametrize("rule, event", [
    (NOTE, written("C:\\Shares\\Finance\\HOW_TO_DECRYPT.txt")),
    (NOTE, written("C:\\Users\\jdoe\\Desktop\\YOUR_FILES.txt")),  # Atomic Red Team's PureLocker note
    (NOTE, written("C:\\Shares\\HR\\RESTORE-MY-FILES.html")),
    (NOTE, written("D:\\Data\\_readme.txt")),
    (NOTE, written("C:\\Shares\\DECRYPT_INSTRUCTIONS.hta")),
    (CANARY, written("C:\\Shares\\Finance\\dwellwatch-canary-q3-budget.xlsx.lockbit")),  # an encrypted copy
    (CANARY, written("C:\\Shares\\Finance\\dwellwatch-canary-q3-budget.xlsx")),  # overwritten in place
    (DISK, process_event("manage-bde -protectors -delete C:", BDE)),
    (DISK, process_event("manage-bde -on C: -pw -UsedSpaceOnly", BDE)),
    (DISK, process_event("manage-bde -forcerecovery C:", BDE)),
    (DISK, process_event("powershell Remove-BitLockerKeyProtector -MountPoint C: -KeyProtectorId $id", PS)),
    (DISK, process_event("powershell Enable-BitLocker -MountPoint C: -PasswordProtector -Password $p", PS)),
    (DISK, process_event("dcrypt.exe", "C:\\Program Files\\dcrypt\\dcrypt.exe")),
    (DISK, process_event("dcinst.exe -setup", "C:\\Program Files\\dcrypt\\dcinst.exe")),
    (CLI, process_event("gpg --passphrase 'x' --batch --yes -c C:\\Users\\Public\\Documents\\f.txt", GPG)),
    (CLI, process_event("openssl enc -aes-256-cbc -in f.xlsx -out f.enc -pass pass:x", "C:\\T\\openssl.exe")),
    (CLI, process_event("7z a -pS3cret -mhe=on C:\\t\\out.7z C:\\Shares\\*", "C:\\Program Files\\7-Zip\\7z.exe")),
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_fires_on_planted_encryption(rule, event):
    assert fires(rule, event)


@pytest.mark.parametrize("rule, event", [
    (NOTE, written("C:\\Program Files\\SplunkUniversalForwarder\\etc\\apps\\Splunk_TA_stream\\README.txt")),
    (NOTE, written("C:\\Users\\jdoe\\Documents\\notes.txt")),
    (NOTE, written("C:\\Tools\\HOW_TO_DECRYPT.exe")),  # a name like a note, but not a page
    (NOTE, written("C:\\Windows\\Logs\\restore.log")),
    (CANARY, written("C:\\Shares\\Finance\\q3-budget.xlsx.lockbit")),
    (DISK, process_event("manage-bde -status", BDE)),
    (DISK, process_event("manage-bde -on C: -RecoveryPassword -SkipHardwareTest", BDE)),  # a normal rollout
    (DISK, process_event("manage-bde -protectors -get C:", BDE)),
    (DISK, process_event("powershell Get-BitLockerVolume", PS)),
    (CLI, process_event("gpg --verify release.zip.sig", GPG)),
    (CLI, process_event("gpg -c f.txt", GPG)),  # prompts for the passphrase
    (CLI, process_event("openssl req -new -key k.pem -out r.csr", "C:\\Tools\\openssl.exe")),
    (CLI, process_event("7z a C:\\t\\out.7z C:\\Shares\\HR", "C:\\Program Files\\7-Zip\\7z.exe")),
    (CLI, process_event("7z x -pS3cret C:\\t\\in.7z", "C:\\Program Files\\7-Zip\\7z.exe")),  # extracting
], ids=lambda value: getattr(value, "path", None) and value.path.stem or None)
def test_stays_quiet_on_ordinary_files_and_admin_work(rule, event):
    assert not fires(rule, event)


@pytest.mark.parametrize("rule, severity", [
    (NOTE, Severity.HIGH), (CANARY, Severity.CRITICAL), (DISK, Severity.HIGH), (CLI, Severity.MEDIUM),
])
def test_every_stage6_rule_is_encryption_t1486(rule, severity):
    assert (rule.stage, rule.attack_technique, rule.severity) == (Stage.ENCRYPTION, "T1486", severity)


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------


def fired_images(relative):
    events, rules = list(load_events(dataset(relative))), load_rules()
    fired = Counter()
    for event in events:
        for signal in replay([event], rules):
            fired[(signal.rule_id, event["Image"].rsplit("\\", 1)[-1])] += 1
    return events, fired


def test_diskcryptor_install_and_run_fire():
    events, fired = fired_images("T1486/dcrypt/windows-sysmon.log")
    assert len(events) == 343
    # The downloaded dcrypt.exe, the installed one, and its driver installer; not the Inno Setup
    # stub (dcrypt.tmp) that unpacked them.
    assert fired == {(DISK.id, "dcrypt.exe"): 2, (DISK.id, "dcinst.exe"): 1}


def test_bitlocker_protectors_deleted_fires():
    events, fired = fired_images("T1486/bitlocker_sus_commands/bitlocker_sus_commands.log")
    assert fired == {(DISK.id, "manage-bde.exe"): 1}


def test_a_readme_from_ordinary_software_is_not_a_ransom_note():
    events, fired = fired_images("T1486/sam_sam_note/windows-sysmon.log")
    assert len(events) == 8491
    assert any(e.get("TargetFilename", "").endswith("\\README.txt") for e in events)  # the forwarder's own
    assert fired == Counter()
