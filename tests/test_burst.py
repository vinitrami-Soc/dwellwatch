"""The note-burst counter: one process writing one file name into 20 folders within 10 minutes."""

from datetime import UTC, datetime, timedelta

import pytest

from dwellwatch.burst import NOTE_BURST_RULE_ID, NOTE_FOLDERS, NOTE_WINDOW, NoteBursts, note_bursts
from dwellwatch.correlate import correlate
from dwellwatch.models import Severity, Signal, Stage
from dwellwatch.replay import load_events

from conftest import dataset

T0 = datetime(2025, 4, 24, 9, 0, tzinfo=UTC)
SECOND = timedelta(seconds=1)


def file_event(path, at=T0, *, process="{A1}", host="FS01.lab.local", user=None):
    """A planted Sysmon file-creation event, flat, as load_events returns it."""
    event = {"EventID": "11", "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": host,
             "TimeCreated": at.isoformat(), "ProcessGuid": process, "ProcessId": "4242",
             "Image": "C:\\Users\\Public\\enc.exe", "TargetFilename": path}
    if user:
        event["User"] = user
    return event


def spray(folders, name="README.txt", *, every=SECOND, start=T0, **kwargs):
    return [file_event(f"C:\\Shares\\Finance\\dir{i:03}\\{name}", start + i * every, **kwargs)
            for i in range(folders)]


def test_twenty_folders_in_ten_minutes_is_one_stage_6_signal_at_the_twentieth():
    [signal] = note_bursts(spray(NOTE_FOLDERS))
    assert (signal.stage, signal.attack_technique, signal.severity) == (Stage.ENCRYPTION, "T1486", Severity.HIGH)
    assert (signal.host, signal.user, signal.rule_id) == ("FS01.lab.local", None, NOTE_BURST_RULE_ID)
    assert signal.timestamp == T0 + (NOTE_FOLDERS - 1) * SECOND


def test_nineteen_folders_are_not_a_burst():
    assert note_bursts(spray(NOTE_FOLDERS - 1)) == []


def test_the_folders_must_fall_within_ten_minutes_of_each_other():
    # One folder a minute: never more than 11 inside any 10-minute window, however long it goes on.
    assert note_bursts(spray(60, every=timedelta(minutes=1))) == []
    # The window includes its end: a 20th folder exactly 10 minutes after the first counts, a second later not.
    nineteen = spray(NOTE_FOLDERS - 1)
    at_the_edge = file_event("C:\\Shares\\Finance\\last\\README.txt", T0 + NOTE_WINDOW)
    assert len(note_bursts([*nineteen, at_the_edge])) == 1
    at_the_edge["TimeCreated"] = (T0 + NOTE_WINDOW + SECOND).isoformat()
    assert note_bursts([*nineteen, at_the_edge]) == []


def test_one_folder_written_many_times_is_not_a_burst():
    assert note_bursts([file_event("C:\\Shares\\Finance\\README.txt", T0 + i * SECOND) for i in range(100)]) == []


def test_the_folders_must_be_written_by_one_process():
    events = spray(NOTE_FOLDERS)
    for i, event in enumerate(events):
        event["ProcessGuid"] = f"{{A{i % 2}}}"  # two processes, 10 folders each
    assert note_bursts(events) == []


def test_the_files_must_share_a_name():
    reports = [file_event(f"C:\\Shares\\dir{i}\\report{i}.docx", T0 + i * SECOND) for i in range(50)]
    assert note_bursts(reports) == []


def test_names_and_folders_are_compared_as_windows_does_without_case():
    events = spray(NOTE_FOLDERS)
    for i, event in enumerate(events):
        if i % 2:
            event["TargetFilename"] = event["TargetFilename"].upper()
    assert len(note_bursts(events)) == 1
    # The same folder in two spellings is still one folder.
    doubled = spray(NOTE_FOLDERS - 1) + [file_event("C:\\SHARES\\FINANCE\\DIR000\\readme.TXT", T0 + 30 * SECOND)]
    assert note_bursts(doubled) == []


def test_a_long_spray_is_one_signal_and_a_new_one_after_ten_quiet_minutes_is_another():
    first = spray(900)
    second = spray(NOTE_FOLDERS, start=T0 + 900 * SECOND + NOTE_WINDOW + SECOND)
    signals = note_bursts(first + second)
    assert [s.timestamp for s in signals] == [T0 + 19 * SECOND, T0 + 900 * SECOND + NOTE_WINDOW + 20 * SECOND]


def test_arrival_order_does_not_matter():
    events = spray(NOTE_FOLDERS)
    assert note_bursts(reversed(events)) == note_bursts(events)


def test_the_account_is_kept_when_sysmon_records_one():
    [signal] = note_bursts(spray(NOTE_FOLDERS, user="LAB\\jdoe"))
    assert signal.user == "LAB\\jdoe"


def test_without_a_process_guid_the_process_id_and_image_identify_the_process():
    events = spray(NOTE_FOLDERS)
    for event in events:
        del event["ProcessGuid"]
    assert len(note_bursts(events)) == 1
    events[0]["ProcessId"] = "99"  # a different process, so only 19 folders from the first
    assert note_bursts(events) == []


def test_only_sysmon_file_creations_count():
    events = spray(NOTE_FOLDERS)
    for event in events:
        event["EventID"] = "23"  # file delete
    assert note_bursts(events) == []


def test_watching_passes_events_through_untouched():
    events = spray(NOTE_FOLDERS)
    bursts = NoteBursts()
    assert list(bursts.watch(iter(events))) == events
    assert len(bursts.signals()) == 1


def test_the_threshold_and_window_can_be_changed_for_tuning():
    assert len(note_bursts(spray(5), folders=5)) == 1
    assert note_bursts(spray(NOTE_FOLDERS, every=timedelta(minutes=1)), window=timedelta(minutes=5)) == []
    with pytest.raises(ValueError):
        NoteBursts(folders=1)


# --- recordings -------------------------------------------------------------------------------


def test_a_real_ransomware_spray_is_one_burst():
    # 83 ransom notes, HOW_TO_RESTORE_MY_FILES.txt, from one cscript.exe in 5 seconds.
    [signal] = note_bursts(load_events(dataset("malware/ransomware_ttp/data2/windows-sysmon.log")))
    assert signal.host == "win-dc-385.attackrange.local"
    assert signal.timestamp.strftime("%H:%M:%S") == "14:31:28"


@pytest.mark.parametrize("relative", [
    "T1087.002/AD_discovery/windows-sysmon.log",  # 7-Zip writing readme.txt into 10 folders of a source tree
    "T1003.001/atomic_red_team/windows-sysmon.log",  # PowerShell installing modules: YamlDotNet.dll in 9 folders
    "T1486/sam_sam_note/windows-sysmon.log",  # one note, one folder
    "T1486/dcrypt/windows-sysmon.log",  # disk encryption: no notes at all
])
def test_ordinary_software_and_single_notes_are_not_bursts(relative):
    assert note_bursts(load_events(dataset(relative))) == []


def test_a_burst_joins_the_backup_deletion_before_it_in_one_incident():
    shadow_delete = Signal(stage=Stage.BACKUP_DESTRUCTION, host="FS01.lab.local", user="LAB\\jdoe", timestamp=T0,
                           rule_id="rule-5", attack_technique="T1490", severity=Severity.HIGH)
    burst = note_bursts(spray(NOTE_FOLDERS, start=T0 + timedelta(hours=2), host="FS01"))
    [incident] = correlate([shadow_delete, *burst])
    assert incident.stages == (Stage.BACKUP_DESTRUCTION, Stage.ENCRYPTION)
    assert (incident.entity_kind, incident.entity) == ("host", "fs01")
