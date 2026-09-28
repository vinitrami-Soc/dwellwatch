"""Stage 6 by counting: one process writing a file of the same name into many folders, fast.

Ransomware leaves its ransom note in every folder it encrypts, always under one name
(readme.txt, HOW_TO_RESTORE_MY_FILES.txt, a random name per victim). A Sigma rule sees one event
at a time, so it can only match notes by names someone has already seen; counting sees the
spray whatever the note is called:

    One process creating or overwriting files of one name in NOTE_FOLDERS (20) different
    folders within NOTE_WINDOW (10 minutes) is a stage 6 signal (T1486), timed at the write
    that reaches the 20th folder. It fires once per spray; the same process and name can fire
    again only after 10 quiet minutes.

The events are Sysmon's file creations (event 11), the ones the file_event rules read. Names and
folders are compared without regard to case, as Windows does. The 20 was chosen after measuring
recordings of both ransomware and ordinary software; docs/detection-catalogue.md has the numbers.

Wazuh counts differently: its frequency rules cannot count distinct file names, so the Wazuh
version (wazuh/dwellwatch_fim_rules.xml) counts file changes in monitored folders instead.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta

from .models import Severity, Signal, Stage
from .replay import SYSMON, Event, event_time

NOTE_FOLDERS = 20
NOTE_WINDOW = timedelta(minutes=10)
NOTE_BURST_RULE_ID = "0fbcaaab-4e91-4837-b258-0718e7acfda1"  # stands in for a Sigma rule's id
NOTE_BURST_TITLE = "DwellWatch Same File Name Written Into Many Folders"

Write = tuple[datetime, str, str | None]  # when, which folder, the account if Sysmon recorded one


class NoteBursts:
    """Notes file creations as events stream past; signals() then finds the sprays.

    Events can arrive in any order (exports often run newest first), so the writes are kept,
    compactly, and ordered only when signals() is asked for.
    """

    def __init__(self, folders: int = NOTE_FOLDERS, window: timedelta = NOTE_WINDOW) -> None:
        if folders < 2:
            raise ValueError("a spray needs at least two folders")
        self.folders, self.window = folders, window
        self._writes: dict[tuple[str, str, str], list[Write]] = defaultdict(list)

    def add(self, event: Event) -> None:
        if event.get("Channel") != SYSMON or event.get("EventID") != "11":
            return
        folder, _, name = event.get("TargetFilename", "").rpartition("\\")
        if not folder or not name:
            return
        process = event.get("ProcessGuid") or f"{event.get('ProcessId', '')}|{event.get('Image', '')}"
        key = (event.get("Computer", ""), process.lower(), name.lower())
        self._writes[key].append((event_time(event), folder.lower(), event.get("User") or None))

    def watch(self, events: Iterable[Event]) -> Iterator[Event]:
        """Pass `events` through unchanged, noting the file creations on the way."""
        for event in events:
            self.add(event)
            yield event

    def signals(self) -> list[Signal]:
        """One stage 6 signal per spray, in time order."""
        found = []
        for (host, _, _), writes in self._writes.items():
            writes.sort(key=lambda write: (write[0], write[1]))
            recent: deque[tuple[datetime, str]] = deque()
            folders: Counter[str] = Counter()
            fired = False
            for when, folder, user in writes:
                if recent and when - recent[-1][0] > self.window:
                    fired = False  # a quiet window: whatever comes next is a new spray
                recent.append((when, folder))
                folders[folder] += 1
                while when - recent[0][0] > self.window:
                    _, old = recent.popleft()
                    folders[old] -= 1
                    if not folders[old]:
                        del folders[old]
                if len(folders) >= self.folders and not fired:
                    fired = True
                    found.append(Signal(
                        stage=Stage.ENCRYPTION,
                        host=host,
                        user=user,
                        timestamp=when,
                        rule_id=NOTE_BURST_RULE_ID,
                        attack_technique="T1486",
                        severity=Severity.HIGH,
                    ))
        return sorted(found, key=lambda signal: (signal.timestamp, signal.host))


def note_bursts(events: Iterable[Event], folders: int = NOTE_FOLDERS,
                window: timedelta = NOTE_WINDOW) -> list[Signal]:
    """The sprays in `events`: see the module docstring."""
    bursts = NoteBursts(folders, window)
    for event in events:
        bursts.add(event)
    return bursts.signals()
