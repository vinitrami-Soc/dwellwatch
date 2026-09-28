"""The dwell-time metric: how long before encryption DwellWatch first fired, per run and overall.

    python -m dwellwatch.metric                    # measure every run in datasets/runs.yml
    python -m dwellwatch.metric --check README.md  # and fail if the README's headline says otherwise

For one run, measure() takes its signals and returns which stage fired first and how long before
encryption. As the project brief defines it, encryption starts at the first stage 6 signal. The
headline instead gives each run its hand-labelled start, its first ransom note (datasets/runs.yml),
so that the yardstick does not depend on how quickly DwellWatch notices encryption. Known false
positives, labelled in the same file, are left out. Method and caveats: docs/metric-method.md.
"""

from __future__ import annotations

import argparse
import re
import statistics
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from sigma.exceptions import SigmaError

from .correlate import STAGE_NAMES, correlate, detect, raised_at
from .models import Signal, Stage
from .replay import SYSMON, Event, event_time, load_rules

ROOT = Path(__file__).resolve().parents[2]
RUNS = ROOT / "datasets" / "runs.yml"
DATASETS = ROOT / "datasets" / "attack_data" / "datasets"
HEADLINE_LABEL = "**Headline metric:**"

FalsePositive = tuple[str, datetime]  # a rule's id and the second it fired


@dataclass(frozen=True)
class Measurement:
    """One run, measured."""

    encryption_at: datetime | None  # None when there is no labelled start and no stage 6 signal
    first: Signal | None  # the first signal before encryption, false positives left out
    stages_before: tuple[Stage, ...]  # the stages seen before encryption, in attack order
    encryption_seen_at: datetime | None  # the first stage 6 signal: when DwellWatch saw encryption
    incident_at: datetime | None  # when correlation first raised an incident, before or after encryption

    @property
    def first_stage(self) -> Stage | None:
        return self.first.stage if self.first else None

    @property
    def lead(self) -> timedelta | None:
        """How long before encryption the first signal fired; None if nothing fired before it."""
        return self.encryption_at - self.first.timestamp if self.first and self.encryption_at else None

    @property
    def incident_lead(self) -> timedelta | None:
        """How long before encryption an incident was raised; None if none was raised before it."""
        if self.incident_at and self.encryption_at and self.incident_at < self.encryption_at:
            return self.encryption_at - self.incident_at
        return None


def measure(signals: Iterable[Signal], encryption_at: datetime | None = None,
            false_positives: Iterable[FalsePositive] = ()) -> Measurement:
    """Which stage fired first, and how long before encryption. Encryption starts at `encryption_at`
    if given, otherwise at the first stage 6 signal. A signal counts only if strictly earlier."""
    ignored = {(rule, at.replace(microsecond=0)) for rule, at in false_positives}
    kept = sorted((s for s in signals if (s.rule_id, s.timestamp.replace(microsecond=0)) not in ignored),
                  key=lambda s: (s.timestamp, s.stage))
    seen = next((s.timestamp for s in kept if s.stage is Stage.ENCRYPTION), None)
    encryption_at = encryption_at or seen
    before = [s for s in kept if encryption_at and s.timestamp < encryption_at]
    return Measurement(
        encryption_at=encryption_at,
        first=before[0] if before else None,
        stages_before=tuple(sorted({s.stage for s in before})),
        encryption_seen_at=seen,
        incident_at=min((raised_at(incident) for incident in correlate(kept)), default=None),
    )


# --- runs -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Run:
    """A recording in which ransomware encrypted files, with its hand labels (datasets/runs.yml)."""

    name: str
    files: tuple[Path, ...]
    process: re.Pattern[str]  # the image of the process that writes the ransom note
    note: re.Pattern[str]  # the note's path
    false_positives: tuple[FalsePositive, ...]
    seen: bool  # whether the rules or thresholds were shaped with this recording in view


class FirstNote:
    """Notes, as events stream past, when a run's first ransom note was written: `at`."""

    def __init__(self, run: Run) -> None:
        self.run, self.at = run, None

    def watch(self, events: Iterable[Event]) -> Iterator[Event]:
        for event in events:
            if (event.get("Channel") == SYSMON and event.get("EventID") == "11"
                    and self.run.process.search(event.get("Image", ""))
                    and self.run.note.search(event.get("TargetFilename", ""))):
                when = event_time(event)
                self.at = when if self.at is None else min(self.at, when)
            yield event


def load_runs(path: Path = RUNS, datasets: Path = DATASETS) -> list[Run]:
    runs = []
    for entry in yaml.safe_load(path.read_text(encoding="utf-8"))["runs"]:
        runs.append(Run(
            name=entry["name"],
            files=tuple(datasets / name for name in entry["files"]),
            process=re.compile(entry["encryption"]["process"], re.IGNORECASE),
            note=re.compile(entry["encryption"]["file"], re.IGNORECASE),
            false_positives=tuple((fp["rule"], _utc(fp["at"])) for fp in entry.get("false_positives", [])),
            seen=bool(entry["seen"]),
        ))
    return runs


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def measure_run(run: Run, rules=None) -> Measurement:
    """Replay `run` through the rules and counters and measure it against its first ransom note."""
    missing = [path for path in run.files if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"{missing[0]} not fetched; run datasets/fetch.sh --metric")
    note = FirstNote(run)
    signals = detect(run.files, rules if rules is not None else load_rules(), watch=note.watch)
    if note.at is None:
        raise ValueError(f"{run.name}: no file matching its ransom note was written; check datasets/runs.yml")
    return measure(signals, note.at, run.false_positives)


# --- summary ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Summary:
    runs: int
    leads: tuple[timedelta, ...]  # the runs with a signal before encryption
    incident_leads: tuple[timedelta, ...]  # the runs with an incident before encryption

    @property
    def median_lead(self) -> timedelta | None:
        return statistics.median(self.leads) if self.leads else None


def summarise(measurements: Iterable[Measurement]) -> Summary:
    measurements = list(measurements)
    return Summary(
        runs=len(measurements),
        leads=tuple(sorted(m.lead for m in measurements if m.lead is not None)),
        incident_leads=tuple(sorted(m.incident_lead for m in measurements if m.incident_lead is not None)),
    )


def headline(summary: Summary) -> str:
    """The README's number: 'First alert fired N minutes before encryption in X of Y runs'."""
    runs = f"{summary.runs} replayed ransomware runs"
    if summary.median_lead is None:
        return f"No alert fired before encryption in any of {runs}."
    minutes = summary.median_lead.total_seconds() / 60
    amount = f"{minutes:.1f}" if minutes < 10 else f"{minutes:.0f}"
    return (f"First alert fired a median of {amount} minutes before encryption in {len(summary.leads)} "
            f"of {runs}.")


def incident_line(summary: Summary) -> str:
    """The same for correlated incidents, which is what an analyst would be shown."""
    if not summary.incident_leads:
        return "No correlated incident was raised before encryption in any of them."
    minutes = statistics.median(summary.incident_leads).total_seconds() / 60
    return (f"A correlated incident was raised before encryption in {len(summary.incident_leads)} of them, "
            f"a median of {minutes:.1f} minutes before.")


def check_readme(readme: Path, summary: Summary) -> list[str]:
    """What the README's headline paragraph is missing, if anything."""
    text = readme.read_text(encoding="utf-8")
    start = text.find(HEADLINE_LABEL)
    if start < 0:
        return [f"{readme}: no line starting {HEADLINE_LABEL}"]
    end = text.find("\n\n", start)
    paragraph = " ".join(text[start:end if end >= 0 else None].split())
    return [f"{readme}: the headline should say: {line}" for line in (headline(summary), incident_line(summary))
            if line not in paragraph]


# --- command line -----------------------------------------------------------------------------


def _span(delta: timedelta | None) -> str:
    if delta is None:
        return "-"
    seconds = delta.total_seconds()
    if seconds < 1:
        return "<1s"
    return f"{seconds:.0f}s" if seconds < 120 else f"{seconds / 60:.1f} min"


def _relative(when: datetime | None, encryption_at: datetime | None) -> str:
    if when is None or encryption_at is None:
        return "none"
    delta = when - encryption_at
    return f"{_span(-delta)} before" if delta < timedelta(0) else f"{_span(delta)} after"


def report(runs: list[Run], measurements: list[Measurement], write: Callable[[str], None] = print) -> None:
    write(f"{'run':34}{'seen':6}{'encryption (UTC)':21}{'first alert':30}{'lead':10}"
          f"{'encryption seen':17}incident")
    for run, m in zip(runs, measurements, strict=True):
        first = "none before encryption"
        if m.first:
            first = f"stage {int(m.first.stage)}, {STAGE_NAMES[m.first.stage]}"
        started = f"{m.encryption_at.astimezone(UTC):%Y-%m-%d %H:%M:%S}" if m.encryption_at else "-"
        write(f"{run.name:34}{'yes' if run.seen else 'no':6}{started:21}{first:30}{_span(m.lead):10}"
              f"{_relative(m.encryption_seen_at, m.encryption_at):17}{_relative(m.incident_at, m.encryption_at)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dwellwatch.metric",
                                     description="Measure how long before encryption DwellWatch first fires.")
    parser.add_argument("--runs", type=Path, default=RUNS, help="the runs and their labels (datasets/runs.yml)")
    parser.add_argument("--check", type=Path, metavar="README",
                        help="fail unless this file's headline paragraph states the measured numbers")
    args = parser.parse_args(argv)
    try:
        runs, rules = load_runs(args.runs), load_rules()
        measurements = [measure_run(run, rules) for run in runs]
    except (OSError, ValueError, KeyError, SigmaError, yaml.YAMLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    report(runs, measurements)
    summary = summarise(measurements)
    print(f"\n{headline(summary)} {incident_line(summary)}")
    if args.check:
        problems = check_readme(args.check, summary)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
