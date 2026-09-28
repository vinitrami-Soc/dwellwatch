"""Replay recorded Windows events through the Sigma rules, offline, and emit Signals.

pySigma parses the rules, so replay reads them exactly as the SIEM converters will.
pySigma has no in-memory matcher, so this module evaluates its condition tree itself.
It supports the parts of Sigma the rules here use; a rule that needs anything else is
refused when it is loaded, never quietly treated as "no match".

    python -m dwellwatch.replay path/to/windows-sysmon.log [more files...]
"""

from __future__ import annotations

import argparse
import codecs
import itertools
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)

from .models import Severity, Signal, Stage

Event = dict[str, str]
Matcher = Callable[[Event], bool]

RULES_DIR = Path(__file__).resolve().parents[2] / "sigma"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"

# The recorded events each Sigma logsource covers, as (channel, event id) pairs.
LOGSOURCES: dict[tuple[str | None, str | None], frozenset[tuple[str, int]]] = {
    ("windows", "process_creation"): frozenset({(SYSMON, 1), (SECURITY, 4688)}),
}

STAGE_FOLDER = re.compile(r"stage(\d)_")
TECHNIQUE_TAG = re.compile(r"t\d{4}(\.\d{3})?")


class UnsupportedRule(ValueError):
    """A rule uses Sigma that the replay engine cannot evaluate faithfully."""


class UnsupportedFormat(ValueError):
    """A dataset file is not in a format replay can read."""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    stage: Stage
    attack_technique: str
    severity: Severity
    sources: frozenset[tuple[str, int]]
    matches: Matcher
    path: Path


# --- rules ------------------------------------------------------------------------------------


def load_rules(root: Path = RULES_DIR) -> list[Rule]:
    """Every rule in the stage folders. Correlation rules are not per-event, so they are skipped."""
    return [load_rule(path) for path in sorted(root.glob("stage*_*/*.yml"))]


def load_rule(path: Path) -> Rule:
    rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
    stage = STAGE_FOLDER.match(path.parent.name)
    if not stage:
        raise UnsupportedRule(f"{path}: rules live in a sigma/stageN_* folder, which sets their stage")
    techniques = [t.name.upper() for t in rule.tags if t.namespace == "attack" and TECHNIQUE_TAG.fullmatch(t.name)]
    if not techniques:
        raise UnsupportedRule(f"{path}: needs an ATT&CK technique tag such as attack.t1490")
    if rule.id is None or rule.level is None:
        raise UnsupportedRule(f"{path}: needs an id and a level")
    logsource = (rule.logsource.product, rule.logsource.category)
    if rule.logsource.service or logsource not in LOGSOURCES:
        raise UnsupportedRule(f"{path}: logsource {rule.logsource} is not mapped to recorded events yet")

    conditions = [_compile(condition.parsed, path) for condition in rule.detection.parsed_condition]
    return Rule(
        id=str(rule.id),
        title=rule.title,
        stage=Stage(int(stage.group(1))),
        attack_technique=techniques[0],
        severity=Severity[rule.level.name],
        sources=LOGSOURCES[logsource],
        matches=lambda event: any(condition(event) for condition in conditions),
        path=path,
    )


def _compile(node: Any, path: Path) -> Matcher:
    """Turn pySigma's condition tree into one function per node, so each event is a tree walk."""
    if isinstance(node, (ConditionAND, ConditionOR)):
        parts = [_compile(arg, path) for arg in node.args]
        combine = all if isinstance(node, ConditionAND) else any
        return lambda event: combine(part(event) for part in parts)
    if isinstance(node, ConditionNOT):
        inner = _compile(node.args[0], path)
        return lambda event: not inner(event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        field, test = node.field, _value_test(node.value, path)
        return lambda event: test(event.get(field))
    if isinstance(node, ConditionValueExpression):
        raise UnsupportedRule(f"{path}: keyword searches have no field to match; name the field instead")
    raise UnsupportedRule(f"{path}: {type(node).__name__} conditions are not supported by replay")


def _value_test(value: Any, path: Path) -> Callable[[str | None], bool]:
    if isinstance(value, SigmaNull):
        return lambda actual: actual is None or actual == ""
    if isinstance(value, SigmaString):
        # Sigma strings match case-insensitively unless the rule used the |cased modifier.
        flags = re.DOTALL if isinstance(value, SigmaCasedString) else re.DOTALL | re.IGNORECASE
        pattern = re.compile(str(value.to_regex().regexp), flags)
        return lambda actual: actual is not None and pattern.fullmatch(actual) is not None
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        for flag in value.flags:
            flags |= SigmaRegularExpression.sigma_to_python_flags[flag]
        pattern = re.compile(str(value.regexp), flags)
        return lambda actual: actual is not None and pattern.search(actual) is not None
    if isinstance(value, SigmaNumber):
        return lambda actual: actual is not None and _as_number(actual) == value.number
    raise UnsupportedRule(f"{path}: {type(value).__name__} values are not supported by replay")


# --- events -----------------------------------------------------------------------------------


BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),  # PowerShell 5.1's > and Out-File
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def load_events(path: Path) -> Iterator[Event]:
    """Read one dataset file as flat events: System fields plus EventData fields.

    Accepts Windows event XML (attack_data, wevtutil, python-evtx), JSON Lines or a JSON array
    from `evtx_dump`, or already-flat JSON events; in UTF-8, or in UTF-16 with a byte-order mark
    as PowerShell 5.1 writes. XML and JSON Lines are read a record at a time, so a large export
    does not have to fit in memory.
    """
    with path.open("rb") as raw:
        head = raw.read(4)
    encoding = next((name for mark, name in BYTE_ORDER_MARKS if head.startswith(mark)), "utf-8")
    with path.open(encoding=encoding, errors="replace") as text:
        lines = enumerate(text, 1)
        first = next(((number, line) for number, line in lines if line.strip()), None)
        if first is None:
            return  # an empty file holds no events
        rest = itertools.chain([first], lines)
        start = first[1].lstrip()[0]
        if start == "<":
            yield from _xml_events((line for _, line in rest), path)
        elif start == "{":
            yield from _json_lines(rest, path)
        elif start == "[":
            yield from _json_array("".join(line for _, line in rest), path)
        else:
            raise UnsupportedFormat(
                f"{path}: not Windows event XML, JSON Lines or a JSON array (it starts {first[1].strip()[:40]!r});"
                " from evtx_dump, use -o jsonl")


# Only <Event> elements are parsed, so a DOCTYPE or entity declaration in the file never is.
# The [\s>] after the name skips the <Events> wrapper and the <EventID> and <EventData> children.
EVENT_XML = re.compile(r"<Event[\s>].*?</Event>", re.DOTALL)


def _xml_events(lines: Iterable[str], path: Path) -> Iterator[Event]:
    buffer = ""
    for line in lines:
        buffer += line
        if "</Event>" not in line:
            continue
        end = 0
        for match in EVENT_XML.finditer(buffer):
            yield _xml_event(match.group(), path)
            end = match.end()
        buffer = buffer[end:]


def _xml_event(record: str, path: Path) -> Event:
    try:
        root = ET.fromstring(record)
    except ET.ParseError as error:
        raise UnsupportedFormat(f"{path}: malformed event XML ({error}): {record[:80]!r}") from None
    event: Event = {}
    for section in root:
        name = _local(section.tag)
        if name == "System":
            for item in section:
                tag = _local(item.tag)
                if tag == "TimeCreated":
                    event["TimeCreated"] = item.get("SystemTime", "")
                elif tag == "Provider":
                    event["Provider_Name"] = item.get("Name", "")
                elif tag in ("EventID", "Channel", "Computer"):
                    event[tag] = (item.text or "").strip()
        elif name == "EventData":
            for data in section:
                if data.get("Name"):
                    event[data.get("Name")] = data.text or ""
    return event


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _json_lines(lines: Iterable[tuple[int, str]], path: Path) -> Iterator[Event]:
    for number, line in lines:
        if line.strip():
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise UnsupportedFormat(f"{path}, line {number}: not valid JSON ({error.msg})") from None
            yield _json_event(record, f"{path}, line {number}")


def _json_array(text: str, path: Path) -> Iterator[Event]:
    try:
        records = json.loads(text)
    except json.JSONDecodeError as error:
        raise UnsupportedFormat(f"{path}: not a valid JSON array ({error.msg}, line {error.lineno})") from None
    for index, record in enumerate(records):
        yield _json_event(record, f"{path}, item {index}")


def _json_event(record: Any, where: str) -> Event:
    if not isinstance(record, dict):
        raise UnsupportedFormat(f"{where}: expected a JSON object per event, got {type(record).__name__}")
    wrapped = record.get("Event")
    if not isinstance(wrapped, dict):  # already flat
        return {key: _text(value) for key, value in record.items() if value is not None}
    system = wrapped.get("System") or {}
    event = {key: _text(value) for key, value in (wrapped.get("EventData") or {}).items() if value is not None}
    event["EventID"] = _text(system.get("EventID"))
    event["Channel"] = _text(system.get("Channel"))
    event["Computer"] = _text(system.get("Computer"))
    event["TimeCreated"] = _text(((system.get("TimeCreated") or {}).get("#attributes") or {}).get("SystemTime"))
    event["Provider_Name"] = _text(((system.get("Provider") or {}).get("#attributes") or {}).get("Name"))
    return event


def _text(value: Any) -> str:
    if isinstance(value, dict):  # evtx_dump writes attributed values as {"#attributes": ..., "#text": ...}
        value = value.get("#text")
    return "" if value is None else str(value)


def normalise(event: Event) -> Event:
    """Give Security 4688 the Sysmon field names that process_creation rules are written against."""
    if event.get("Channel") != SECURITY or event.get("EventID") != "4688":
        return event
    event = dict(event)
    event.setdefault("Image", event.get("NewProcessName", ""))
    event.setdefault("ParentImage", event.get("ParentProcessName", ""))
    # The new process runs as the target account when there is one, otherwise as its creator.
    user = _account(event, "Target") or _account(event, "Subject")
    if user:
        event.setdefault("User", user)
    return event


def _account(event: Event, prefix: str) -> str | None:
    name, domain = event.get(f"{prefix}UserName", "-"), event.get(f"{prefix}DomainName", "-")
    if name in ("", "-"):
        return None
    return f"{domain}\\{name}" if domain not in ("", "-") else name


FRACTION = re.compile(r"(\.\d{6})\d+")


def event_time(event: Event) -> datetime:
    """When the event happened, in UTC. Windows records both TimeCreated and Sysmon's UtcTime in UTC."""
    raw = event.get("TimeCreated") or event.get("UtcTime")
    if not raw:
        raise ValueError(f"event {event.get('EventID', '?')} on {event.get('Computer', '?')} has no timestamp")
    stamp = datetime.fromisoformat(FRACTION.sub(r"\1", raw.strip().replace(" ", "T")).replace("Z", "+00:00"))
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


def _as_number(text: str) -> int | float | None:
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return None


# --- replay -----------------------------------------------------------------------------------


def replay(events: Iterable[Event], rules: Iterable[Rule]) -> list[Signal]:
    """Run every rule over every event it covers. Signals come back in time order."""
    rules = list(rules)
    signals = []
    for event in map(normalise, events):
        source = (event.get("Channel", ""), _as_number(event.get("EventID", "")))
        for rule in rules:
            if source in rule.sources and rule.matches(event):
                user = event.get("User", "")
                signals.append(Signal(
                    stage=rule.stage,
                    host=event.get("Computer", ""),
                    user=None if user in ("", "-") else user,
                    timestamp=event_time(event),
                    rule_id=rule.id,
                    attack_technique=rule.attack_technique,
                    severity=rule.severity,
                ))
    return sorted(signals, key=lambda signal: signal.timestamp)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dwellwatch.replay",
        description="Replay recorded Windows events through DwellWatch's Sigma rules and list what fires.",
    )
    parser.add_argument("datasets", nargs="+", type=Path, help="Windows event XML, JSON Lines or JSON files")
    parser.add_argument("--rules", type=Path, default=RULES_DIR, help="folder holding the stageN_* rule folders")
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError, SigmaError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    titles = {rule.id: rule.title for rule in rules}
    status = 0
    for path in args.datasets:
        seen = itertools.count(1)  # zip draws one number per event, so next(seen) - 1 is the count
        try:
            signals = replay((event for event, _ in zip(load_events(path), seen, strict=False)), rules)
        except (OSError, ValueError) as error:  # unreadable, unsupported or malformed: say so, go on
            print(f"error: {error}", file=sys.stderr)
            status = 2
            continue
        print(f"{path}: {len(signals)} signal(s) from {next(seen) - 1} event(s)")
        for s in signals:
            when = s.timestamp.astimezone(UTC)
            print(f"  {when:%Y-%m-%d %H:%M:%S}Z  stage {s.stage.value}  {s.attack_technique}"
                  f"  {s.severity.name.lower()}  {s.host}  {s.user or '-'}  {titles[s.rule_id]}")
    return status


if __name__ == "__main__":
    sys.exit(main())
