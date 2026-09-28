"""Convert the Sigma rules into what each SIEM deploys: Wazuh rules, Splunk SPL and Sentinel KQL.

Splunk and Sentinel go through pySigma's maintained backends. Wazuh has no pySigma backend, so its
rules are generated here from the same parsed rule. A rule a target cannot express faithfully raises
UnsupportedForTarget instead of producing a query that would quietly never match.

    python -m dwellwatch.convert           # regenerate converted/
    python -m dwellwatch.convert --check   # change nothing; exit 1 if converted/ is out of date
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import yaml
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.exceptions import SigmaError
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.sentinelasim import sentinel_asim_pipeline
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaExpansion,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from .replay import RULES_DIR, STAGE_FOLDER, TECHNIQUE_TAG

CONVERTED_DIR = RULES_DIR.parent / "converted"
WAZUH_IDS = RULES_DIR / "wazuh-ids.yml"
TARGETS = ("wazuh", "splunk", "sentinel")
EXTENSIONS = {"wazuh": ".xml", "splunk": ".spl", "sentinel": ".kql"}


class ConversionError(Exception):
    """A rule could not be converted."""


class UnsupportedForTarget(ConversionError):
    """The target cannot express this rule faithfully, so no query is produced for it."""

    def __init__(self, path: Path, target: str, reason: str):
        super().__init__(f"{path}: cannot convert to {target}: {reason}")
        self.path, self.target, self.reason = path, target, reason


def convert(rule_path: Path, target: str) -> str:
    """The rule at `rule_path` as a `target` query or rule file: "wazuh", "splunk" or "sentinel"."""
    if target not in TARGETS:
        raise ValueError(f"unknown target {target!r}; choose from {', '.join(TARGETS)}")
    text = rule_path.read_text(encoding="utf-8")
    # Parse afresh for every target: pySigma's processing pipelines rewrite the parsed rule in place.
    return {"wazuh": _wazuh, "splunk": _splunk, "sentinel": _sentinel}[target](text, rule_path)


# --- Splunk -----------------------------------------------------------------------------------


def _splunk(text: str, path: Path) -> str:
    query = _backend_convert(SplunkBackend(), text, path, "splunk")
    # For a regex inside an OR, pySigma's Splunk backend emits a rex/eval chain that either starts
    # with no base search or strands part of the OR in a trailing `| search OR ...`. Neither runs
    # as written, so refuse rather than ship it. A single regex ANDed with the rest converts cleanly.
    if "| rex field=" in query:
        raise UnsupportedForTarget(path, "splunk", "a regex inside an OR, which pySigma's Splunk backend "
                                   "cannot express; fold the alternatives into one regex")
    return query + "\n"


# --- Sentinel ---------------------------------------------------------------------------------

# Security-log rules query Sentinel's SecurityEvent table, where the Windows Security Events
# connector puts them with their EventData fields as columns. pySigma's ASIM pipeline maps log
# categories (process, file, registry, network, web) to ASIM tables, and has none for this service.
SENTINEL_SECURITY_TABLE = "SecurityEvent"

# Two field mappings in pySigma-backend-kusto 1.0.1's ASIM pipeline are wrong, so DwellWatch maps
# these fields first and the ASIM pipeline then leaves them alone:
# - OriginalFileName goes to two fields, one of which (TargetProcessFilename) is not in its own
#   imProcessCreate schema, so every rule using it fails to convert.
# - Sysmon's TargetFilename, a full path, goes to TargetFileName, which in imFileEvent is the bare
#   file name; a condition on the folder would never match.
_ASIM_FIXES = ProcessingPipeline(
    name="DwellWatch fixes to the Sentinel ASIM pipeline",
    priority=5,
    items=[
        ProcessingItem(
            identifier="dwellwatch_asim_original_file_name",
            transformation=FieldMappingTransformation({"OriginalFileName": "TargetProcessFileOriginalName"}),
            rule_conditions=[LogsourceCondition(category="process_creation", product="windows")],
        ),
        ProcessingItem(
            identifier="dwellwatch_asim_target_file_path",
            transformation=FieldMappingTransformation({"TargetFilename": "TargetFilePath"}),
            rule_conditions=[LogsourceCondition(category="file_event", product="windows")],
        ),
    ],
)


# pySigma-backend-kusto quotes the numbers in a value list and compares them with in~, the
# case-insensitive string operator: EventID in~ ("4728", "4732"). SecurityEvent's EventID is an
# integer column, so write such a list as numbers and leave nothing to Kusto's type conversion.
_QUOTED_EVENT_IDS = re.compile(r'\bEventID in~ \(((?:"\d+", )*"\d+")\)')


def _sentinel(text: str, path: Path) -> str:
    if SigmaRule.from_yaml(text).logsource.service == "security":
        pipeline = azure_monitor_pipeline(query_table=SENTINEL_SECURITY_TABLE)
    else:
        pipeline = _ASIM_FIXES + sentinel_asim_pipeline()
    query = _backend_convert(KustoBackend(pipeline), text, path, "sentinel")
    query = _QUOTED_EVENT_IDS.sub(lambda match: "EventID in (" + match.group(1).replace('"', "") + ")", query)
    return f"// {_title(text)}\n// Generated from {_relative(path)} by dwellwatch.convert; do not edit.\n{query}\n"


def _backend_convert(backend: Any, text: str, path: Path, target: str) -> str:
    try:
        [query] = backend.convert(SigmaCollection.from_yaml(text))
    except SigmaError as error:  # e.g. a field or log source the target's tables do not have
        raise UnsupportedForTarget(path, target, str(error).split("\n", 1)[0]) from None
    return query


# --- Wazuh ------------------------------------------------------------------------------------

# Sigma level -> Wazuh level. Wazuh tries sibling rules from the highest level down, built-in rules
# before local ones on a tie, and stops at the first match. "high" is 13, one above Wazuh's own
# level-12 Sysmon rules (92057 matches PowerShell running an encoded command, as REvil does), so
# those cannot take an event away from a DwellWatch rule.
WAZUH_LEVELS = {"INFORMATIONAL": 3, "LOW": 6, "MEDIUM": 10, "HIGH": 13, "CRITICAL": 15}


@dataclass(frozen=True)
class WazuhSource:
    """Where one event source hangs in Wazuh's rule tree, and what Wazuh calls its fields."""

    name: str
    parent: tuple[str, ...]  # XML elements that tie a rule to this source
    field: Callable[[str], str | None]  # Sigma field -> Wazuh field, or None if the source lacks it


def _eventdata(field: str) -> str:
    # Wazuh's eventchannel decoder names EventData fields in lowerCamelCase: Image -> image.
    return f"win.eventdata.{field[:1].lower()}{field[1:]}"


def _security(field: str) -> str:
    return "win.system.eventID" if field == "EventID" else _eventdata(field)


# Parents checked against the Wazuh 4.14.8 ruleset: Sysmon event 1 is tagged sysmon_event1 by rule
# 61603 (0595-win-sysmon_rules.xml); a Security event reaches 60001 and then, if the audit
# succeeded, 60103 (0580-win-security_rules.xml), which is where Wazuh's own rules for successful
# Security events hang. Rules on audit failures (4625) would hang from 60104; none do yet.
SYSMON_1 = WazuhSource("Sysmon event 1", ("<if_group>sysmon_event1</if_group>",), _eventdata)
SECURITY_4688 = WazuhSource(
    "Security event 4688",
    ("<if_sid>60103</if_sid>", '<field name="win.system.eventID">^4688$</field>'),
    {"Image": "win.eventdata.newProcessName", "ParentImage": "win.eventdata.parentProcessName",
     "CommandLine": "win.eventdata.commandLine"}.get,
)
SECURITY = WazuhSource("Security audit success", ("<if_sid>60103</if_sid>",), _security)
# Sysmon events 10 and 11 are tagged by rules 61612 and 61613, as event 1 is by 61603.
SYSMON_10 = WazuhSource("Sysmon event 10", ("<if_group>sysmon_event_10</if_group>",), _eventdata)
SYSMON_11 = WazuhSource("Sysmon event 11", ("<if_group>sysmon_event_11</if_group>",), _eventdata)
WAZUH_SOURCES = {
    ("windows", "process_creation", None): (SYSMON_1, SECURITY_4688),
    ("windows", "process_access", None): (SYSMON_10,),
    ("windows", "file_event", None): (SYSMON_11,),
    ("windows", None, "security"): (SECURITY,),
}

Literal = tuple[str, tuple[Any, ...], bool]  # a field, the values it may take (ORed), and whether it must not
REGEX_FLAGS = {SigmaRegularExpressionFlag.IGNORECASE: "i", SigmaRegularExpressionFlag.MULTILINE: "m",
               SigmaRegularExpressionFlag.DOTALL: "s"}


def _wazuh(text: str, path: Path) -> str:
    rule = SigmaRule.from_yaml(text)
    stage = STAGE_FOLDER.match(path.parent.name)
    sources = WAZUH_SOURCES.get((rule.logsource.product, rule.logsource.category, rule.logsource.service))
    if not stage or not sources:
        raise UnsupportedForTarget(path, "wazuh", f"no Wazuh parent rule is mapped for {rule.logsource}")

    branches = [branch for condition in rule.detection.parsed_condition
                for branch in _dnf(condition.parsed, path)]
    blocks = []
    for source in sources:
        for branch in branches:
            fields = _wazuh_fields(branch, source, path)
            if fields is not None:  # this source has every field the branch needs
                blocks.append((source, fields))
    if not blocks:
        raise UnsupportedForTarget(path, "wazuh", "no event source has all the fields the rule needs")
    if len(blocks) > 10:
        raise UnsupportedForTarget(path, "wazuh", f"needs {len(blocks)} Wazuh rules, more than its ID block of 10")
    base_id = _wazuh_ids().get(str(rule.id))
    if base_id is None:
        raise ConversionError(f"{path}: rule {rule.id} has no Wazuh ID block; add one to {WAZUH_IDS.name}")

    techniques = [tag.name.upper() for tag in rule.tags
                  if tag.namespace == "attack" and TECHNIQUE_TAG.fullmatch(tag.name)]
    level = WAZUH_LEVELS[rule.level.name]
    lines = [
        f"<!-- {rule.title}",
        f"     Generated from {_relative(path)} ({rule.id}) by dwellwatch.convert; do not edit. -->",
        '<group name="dwellwatch,">',
    ]
    for offset, (source, fields) in enumerate(blocks):
        lines += [f"  <!-- {source.name} -->", f'  <rule id="{base_id + offset}" level="{level}">']
        lines += [f"    {parent}" for parent in source.parent]
        lines += [f'    <field name="{name}" type="pcre2">{escape(pattern)}</field>' for name, pattern in fields]
        lines += [
            f"    <description>DwellWatch stage {stage.group(1)}: {escape(rule.title)}</description>",
            "    <mitre>", *[f"      <id>{t}</id>" for t in techniques], "    </mitre>",
            f"    <group>dwellwatch_stage{stage.group(1)},</group>",
            "  </rule>",
        ]
    lines.append("</group>")
    return "\n".join(lines) + "\n"


def _wazuh_ids() -> dict[str, int]:
    return {str(key): int(value) for key, value in yaml.safe_load(WAZUH_IDS.read_text(encoding="utf-8")).items()}


def _dnf(node: Any, path: Path, negated: bool = False) -> list[list[Literal]]:
    """The condition as alternatives (OR) of conditions that must all hold (AND).

    A `not` is pushed down to the fields, so each literal says a field must, or must not, take one
    of its values. ORed values of one field stay a single literal, so `Image|endswith: [a, b]` is
    one pattern, as are alternatives that test the same field (TargetSid by suffix or whole SID).
    """
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return [[(node.field, (node.value,), negated)]]
    if isinstance(node, ConditionNOT):
        return _dnf(node.args[0], path, not negated)
    if isinstance(node, (ConditionAND, ConditionOR)):
        parts = [_dnf(arg, path, negated) for arg in node.args]
        if isinstance(node, ConditionAND) != negated:  # not (a or b) is (not a) and (not b)
            branches: list[list[Literal]] = [[]]
            for part in parts:
                branches = [left + right for left in branches for right in part]
            return branches
        alternatives: list[list[Literal]] = []
        by_field: dict[str, list[Literal]] = {}  # field -> the alternative that only requires it
        for branch in (branch for part in parts for branch in part):
            if len(branch) == 1 and not branch[0][2]:
                field, values, _ = branch[0]
                if field in by_field:
                    by_field[field][0] = (field, by_field[field][0][1] + values, False)
                    continue
                branch = by_field[field] = [branch[0]]
            alternatives.append(branch)
        return alternatives
    if isinstance(node, ConditionValueExpression):
        raise UnsupportedForTarget(path, "wazuh", "keyword searches have no field to match")
    raise UnsupportedForTarget(path, "wazuh", f"{type(node).__name__} conditions are not supported")


def _wazuh_fields(branch: list[Literal], source: WazuhSource, path: Path) -> list[tuple[str, str]] | None:
    """One PCRE2 pattern per Wazuh field for this branch, or None if the source lacks a field.

    A field the source never has cannot equal anything, so a condition that it must not is
    dropped as always true, as Sigma reads it.
    """
    by_field: dict[str, tuple[list[list[str]], list[str]]] = {}
    for sigma_field, values, negated in branch:
        wazuh_field = source.field(sigma_field)
        if wazuh_field is None:
            if negated:
                continue
            return None
        must, must_not = by_field.setdefault(wazuh_field, ([], []))
        patterns = [_wazuh_value(value, path) for value in values]
        if negated:
            must_not.extend(patterns)
        else:
            must.append(patterns)
    fields = []
    for wazuh_field, (must, must_not) in by_field.items():
        if len(must) == 1 and not must_not:
            body = _alternation(must[0])
        else:  # several conditions on one field: one lookahead each, negative for "must not"
            body = "".join(f"(?={_alternation(alternatives)})" for alternatives in must)
            body += f"(?!{_alternation(must_not)})" if must_not else ""
        fields.append((wazuh_field, f"(?s)^{body}"))
    return fields


def _alternation(alternatives: list[str]) -> str:
    return alternatives[0] if len(alternatives) == 1 else "(?:" + "|".join(alternatives) + ")"


def _wazuh_value(value: Any, path: Path) -> str:
    """A pattern that matches `value` from the start of a Wazuh field.

    Wazuh keeps Windows event values JSON-escaped: a path's backslashes arrive doubled and a quote
    arrives as \\" (see the events in Wazuh's ruleset/testing/tests/sysmon_eid_1.ini). A literal
    backslash therefore matches one or two backslashes, and a quote an optional backslash first.
    """
    if isinstance(value, SigmaExpansion):
        return _alternation([_wazuh_value(variant, path) for variant in value.values])
    if isinstance(value, SigmaString):
        parts = list(value.s)
        prefix_only = bool(parts) and parts[-1] == SpecialChars.WILDCARD_MULTI  # startswith/contains
        if prefix_only:
            parts = parts[:-1]
        body = "".join(_wazuh_part(part) for part in parts) + ("" if prefix_only else "$")
        return f"(?-i:{body})" if isinstance(value, SigmaCasedString) else f"(?i:{body})"
    if isinstance(value, SigmaRegularExpression):
        source = str(value.regexp)
        if "\\\\" in source:
            raise UnsupportedForTarget(path, "wazuh", "a regex that matches a literal backslash, which Wazuh "
                                       "stores doubled")
        flags = "".join(REGEX_FLAGS[flag] for flag in sorted(value.flags, key=str))
        source = source.replace('"', r'(?:\\?")')  # a quote may arrive escaped
        return f"(?{flags}:.*?(?:{source}))"
    if isinstance(value, SigmaNumber):
        return f"(?:{value.number}$)"
    raise UnsupportedForTarget(path, "wazuh", f"{type(value).__name__} values are not converted yet")


def _wazuh_part(part: Any) -> str:
    if part == SpecialChars.WILDCARD_MULTI:
        return ".*"
    if part == SpecialChars.WILDCARD_SINGLE:
        return "."
    return "".join("\\\\{1,2}" if char == "\\" else '\\\\?"' if char == '"' else re.escape(char) for char in part)


# --- all rules --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Skipped:
    path: Path
    target: str
    reason: str


def render_all(rules_dir: Path = RULES_DIR) -> tuple[dict[Path, str], list[Skipped]]:
    """Every rule in every target, keyed by path under converted/, plus the conversions refused."""
    files: dict[Path, str] = {}
    skipped: list[Skipped] = []
    for path in sorted(rules_dir.glob("stage*_*/*.yml")):
        for target in TARGETS:
            try:
                files[Path(target) / (path.stem + EXTENSIONS[target])] = convert(path, target)
            except UnsupportedForTarget as error:
                skipped.append(Skipped(path, target, error.reason))
    return files, skipped


def _title(text: str) -> str:
    return str(yaml.safe_load(text).get("title", ""))


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(RULES_DIR.parent).as_posix()
    except ValueError:
        return path.name


def _generated(out: Path) -> Iterator[Path]:
    for target, extension in EXTENSIONS.items():
        yield from (path.relative_to(out) for path in (out / target).glob(f"*{extension}"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dwellwatch.convert",
        description="Write every Sigma rule as Wazuh rules, Splunk SPL and Sentinel KQL under converted/.",
    )
    parser.add_argument("--check", action="store_true", help="change nothing; exit 1 if converted/ is out of date")
    parser.add_argument("--rules", type=Path, default=RULES_DIR, help="folder holding the stageN_* rule folders")
    parser.add_argument("--out", type=Path, default=CONVERTED_DIR, help="folder to write the conversions to")
    args = parser.parse_args(argv)

    try:
        files, skipped = render_all(args.rules)
    except (ConversionError, SigmaError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for skip in skipped:
        print(f"not converted: {skip.path.name} -> {skip.target}: {skip.reason}")

    def current(path: Path) -> str | None:
        target = args.out / path
        return target.read_text(encoding="utf-8") if target.is_file() else None

    stale = sorted(set(_generated(args.out)) - files.keys())
    changed = sorted(path for path, text in files.items() if current(path) != text)
    if args.check:
        for path in changed:
            print(f"out of date: {args.out.name}/{path.as_posix()}")
        for path in stale:
            print(f"no longer generated: {args.out.name}/{path.as_posix()}")
        if changed or stale:
            print("run `python -m dwellwatch.convert` and commit the result", file=sys.stderr)
            return 1
        print(f"{args.out.name}/ is up to date: {len(files)} files")
        return 0

    for path in changed:
        (args.out / path).parent.mkdir(parents=True, exist_ok=True)
        (args.out / path).write_text(files[path], encoding="utf-8")
    for path in stale:
        (args.out / path).unlink()
    print(f"{args.out.name}/: {len(changed)} written, {len(stale)} removed, {len(files)} in total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
