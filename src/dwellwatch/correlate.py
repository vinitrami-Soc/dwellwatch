"""Correlate signals into incidents: two or more stages on one host or one account in 24 hours.

One rule firing is a weak signal: a service-desk reset, a `net user /domain`, even a shadow-copy
deletion can each be an administrator's work. The same account or host showing two different
stages of the chain within a day is how a help-desk-led intrusion looks, so that is an incident.

    python -m dwellwatch.correlate path/to/*.log   # replay the files through the rules, then correlate

How it decides, in order:

1. Signals are grouped by host and, separately, by account. Hosts are compared by their short
   name in lower case (WIN-DC.corp.local is win-dc). Service identities (SYSTEM, LOCAL SERVICE,
   NETWORK SERVICE, anonymous logons, machine accounts ending in $) never link signals: every
   Windows host has them, so they would tie unrelated activity together.
2. Within an entity, an incident needs two signals of different stages no more than 24 hours
   apart (a rolling window). It then carries every signal chained to them by gaps of 24 hours
   or less, so the earlier weak signals are part of the story.
3. Severity: two stages are high; three or more, or two within an hour of each other, are
   critical; so is any incident that includes credential theft (stage 3) or backup destruction
   (stage 5), which are high-confidence on their own once anything else points at the same
   entity. An incident is never less severe than its most severe signal.
4. A host incident whose signals all belong to a larger account incident is not reported twice.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, timedelta
from pathlib import Path

from sigma.exceptions import SigmaError

from .models import Incident, Severity, Signal, Stage
from .replay import RULES_DIR, load_events, load_rules, replay

WINDOW = timedelta(hours=24)  # two stages this close are an incident
CLOSE = timedelta(hours=1)  # two stages this close are critical
CRITICAL_STAGES = frozenset({Stage.CREDENTIAL_THEFT, Stage.BACKUP_DESTRUCTION})

STAGE_NAMES = {
    Stage.HELPDESK_RESET: "help-desk reset",
    Stage.REMOTE_DISCOVERY: "remote tooling and discovery",
    Stage.CREDENTIAL_THEFT: "credential theft",
    Stage.LATERAL_MOVEMENT: "lateral movement",
    Stage.BACKUP_DESTRUCTION: "backup destruction",
    Stage.ENCRYPTION: "encryption",
}
SERVICE_ACCOUNTS = frozenset({"system", "local service", "network service", "anonymous logon", "-"})


def correlate(signals: Iterable[Signal], window: timedelta = WINDOW) -> list[Incident]:
    """The incidents in `signals`, in time order."""
    ordered = sorted(signals, key=_order)
    candidates: list[tuple[str, str, tuple[Signal, ...]]] = []
    for kind, key in (("user", _user_key), ("host", _host_key)):
        by_entity: dict[str, list[Signal]] = defaultdict(list)
        for signal in ordered:
            entity = key(signal)
            if entity:
                by_entity[entity].append(signal)
        for entity, entity_signals in sorted(by_entity.items()):
            for chain in _chains(entity_signals, window):
                if _closest_pair(chain) <= window:
                    candidates.append((kind, entity, tuple(chain)))

    # Largest first, accounts before hosts on a tie, so a host incident inside an account one goes.
    candidates.sort(key=lambda c: (-len(c[2]), c[0] != "user", c[1], _order(c[2][0])))
    kept: list[tuple[str, str, tuple[Signal, ...]]] = []
    for kind, entity, chain in candidates:
        if not any(set(chain) <= set(other) for _, _, other in kept):
            kept.append((kind, entity, chain))

    incidents = []
    for kind, entity, chain in kept:
        severity, reason = _assess(kind, entity, chain)
        incidents.append(Incident(kind, entity, chain, severity, reason))  # type: ignore[arg-type]
    return sorted(incidents, key=lambda i: (i.first_seen, i.entity_kind, i.entity))


def _order(signal: Signal) -> tuple:
    return (signal.timestamp, signal.stage, signal.host, signal.user or "", signal.rule_id)


def _user_key(signal: Signal) -> str | None:
    if not signal.user:
        return None
    user = signal.user.strip().lower()
    account = user.rsplit("\\", 1)[-1]
    if account in SERVICE_ACCOUNTS or account.endswith("$") or user.startswith("nt authority\\"):
        return None
    return user


def _host_key(signal: Signal) -> str | None:
    host = signal.host.strip().lower().rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return host.split(".", 1)[0]


def _chains(signals: list[Signal], window: timedelta) -> Iterable[list[Signal]]:
    """Runs of signals (already in time order) where each follows the last within `window`."""
    chain: list[Signal] = []
    for signal in signals:
        if chain and signal.timestamp - chain[-1].timestamp > window:
            yield chain
            chain = []
        chain.append(signal)
    if chain:
        yield chain


def _closest_pair(chain: list[Signal]) -> timedelta:
    """The shortest time between two signals of different stages (a very long time if none)."""
    closest = timedelta.max
    latest: dict[Stage, Signal] = {}
    for signal in chain:
        for stage, other in latest.items():
            if stage is not signal.stage:
                closest = min(closest, signal.timestamp - other.timestamp)
        latest[signal.stage] = signal
    return closest


def _assess(kind: str, entity: str, chain: tuple[Signal, ...]) -> tuple[Severity, str]:
    stages = sorted({s.stage for s in chain})
    named = [f"{int(stage)} ({STAGE_NAMES[stage]})" for stage in stages]
    listed = named[0] if len(named) == 1 else ", ".join(named[:-1]) + " and " + named[-1]
    span = _duration(chain[-1].timestamp - chain[0].timestamp)
    reason = f"Stages {listed} on {'account' if kind == 'user' else 'host'} {entity} within {span}"

    if CRITICAL_STAGES.intersection(stages):
        severity = Severity.CRITICAL
        why = " or ".join(STAGE_NAMES[s] for s in sorted(CRITICAL_STAGES.intersection(stages)))
        reason += f"; critical because it includes {why}"
    elif len(stages) >= 3:
        severity, reason = Severity.CRITICAL, reason + "; critical because it spans three or more stages"
    elif _closest_pair(list(chain)) <= CLOSE:
        severity, reason = Severity.CRITICAL, reason + "; critical because two stages came within an hour"
    else:
        severity, reason = Severity.HIGH, reason + "; high: two stages in a day"
    worst = max(s.severity for s in chain)
    if worst > severity:
        severity, reason = worst, reason + f", raised to {worst.name.lower()} by a {worst.name.lower()} signal"
    return severity, reason + "."


def _duration(delta: timedelta) -> str:
    minutes = round(delta.total_seconds() / 60)
    hours, minutes = divmod(minutes, 60)
    if not hours:
        return f"{minutes}m"
    return f"{hours}h" if not minutes else f"{hours}h{minutes:02}m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dwellwatch.correlate",
        description="Replay Windows event files through DwellWatch's rules, then correlate the signals.",
    )
    parser.add_argument("datasets", nargs="+", type=Path, help="Windows event XML, JSON Lines or JSON files, "
                                                                   "read as one timeline")
    parser.add_argument("--rules", type=Path, default=RULES_DIR, help="folder holding the stageN_* rule folders")
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
        signals = [s for path in args.datasets for s in replay(load_events(path), rules)]
    except (OSError, ValueError, SigmaError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    incidents = correlate(signals)
    print(f"{len(signals)} signal(s), {len(incidents)} incident(s)")
    for incident in incidents:
        first, last = (t.astimezone(UTC) for t in (incident.first_seen, incident.last_seen))
        print(f"\n{incident.severity.name}  {incident.entity_kind} {incident.entity}  "
              f"{first:%Y-%m-%d %H:%M}Z to {last:%Y-%m-%d %H:%M}Z  {len(incident.signals)} signal(s)")
        print(f"  {incident.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
