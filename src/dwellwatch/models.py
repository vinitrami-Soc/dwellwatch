"""Data model shared by replay, correlation, the metric and the IntelPulse webhook."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum
from typing import Literal


class Stage(IntEnum):
    """The six stages of the chain, in attack order. Stages 1 to 5 happen during dwell time."""

    HELPDESK_RESET = 1       # impersonated employee gets a password or MFA reset
    REMOTE_DISCOVERY = 2     # remote access tooling installed, discovery commands run
    CREDENTIAL_THEFT = 3     # LSASS read, NTDS.dit copied, DCSync
    LATERAL_MOVEMENT = 4     # host to host with the stolen account
    BACKUP_DESTRUCTION = 5   # shadow copies, backup catalogue and recovery removed
    ENCRYPTION = 6           # impact: the backstop, not the goal


class Severity(IntEnum):
    """Sigma's `level` values, ordered so severities can be compared and maxed."""

    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


def _require_aware(timestamp: datetime) -> None:
    # Signals come from different hosts and datasets; naive times cannot be ordered safely.
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(f"timestamp must be timezone-aware, got {timestamp.isoformat()}")


@dataclass(frozen=True)
class Signal:
    """One rule firing on one event."""

    stage: Stage
    host: str
    user: str | None  # None when the event carries no account, e.g. a FIM burst
    timestamp: datetime
    rule_id: str  # the Sigma rule's UUID
    attack_technique: str  # e.g. "T1490"
    severity: Severity

    def __post_init__(self) -> None:
        _require_aware(self.timestamp)


@dataclass(frozen=True)
class Incident:
    """Two or more stages seen on the same host or user, raised by correlation."""

    entity_kind: Literal["host", "user"]
    entity: str
    signals: tuple[Signal, ...]
    severity: Severity

    def __post_init__(self) -> None:
        if not self.signals:
            raise ValueError("an incident needs at least one signal")

    @property
    def stages(self) -> tuple[Stage, ...]:
        """Distinct stages seen, in attack order."""
        return tuple(sorted({s.stage for s in self.signals}))

    @property
    def first_seen(self) -> datetime:
        return min(s.timestamp for s in self.signals)

    @property
    def last_seen(self) -> datetime:
        return max(s.timestamp for s in self.signals)
