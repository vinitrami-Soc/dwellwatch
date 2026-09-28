from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from dwellwatch.models import Incident, Severity, Signal, Stage

T0 = datetime(2025, 4, 24, 9, 0, tzinfo=UTC)


def signal(stage=Stage.BACKUP_DESTRUCTION, at=T0, **overrides):
    fields = dict(stage=stage, host="WS01", user="lab\\jdoe", timestamp=at,
                  rule_id="00000000-0000-4000-8000-000000000000", attack_technique="T1490",
                  severity=Severity.HIGH)
    fields.update(overrides)
    return Signal(**fields)


def test_signal_keeps_its_fields():
    s = signal()
    assert s.stage is Stage.BACKUP_DESTRUCTION
    assert s.host == "WS01"
    assert s.attack_technique == "T1490"


def test_signals_are_immutable():
    with pytest.raises(FrozenInstanceError):
        signal().host = "WS02"


def test_naive_timestamps_are_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        signal(at=datetime(2025, 4, 24, 9, 0))


def test_stages_and_severities_are_ordered():
    assert list(Stage) == sorted(Stage) and len(Stage) == 6
    assert Stage.HELPDESK_RESET < Stage.ENCRYPTION
    assert max(Severity.MEDIUM, Severity.CRITICAL, Severity.LOW) is Severity.CRITICAL
    assert Severity["HIGH"] is Severity.HIGH  # Sigma's `level`, upper-cased


def test_incident_lists_stages_in_attack_order_and_its_time_span():
    later = signal(Stage.BACKUP_DESTRUCTION, T0 + timedelta(hours=3))
    earlier = signal(Stage.HELPDESK_RESET, T0, attack_technique="T1098")
    repeat = signal(Stage.BACKUP_DESTRUCTION, T0 + timedelta(hours=4))
    incident = Incident("host", "WS01", (later, earlier, repeat), Severity.CRITICAL)
    assert incident.stages == (Stage.HELPDESK_RESET, Stage.BACKUP_DESTRUCTION)
    assert incident.first_seen == T0
    assert incident.last_seen == T0 + timedelta(hours=4)


def test_an_incident_needs_signals():
    with pytest.raises(ValueError):
        Incident("user", "lab\\jdoe", (), Severity.HIGH)
