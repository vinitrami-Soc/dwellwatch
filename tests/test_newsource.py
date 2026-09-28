"""The new-source counter: an account reaching 2 hosts within an hour from a source it has not used."""

from datetime import UTC, datetime, timedelta

import pytest
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule, SigmaCorrelationType

from dwellwatch.correlate import correlate, detect, main
from dwellwatch.models import Severity, Signal, Stage
from dwellwatch.newsource import (
    HOSTS,
    LEARNING,
    MEMORY,
    NEW_SOURCE_RULE_ID,
    WINDOW,
    NewSources,
    new_sources,
    remote_logon,
)
from dwellwatch.replay import _compile, load_events, load_rules

from conftest import ROOT, dataset, security_event

T0 = datetime(2025, 4, 1, 9, 0, tzinfo=UTC)
ATTACK = T0 + LEARNING + timedelta(days=1)  # after the counter has learned
MINUTE = timedelta(minutes=1)
USUAL, NEW = "10.0.0.21", "10.0.0.99"


def logon(at, host="FS01.lab.local", source=USUAL, user="jdoe", domain="LAB", logon_type=3):
    return security_event(4624, host=host, time=at.isoformat(), LogonType=str(logon_type), IpAddress=source,
                          TargetUserName=user, TargetDomainName=domain)


def usual_days(user="jdoe", days=LEARNING.days + 1):
    """A person's ordinary logons: their workstation reaching the file server and DC every morning."""
    return [logon(T0 + timedelta(days=d, minutes=m), host=host, user=user)
            for d in range(days) for m, host in enumerate(["FS01.lab.local", "DC01.lab.local"])]


def spread(source=NEW, start=ATTACK, hosts=("WS02.lab.local", "SRV01.lab.local"), every=MINUTE, **kwargs):
    return [logon(start + i * every, host=host, source=source, **kwargs) for i, host in enumerate(hosts)]


def test_a_new_source_reaching_two_hosts_within_an_hour_is_one_stage_4_signal():
    [signal] = new_sources(usual_days() + spread())
    assert (signal.stage, signal.attack_technique, signal.severity) == \
        (Stage.LATERAL_MOVEMENT, "T1021", Severity.MEDIUM)
    assert (signal.host, signal.user, signal.rule_id) == ("SRV01.lab.local", "LAB\\jdoe", NEW_SOURCE_RULE_ID)
    assert signal.timestamp == ATTACK + MINUTE  # the logon that reaches the second host


def test_remote_desktop_counts_as_well_as_network_logons():
    events = usual_days() + [logon(ATTACK, host="WS02", source=NEW, logon_type=10),
                             logon(ATTACK + MINUTE, host="SRV01", source=NEW, logon_type=3)]
    assert len(new_sources(events)) == 1


# Interactive, batch, service, unlock, new credentials, cached interactive.
@pytest.mark.parametrize("logon_type", [2, 4, 5, 7, 9, 11])
def test_other_logon_types_do_not_count(logon_type):
    assert new_sources(usual_days() + spread(logon_type=logon_type)) == []


def test_the_usual_source_reaching_many_hosts_is_not_new():
    assert new_sources(usual_days() + spread(source=USUAL, hosts=[f"SRV{i:02}" for i in range(10)])) == []


def test_a_new_source_reaching_one_host_is_not_a_spread():
    assert new_sources(usual_days() + spread(hosts=["WS02"])) == []
    # The same host under two spellings is still one host.
    assert new_sources(usual_days() + spread(hosts=["WS02", "ws02.LAB.local"])) == []


def test_the_second_host_must_come_within_the_hour_of_the_first_logon():
    assert len(new_sources(usual_days() + spread(every=WINDOW))) == 1  # the hour includes its end
    assert new_sources(usual_days() + spread(every=WINDOW + MINUTE)) == []


def test_after_its_hour_a_new_source_is_known():
    events = usual_days() + spread(hosts=["WS02"]) + spread(start=ATTACK + 2 * WINDOW)
    assert new_sources(events) == []


def test_a_source_unused_for_longer_than_the_memory_is_new_again():
    used = T0 + timedelta(days=2)
    old = spread(source=NEW, start=used, hosts=["WS02"])  # used once, during learning
    assert new_sources(usual_days() + old + spread(start=used + MEMORY + timedelta(days=1))) != []
    assert new_sources(usual_days() + old + spread(start=used + MEMORY - timedelta(days=1))) == []


def test_nothing_is_judged_while_the_counter_is_still_learning():
    early = T0 + LEARNING - timedelta(hours=1)
    assert new_sources(usual_days() + spread(start=early)) == []


def test_a_baseline_teaches_but_never_alerts():
    # The baseline holds a spread of its own; only the data after it is judged.
    baseline = usual_days() + spread(start=T0 + LEARNING)
    attack = spread(source="10.0.0.77", start=ATTACK + timedelta(days=1))
    assert new_sources(attack, baseline=baseline)[0].timestamp == ATTACK + timedelta(days=1) + MINUTE
    assert new_sources([], baseline=baseline) == []
    # Without the baseline, the attack is the start of history: nothing is new yet.
    assert new_sources(attack) == []


def test_a_source_first_seen_in_the_baseline_is_known_even_minutes_later():
    baseline = usual_days() + [logon(ATTACK - 5 * MINUTE, host="WS02", source=NEW)]
    assert new_sources(spread(hosts=["SRV01", "SRV02"]), baseline=baseline) == []


def test_baseline_logons_never_count_towards_a_spread_even_when_they_overlap_the_data():
    baseline = usual_days() + [logon(ATTACK + MINUTE, host="SRV01", source=NEW)]
    assert new_sources(spread(hosts=["WS02"]), baseline=baseline) == []


def test_one_signal_per_source_however_far_it_spreads_and_one_per_new_source():
    events = usual_days() + spread(hosts=[f"SRV{i:02}" for i in range(10)])
    events += spread(source="10.0.0.77", start=ATTACK + timedelta(minutes=30))
    assert len(new_sources(events)) == 2


def test_each_account_has_its_own_sources():
    # asmith works from 10.0.0.50 every day; jdoe arriving from there is still new for jdoe.
    asmith = [logon(T0 + timedelta(days=d), source="10.0.0.50", user="asmith") for d in range(LEARNING.days + 1)]
    [signal] = new_sources(usual_days() + asmith + spread(source="10.0.0.50"))
    assert signal.user == "LAB\\jdoe"


def test_one_account_is_one_account_whatever_its_domain_is_spelled():
    baseline = usual_days()
    later = spread(source=USUAL, domain="lab.local")  # LAB\jdoe and lab.local\jdoe
    assert new_sources(baseline + later) == []


def test_a_local_account_is_not_the_domain_account_of_the_same_name():
    # One source, the domain's Administrator on DC01, then WS02's own Administrator on WS02: two accounts
    # reaching one host each, as in the pinned RDP recording.
    events = usual_days("administrator") + [
        logon(ATTACK, host="DC01.lab.local", source=NEW, user="Administrator"),
        logon(ATTACK + MINUTE, host="WS02.lab.local", source=NEW, user="Administrator", domain="WS02"),
    ]
    assert new_sources(events) == []
    events[-1] = logon(ATTACK + MINUTE, host="WS02.lab.local", source=NEW, user="Administrator")
    assert len(new_sources(events)) == 1


@pytest.mark.parametrize("user, domain", [("WS07$", "LAB"), ("ANONYMOUS LOGON", "NT AUTHORITY"),
                                          ("SYSTEM", "NT AUTHORITY"), ("IUSR", "NT AUTHORITY"), ("-", "-")])
def test_machine_accounts_and_service_identities_are_left_out(user, domain):
    assert new_sources(usual_days() + spread(user=user, domain=domain)) == []


@pytest.mark.parametrize("source", ["127.0.0.1", "::1", "-", "", "0.0.0.0"])
def test_logons_from_the_machine_itself_are_not_remote(source):
    assert remote_logon(logon(ATTACK, source=source)) is None


def test_arrival_order_does_not_matter():
    events = usual_days() + spread()
    assert new_sources(list(reversed(events))) == new_sources(events)


def test_watching_passes_events_through_untouched():
    events = usual_days() + spread()
    counter = NewSources()
    assert list(counter.watch(iter(events))) == events
    assert len(counter.signals()) == 1


def test_the_settings_can_be_changed_for_tuning():
    assert len(new_sources(usual_days() + spread(hosts=["WS02"]), hosts=1)) == 1
    assert new_sources(usual_days() + spread(hosts=["A", "B"]), hosts=3) == []
    assert len(new_sources(spread(start=T0), learning=timedelta(0))) == 1
    with pytest.raises(ValueError):
        NewSources(hosts=0)


def test_a_spread_joins_the_credential_theft_before_it_in_one_incident():
    theft = Signal(stage=Stage.CREDENTIAL_THEFT, host="WS01", user="LAB\\jdoe",
                   timestamp=ATTACK - timedelta(hours=3), rule_id="rule-3", attack_technique="T1003.001",
                   severity=Severity.HIGH)
    [incident] = correlate([theft, *new_sources(usual_days() + spread())])
    assert (incident.entity_kind, incident.entity) == ("user", "lab\\jdoe")
    assert incident.stages == (Stage.CREDENTIAL_THEFT, Stage.LATERAL_MOVEMENT)


# --- recordings -------------------------------------------------------------------------------

RDP = "T1021.001/rdp_session_established/4624_10_logon.log"


def test_the_rdp_recording_learns_and_raises_nothing():
    # 16 remote desktop logons over five days: shorter than the learning period.
    assert new_sources(load_events(dataset(RDP))) == []


def test_the_rdp_recording_does_not_spread_even_judged_from_the_start():
    # Judged with no learning at all, every source is new, but each reaches one host only: 10.0.1.12
    # reaches ar-win-dc as the domain Administrator and ar-win-dc-2 as that host's local Administrator.
    assert new_sources(load_events(dataset(RDP)), learning=timedelta(0)) == []
    assert len(new_sources(load_events(dataset(RDP)), learning=timedelta(0), hosts=1)) == 3


# --- the command line -------------------------------------------------------------------------


def test_detect_and_the_command_line_take_a_baseline(tmp_path, capsys):
    import json
    baseline, attack = tmp_path / "baseline.jsonl", tmp_path / "attack.jsonl"
    baseline.write_text("".join(json.dumps(e) + "\n" for e in usual_days()))
    attack.write_text("".join(json.dumps(e) + "\n" for e in spread()))
    rules = load_rules()
    assert [s.rule_id for s in detect([attack], rules, [baseline])] == [NEW_SOURCE_RULE_ID]
    assert detect([attack], rules) == []
    assert main([str(attack), "--baseline", str(baseline)]) == 0
    assert capsys.readouterr().out.startswith("1 signal(s), 0 incident(s)")


# --- the same logic in Sigma's correlation syntax -------------------------------------------

FANOUT = ROOT / "sigma" / "correlation" / "new_source_fanout_1h.yml"


def fanout_rules():
    collection = SigmaCollection.from_yaml(FANOUT.read_text(encoding="utf-8"))
    collection.resolve_rule_references()
    return collection


def test_the_sigma_rule_states_the_same_window_and_host_count():
    [rule] = [r for r in fanout_rules().rules if isinstance(r, SigmaCorrelationRule)]
    assert rule.type is SigmaCorrelationType.VALUE_COUNT
    assert tuple(rule.group_by) == ("TargetUserName", "IpAddress")
    assert rule.timespan.seconds == WINDOW.total_seconds()
    assert (rule.condition.fieldref, rule.condition.op, rule.condition.count) == \
        ("Computer", SigmaCorrelationConditionOperator.GTE, HOSTS)


@pytest.mark.parametrize("fields", [
    {"LogonType": "3"}, {"LogonType": "10"}, {"LogonType": "2"}, {"LogonType": "9"},
    {"IpAddress": "127.0.0.1"}, {"IpAddress": "127.0.1.1"}, {"IpAddress": "::1"}, {"IpAddress": "-"},
    {"IpAddress": ""}, {"IpAddress": "0.0.0.0"}, {"IpAddress": "fe80::1"},
    {"TargetUserName": "WS07$"}, {"TargetUserName": "ANONYMOUS LOGON", "TargetDomainName": "NT AUTHORITY"},
    {"TargetUserName": "IUSR", "TargetDomainName": "NT AUTHORITY"}, {"TargetUserName": "SYSTEM"},
    {"TargetUserName": "-", "TargetDomainName": "-"}, {"TargetUserName": "svc-backup"},
])
def test_the_sigma_base_rule_counts_the_same_logons_as_the_counter(fields):
    [base] = [r for r in fanout_rules().rules if getattr(r, "name", None) == "dwellwatch_remote_logon"]
    [condition] = base.detection.parsed_condition
    matches = _compile(condition.parsed, FANOUT)
    event = {**logon(ATTACK, source=NEW), **fields}
    assert matches(event) is (remote_logon(event) is not None), fields


def test_the_sigma_rules_convert_for_splunk():
    [query] = [q for q in SplunkBackend().convert(fanout_rules()) if "value_count" in q]
    assert "EventID=4624" in query and "| bin _time span=1h" in query
    assert "dc(Computer) as value_count by _time TargetUserName IpAddress" in query
    assert "| search value_count >= 2" in query
