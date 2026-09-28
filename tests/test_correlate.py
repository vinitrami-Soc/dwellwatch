"""Correlation: two or more stages on one host or one account inside a rolling 24-hour window.

Cases (a) to (d) are the ones the project brief names; the rest pin the window's edges, which
accounts may link signals, how hosts are named, and how severity scales.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule, SigmaCorrelationType

from dwellwatch.correlate import CLOSE, WINDOW, _user_key, correlate
from dwellwatch.models import Severity, Signal, Stage
from dwellwatch.replay import _compile, load_events, load_rules, replay

from conftest import ROOT, dataset

T0 = datetime(2025, 4, 24, 9, 0, tzinfo=UTC)
H = timedelta(hours=1)
TECHNIQUE = {Stage.HELPDESK_RESET: "T1098", Stage.REMOTE_DISCOVERY: "T1087.002",
             Stage.CREDENTIAL_THEFT: "T1003.001", Stage.LATERAL_MOVEMENT: "T1021.002",
             Stage.BACKUP_DESTRUCTION: "T1490", Stage.ENCRYPTION: "T1486"}


def signal(stage, at=T0, host="WS01.lab.local", user="LAB\\jdoe", severity=Severity.MEDIUM):
    return Signal(stage=stage, host=host, user=user, timestamp=at, rule_id=f"rule-{int(stage)}",
                  attack_technique=TECHNIQUE[stage], severity=severity)


# --- the brief's cases ------------------------------------------------------------------------


def test_a_two_stages_on_one_host_within_24_hours_is_one_critical_incident():
    reset = signal(Stage.HELPDESK_RESET, T0)
    shadow_delete = signal(Stage.BACKUP_DESTRUCTION, T0 + 5 * H, severity=Severity.HIGH)
    [incident] = correlate([reset, shadow_delete])
    assert incident.severity is Severity.CRITICAL  # backup destruction is critical on its own in context
    assert incident.stages == (Stage.HELPDESK_RESET, Stage.BACKUP_DESTRUCTION)
    assert incident.signals == (reset, shadow_delete)


def test_b_two_stages_48_hours_apart_are_not_an_incident():
    assert correlate([signal(Stage.HELPDESK_RESET, T0), signal(Stage.BACKUP_DESTRUCTION, T0 + 48 * H)]) == []


def test_c_single_stage_noise_from_many_hosts_is_not_an_incident():
    # 50 hosts each running a discovery command, the same service-desk account on all of them,
    # and the reset rule firing all day: one stage per entity, however many signals.
    noise = [signal(Stage.REMOTE_DISCOVERY, T0 + i * timedelta(minutes=7), host=f"WS{i:02}", user="LAB\\helpdesk1")
             for i in range(50)]
    noise += [signal(Stage.HELPDESK_RESET, T0 + i * H, host="DC01", user=f"LAB\\user{i}") for i in range(20)]
    assert correlate(noise) == []


def test_d_the_full_chain_on_one_host_is_one_incident_listing_every_stage_in_order():
    chain = [signal(stage, T0 + i * 3 * H) for i, stage in enumerate(Stage)]
    [incident] = correlate(list(reversed(chain)))  # arrival order does not matter
    assert incident.stages == tuple(Stage)
    assert incident.signals == tuple(chain)
    assert incident.severity is Severity.CRITICAL


# --- why a lone alert is not an incident and a pair is --------------------------------------


def test_a_lone_vssadmin_alert_is_not_an_incident_but_a_reset_plus_vssadmin_is():
    vssadmin = signal(Stage.BACKUP_DESTRUCTION, T0 + 2 * H, severity=Severity.HIGH)
    assert correlate([vssadmin]) == []
    assert correlate([vssadmin, signal(Stage.BACKUP_DESTRUCTION, T0 + 3 * H)]) == []  # still one stage
    [incident] = correlate([signal(Stage.HELPDESK_RESET, T0), vssadmin])
    assert "help-desk reset" in incident.reason and "backup destruction" in incident.reason
    assert "within 2h" in incident.reason


# --- the rolling window -----------------------------------------------------------------------


@pytest.mark.parametrize("gap, incident", [
    (WINDOW - timedelta(seconds=1), True),
    (WINDOW, True),  # inclusive
    (WINDOW + timedelta(seconds=1), False),
])
def test_the_window_is_24_hours_inclusive(gap, incident):
    found = correlate([signal(Stage.HELPDESK_RESET, T0), signal(Stage.REMOTE_DISCOVERY, T0 + gap)])
    assert bool(found) is incident


def test_the_window_rolls_rather_than_starting_at_the_first_signal():
    # Discovery on day 1 and again on day 2, then credential theft on day 3: the theft is within
    # 24 hours of the second discovery, so it is an incident, and the day-1 signal is part of it.
    day1 = signal(Stage.REMOTE_DISCOVERY, T0)
    day2 = signal(Stage.REMOTE_DISCOVERY, T0 + 20 * H)
    day3 = signal(Stage.CREDENTIAL_THEFT, T0 + 40 * H)
    [incident] = correlate([day1, day2, day3])
    assert incident.signals == (day1, day2, day3) and incident.first_seen == T0


def test_signals_after_a_quiet_day_start_a_new_incident():
    first = [signal(Stage.HELPDESK_RESET, T0), signal(Stage.REMOTE_DISCOVERY, T0 + H)]
    second = [signal(Stage.CREDENTIAL_THEFT, T0 + 60 * H), signal(Stage.BACKUP_DESTRUCTION, T0 + 61 * H)]
    incidents = correlate(first + second)
    assert [i.stages for i in incidents] == [(Stage.HELPDESK_RESET, Stage.REMOTE_DISCOVERY),
                                             (Stage.CREDENTIAL_THEFT, Stage.BACKUP_DESTRUCTION)]


# --- which entities link signals ------------------------------------------------------------


def test_the_same_account_on_two_hosts_is_a_user_incident():
    # The reset is logged on the domain controller; the account then runs discovery on a workstation.
    reset = signal(Stage.HELPDESK_RESET, T0, host="DC01.lab.local")
    discovery = signal(Stage.REMOTE_DISCOVERY, T0 + 2 * H, host="WS07.lab.local", user="lab\\JDOE")
    [incident] = correlate([reset, discovery])
    assert (incident.entity_kind, incident.entity) == ("user", "lab\\jdoe")


@pytest.mark.parametrize("account", ["NT AUTHORITY\\SYSTEM", "SYSTEM", "NT AUTHORITY\\NETWORK SERVICE",
                                     "NT AUTHORITY\\LOCAL SERVICE", "ANONYMOUS LOGON", "LAB\\WS01$", "-"])
def test_service_identities_do_not_link_signals_across_hosts(account):
    signals = [signal(Stage.REMOTE_DISCOVERY, T0, host="WS01", user=account),
               signal(Stage.BACKUP_DESTRUCTION, T0 + H, host="FS02", user=account)]
    assert correlate(signals) == []


def test_a_host_is_the_same_host_whatever_its_name_is_spelled():
    signals = [signal(Stage.CREDENTIAL_THEFT, T0, host="WIN-DC-770.attackrange.local", user=None),
               signal(Stage.BACKUP_DESTRUCTION, T0 + H, host="win-dc-770", user="NT AUTHORITY\\SYSTEM")]
    [incident] = correlate(signals)
    assert (incident.entity_kind, incident.entity) == ("host", "win-dc-770")


def test_ip_addresses_are_not_cut_at_the_first_dot():
    signals = [signal(Stage.CREDENTIAL_THEFT, T0, host="10.0.1.12", user=None),
               signal(Stage.BACKUP_DESTRUCTION, T0 + H, host="10.0.1.14", user=None)]
    assert correlate(signals) == []


def test_a_host_incident_inside_a_larger_user_incident_is_not_reported_twice():
    on_ws01 = [signal(Stage.REMOTE_DISCOVERY, T0), signal(Stage.CREDENTIAL_THEFT, T0 + H)]
    on_fs02 = [signal(Stage.BACKUP_DESTRUCTION, T0 + 2 * H, host="FS02")]
    [incident] = correlate(on_ws01 + on_fs02)
    assert incident.entity_kind == "user" and len(incident.signals) == 3


def test_overlapping_but_different_stories_are_both_reported():
    # jdoe works on WS01; SYSTEM (not linkable by account) deletes backups on WS01 too.
    jdoe = [signal(Stage.REMOTE_DISCOVERY, T0), signal(Stage.LATERAL_MOVEMENT, T0 + 5 * H, host="FS02")]
    system = signal(Stage.BACKUP_DESTRUCTION, T0 + 6 * H, user="NT AUTHORITY\\SYSTEM")
    incidents = correlate(jdoe + [system])
    assert sorted((i.entity_kind, i.stages) for i in incidents) == [
        ("host", (Stage.REMOTE_DISCOVERY, Stage.BACKUP_DESTRUCTION)),
        ("user", (Stage.REMOTE_DISCOVERY, Stage.LATERAL_MOVEMENT)),
    ]


# --- severity scales with how many stages and how close together -----------------------------


@pytest.mark.parametrize("stages_and_gaps, severity", [
    ([(Stage.HELPDESK_RESET, 0), (Stage.REMOTE_DISCOVERY, 10)], Severity.HIGH),  # two stages, hours apart
    ([(Stage.HELPDESK_RESET, 0), (Stage.REMOTE_DISCOVERY, 0.5)], Severity.CRITICAL),  # within an hour
    ([(Stage.HELPDESK_RESET, 0), (Stage.REMOTE_DISCOVERY, 8), (Stage.LATERAL_MOVEMENT, 16)], Severity.CRITICAL),
    ([(Stage.REMOTE_DISCOVERY, 0), (Stage.CREDENTIAL_THEFT, 20)], Severity.CRITICAL),  # stage 3
    ([(Stage.HELPDESK_RESET, 0), (Stage.BACKUP_DESTRUCTION, 20)], Severity.CRITICAL),  # stage 5
])
def test_severity_scales_with_stage_count_and_closeness(stages_and_gaps, severity):
    [incident] = correlate([signal(stage, T0 + hours * H) for stage, hours in stages_and_gaps])
    assert incident.severity is severity


def test_close_means_within_an_hour():
    assert CLOSE == H


def test_an_incident_is_never_less_severe_than_its_worst_signal():
    canary = signal(Stage.ENCRYPTION, T0 + 10 * H, severity=Severity.CRITICAL)
    [incident] = correlate([signal(Stage.LATERAL_MOVEMENT, T0, severity=Severity.LOW), canary])
    assert incident.severity is Severity.CRITICAL
    assert "critical signal" in incident.reason


def test_incidents_come_back_in_time_order_and_are_stable():
    later = [signal(Stage.HELPDESK_RESET, T0 + 100 * H, host="B"), signal(Stage.REMOTE_DISCOVERY, T0 + 101 * H,
                                                                              host="B")]
    earlier = [signal(Stage.HELPDESK_RESET, T0, host="A", user="LAB\\amy"),
               signal(Stage.REMOTE_DISCOVERY, T0 + H, host="A", user="LAB\\amy")]
    incidents = correlate(later + earlier)
    assert [i.first_seen for i in incidents] == [T0, T0 + 100 * H]
    assert correlate(later + earlier) == correlate(earlier + later)


# --- real replayed data (datasets/fetch.sh) --------------------------------------------------

RULES = load_rules()
SINGLE_TECHNIQUE = [  # every pinned recording of one technique, attack and control alike
    "T1003.001/atomic_red_team/windows-sysmon.log", "T1003.003/atomic_red_team/windows-sysmon.log",
    "T1003.006/mimikatz/xml-windows-security.log", "T1003.006/impacket/windows-security-xml.log",
    "T1021.001/rdp_session_established/4624_10_logon.log", "T1021.002/atomic_red_team/windows-sysmon.log",
    "T1047/atomic_red_team/windows-sysmon.log", "T1087.002/AD_discovery/windows-sysmon.log",
    "T1098/account_manipulation/xml-windows-security.log", "T1098/dnsadmins_member_added/windows-security.log",
    "T1098/windows_multiple_passwords_changed/windows_multiple_passwords_changed.log",
    "T1136.001/atomic_red_team/xml-windows-security.log", "T1219/atomic_red_team/windows-sysmon.log",
    "T1219/screenconnect/screenconnect_sysmon.log", "T1482/atomic_red_team/windows-sysmon.log",
    "T1486/bitlocker_sus_commands/bitlocker_sus_commands.log", "T1486/dcrypt/windows-sysmon.log",
    "T1486/sam_sam_note/windows-sysmon.log", "T1490/atomic_red_team/windows-sysmon.log",
    "T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log",
]


@pytest.mark.parametrize("relative", SINGLE_TECHNIQUE)
def test_a_recording_of_one_technique_is_never_an_incident(relative):
    # Up to 66 signals in one file, but all of one stage: the noise correlation exists to hold back.
    signals = replay(load_events(dataset(relative)), RULES)
    assert len({s.stage for s in signals}) <= 1
    assert correlate(signals) == []


def test_a_ransomware_run_that_deletes_backups_then_drops_notes_is_one_critical_incident():
    signals = replay(load_events(dataset("malware/ransomware_ttp/data2/windows-sysmon.log")), RULES)
    [incident] = correlate(signals)
    assert (incident.entity_kind, incident.entity) == ("host", "win-dc-385")
    assert incident.stages == (Stage.BACKUP_DESTRUCTION, Stage.ENCRYPTION)
    assert incident.severity is Severity.CRITICAL
    assert len(incident.signals) == len(signals) == 84  # one backup deletion, 83 ransom notes


# --- the same logic in Sigma's correlation syntax -------------------------------------------

CORRELATION = ROOT / "sigma" / "correlation" / "two_stage_24h.yml"


def correlation_rules():
    collection = SigmaCollection.from_yaml(CORRELATION.read_text(encoding="utf-8"))
    collection.resolve_rule_references()
    return collection


def test_the_sigma_rules_state_the_same_window_and_threshold():
    correlations = [rule for rule in correlation_rules().rules if isinstance(rule, SigmaCorrelationRule)]
    assert sorted(tuple(rule.group_by) for rule in correlations) == [("host",), ("user",)]
    for rule in correlations:
        assert rule.type is SigmaCorrelationType.VALUE_COUNT
        assert rule.timespan.seconds == WINDOW.total_seconds()
        assert (rule.condition.fieldref, rule.condition.op, rule.condition.count) == \
            ("dwellwatch_stage", SigmaCorrelationConditionOperator.GTE, 2)


def test_the_sigma_account_rule_leaves_out_the_same_service_identities():
    [base] = [r for r in correlation_rules().rules if getattr(r, "name", None) == "dwellwatch_alert_with_account"]
    [condition] = base.detection.parsed_condition
    matches = _compile(condition.parsed, CORRELATION)
    for account in ["NT AUTHORITY\\SYSTEM", "SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NETWORK SERVICE",
                    "NT AUTHORITY\\ANONYMOUS LOGON", "ANONYMOUS LOGON", "NT AUTHORITY\\IUSR", "LAB\\WS01$",
                    "-", "", "LAB\\jdoe", "jdoe", "LAB\\svc-backup"]:
        linkable = signal(Stage.REMOTE_DISCOVERY, user=account)
        assert matches({"dwellwatch_stage": "2", "user": account}) is (_user_key(linkable) is not None), account


def test_the_sigma_rules_convert_for_splunk():
    queries = SplunkBackend().convert(correlation_rules())
    by_host = next(q for q in queries if "by _time host" in q)
    assert "| bin _time span=24h" in by_host  # fixed buckets, not the engine's rolling window
    assert "dc(dwellwatch_stage) as value_count" in by_host and "| search value_count >= 2" in by_host


def test_the_command_line_replays_then_correlates(capsys):
    from dwellwatch.correlate import main
    assert main([str(dataset("malware/ransomware_ttp/data2/windows-sysmon.log"))]) == 0
    out = capsys.readouterr().out
    assert out.startswith("84 signal(s), 1 incident(s)")
    assert "CRITICAL  host win-dc-385" in out and "critical because it includes backup destruction" in out
    assert main([str(ROOT / "no-such-file.log")]) == 2
