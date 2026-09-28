"""The dwell-time metric: which stage fired first, and how long before encryption."""

import re
from datetime import UTC, datetime, timedelta

import pytest
import yaml

from dwellwatch.correlate import correlate, detect, raised_at
from dwellwatch.metric import (
    RUNS,
    Measurement,
    Summary,
    check_readme,
    headline,
    incident_line,
    load_runs,
    main,
    measure,
    measure_run,
    summarise,
)
from dwellwatch.models import Severity, Signal, Stage
from dwellwatch.replay import load_rules

from conftest import ROOT, dataset

T0 = datetime(2025, 4, 24, 9, 0, tzinfo=UTC)
H, M = timedelta(hours=1), timedelta(minutes=1)


def signal(stage, at, host="WS01", user="LAB\\jdoe", rule=None):
    return Signal(stage=stage, host=host, user=user, timestamp=at, rule_id=rule or f"rule-{int(stage)}",
                  attack_technique="T1486", severity=Severity.HIGH)


# --- one run ----------------------------------------------------------------------------------


def test_the_full_chain_reports_its_first_stage_and_the_lead_before_the_stage_6_signal():
    # The brief's definition: encryption starts at the first stage 6 signal.
    chain = [signal(stage, T0 + i * 6 * H) for i, stage in enumerate(Stage)]
    m = measure(reversed(chain))  # arrival order does not matter
    assert m.first_stage is Stage.HELPDESK_RESET
    assert m.lead == 30 * H and m.lead.total_seconds() / 60 == 1800
    assert m.stages_before == tuple(Stage)[:5]
    assert m.encryption_at == m.encryption_seen_at == T0 + 30 * H
    assert m.incident_at == T0 + 6 * H and m.incident_lead == 24 * H  # stages 1 and 2 six hours apart


def test_a_labelled_encryption_start_is_the_yardstick_when_given():
    signals = [signal(Stage.BACKUP_DESTRUCTION, T0), signal(Stage.ENCRYPTION, T0 + 10 * M)]
    m = measure(signals, encryption_at=T0 + 4 * M)  # the first note, before DwellWatch saw it
    assert m.lead == 4 * M and m.encryption_seen_at == T0 + 10 * M


def test_the_first_stage_is_the_earliest_in_time_not_in_the_chain():
    # Ransomware opening LSASS (stage 3) an hour before an admin's discovery command (stage 2).
    signals = [signal(Stage.REMOTE_DISCOVERY, T0 + H), signal(Stage.CREDENTIAL_THEFT, T0),
               signal(Stage.ENCRYPTION, T0 + 2 * H)]
    m = measure(signals)
    assert m.first_stage is Stage.CREDENTIAL_THEFT and m.lead == 2 * H


def test_only_signals_strictly_before_encryption_count():
    signals = [signal(Stage.BACKUP_DESTRUCTION, T0 + 5 * M), signal(Stage.ENCRYPTION, T0 + 5 * M)]
    m = measure(signals, encryption_at=T0 + 5 * M)
    assert (m.first, m.lead, m.stages_before) == (None, None, ())
    # The stage 6 signal itself is never "before encryption", whatever came first.
    assert measure([signal(Stage.ENCRYPTION, T0)]).first is None


def test_known_false_positives_are_left_out_by_rule_and_second():
    procmon = signal(Stage.CREDENTIAL_THEFT, T0 + timedelta(microseconds=335051), rule="lsass")
    shadow = signal(Stage.BACKUP_DESTRUCTION, T0 + 7 * M)
    signals = [procmon, shadow, signal(Stage.ENCRYPTION, T0 + 23 * M)]
    m = measure(signals, false_positives=[("lsass", T0)])
    assert m.first == shadow and m.lead == 16 * M
    assert m.incident_at == T0 + 23 * M  # without the false positive, the second stage is encryption
    assert measure(signals, false_positives=[("lsass", T0 + H)]).first == procmon  # another second: kept


def test_without_encryption_there_is_nothing_to_measure_against():
    m = measure([signal(Stage.HELPDESK_RESET, T0), signal(Stage.CREDENTIAL_THEFT, T0 + H)])
    assert (m.encryption_at, m.lead, m.incident_lead) == (None, None, None)
    assert m.incident_at == T0 + H


def test_an_incident_raised_after_encryption_has_no_lead():
    signals = [signal(Stage.CREDENTIAL_THEFT, T0), signal(Stage.ENCRYPTION, T0 + M)]
    m = measure(signals, encryption_at=T0 + 30 * timedelta(seconds=1))
    assert m.lead == 30 * timedelta(seconds=1)
    assert m.incident_at == T0 + M and m.incident_lead is None


# --- when correlation raises an incident ------------------------------------------------------


def test_an_incident_is_raised_by_the_signal_that_brings_a_second_stage():
    signals = [signal(Stage.REMOTE_DISCOVERY, T0), signal(Stage.REMOTE_DISCOVERY, T0 + H),
               signal(Stage.CREDENTIAL_THEFT, T0 + 3 * H), signal(Stage.ENCRYPTION, T0 + 5 * H)]
    [incident] = correlate(signals)
    assert incident.first_seen == T0 and raised_at(incident) == T0 + 3 * H


def test_an_incident_carried_across_days_is_raised_when_its_second_stage_arrives():
    # Discovery every 20 hours keeps one chain going for three days before credential theft joins it.
    signals = [signal(Stage.REMOTE_DISCOVERY, T0 + i * 20 * H) for i in range(4)]
    signals += [signal(Stage.CREDENTIAL_THEFT, T0 + 70 * H), signal(Stage.REMOTE_DISCOVERY, T0 + 71 * H)]
    [incident] = correlate(signals)
    assert incident.first_seen == T0 and raised_at(incident) == T0 + 70 * H


# --- many runs --------------------------------------------------------------------------------


def run_with_lead(lead, incident_lead=None):
    encryption = T0 + 2 * H
    first = signal(Stage.BACKUP_DESTRUCTION, encryption - lead) if lead is not None else None
    incident = encryption - incident_lead if incident_lead is not None else None
    return Measurement(encryption, first, (), encryption, incident)


def test_the_headline_is_the_median_lead_over_the_runs_detected_before_encryption():
    runs = [run_with_lead(timedelta(seconds=s)) for s in (0.3, 8, 47, 65, 990, 2940)] + [run_with_lead(None)] * 5
    summary = summarise(runs)
    assert (summary.runs, len(summary.leads)) == (11, 6)
    assert summary.median_lead == timedelta(seconds=56)  # between 47 and 65 seconds
    assert headline(summary) == ("First alert fired a median of 0.9 minutes before encryption in 6 of 11 "
                                 "replayed ransomware runs.")


def test_leads_of_ten_minutes_or_more_are_whole_minutes():
    summary = summarise([run_with_lead(49 * M), run_with_lead(16.4 * M), run_with_lead(M)])
    assert "a median of 16 minutes" in headline(summary)


def test_the_headline_says_so_when_nothing_fired_before_encryption():
    summary = summarise([run_with_lead(None)] * 3)
    assert headline(summary) == "No alert fired before encryption in any of 3 replayed ransomware runs."
    assert incident_line(summary) == "No correlated incident was raised before encryption in any of them."


def test_the_incident_line_reports_incidents_raised_before_encryption():
    summary = summarise([run_with_lead(3 * H, incident_lead=H), run_with_lead(M)])
    assert incident_line(summary) == ("A correlated incident was raised before encryption in 1 of them, "
                                      "a median of 60.0 minutes before.")


def test_the_readme_check_reads_the_headline_paragraph_across_line_breaks(tmp_path):
    summary = Summary(runs=2, leads=(M,), incident_leads=())
    readme = tmp_path / "README.md"
    sentence = f"{headline(summary)} {incident_line(summary)}"
    wrapped = sentence.replace(" of 2 ", " of\n2 ")
    readme.write_text(f"# DwellWatch\n\n**Headline metric:** {wrapped}\n\nMore.\n")
    assert check_readme(readme, summary) == []
    readme.write_text("**Headline metric:** First alert fired a median of 1.0 minutes before encryption.\n")
    assert len(check_readme(readme, summary)) == 2
    readme.write_text("no headline here\n")
    assert check_readme(readme, summary) == [f"{readme}: no line starting **Headline metric:**"]


# --- the runs ---------------------------------------------------------------------------------


def test_the_runs_file_names_real_rules_fetched_files_and_one_unseen_run():
    runs = load_runs()
    assert len(runs) == 11 and [r.name for r in runs if not r.seen] == ["Chaos, spreading to root drives"]
    rule_ids = {rule.id for rule in load_rules()}
    for run in runs:
        for rule, _ in run.false_positives:
            assert rule in rule_ids, (run.name, rule)
    fetch = (ROOT / "datasets" / "fetch.sh").read_text()
    fetched = set(re.findall(r"^datasets/(\S+)\s+[0-9a-f]{64}$", fetch, re.M))
    listed = {name for entry in yaml.safe_load(RUNS.read_text())["runs"] for name in entry["files"]}
    assert listed <= fetched


def test_a_pinned_run_measures_against_its_first_ransom_note():
    dataset("malware/ransomware_ttp/data2/windows-sysmon.log")
    [run] = [r for r in load_runs() if r.name == "ransomware_ttp, data2"]
    m = measure_run(run)
    assert m.encryption_at.replace(microsecond=0) == datetime(2021, 6, 21, 14, 31, 28, tzinfo=UTC)
    assert m.first_stage is Stage.BACKUP_DESTRUCTION and round(m.lead.total_seconds()) == 47
    assert m.stages_before == (Stage.BACKUP_DESTRUCTION,) and m.incident_lead is None


def test_detect_lets_a_watcher_see_every_event():
    seen = []

    def watch(events):
        for event in events:
            seen.append(event)
            yield event

    path = dataset("T1490/atomic_red_team/windows-sysmon.log")
    assert detect([path], load_rules(), watch=watch) == detect([path], load_rules())
    assert len(seen) == 285


def test_the_command_line_measures_the_runs_and_checks_the_readme(tmp_path, capsys):
    dataset("malware/ransomware_ttp/data2/windows-sysmon.log")
    runs = tmp_path / "runs.yml"
    entries = [e for e in yaml.safe_load(RUNS.read_text())["runs"] if e["name"] == "ransomware_ttp, data2"]
    runs.write_text(yaml.safe_dump({"runs": entries}))
    readme = tmp_path / "README.md"
    readme.write_text("**Headline metric:** First alert fired a median of 0.8 minutes before encryption\n"
                      "in 1 of 1 replayed ransomware runs. No correlated incident was raised before\n"
                      "encryption in any of them.\n")
    assert main(["--runs", str(runs), "--check", str(readme)]) == 0
    out = capsys.readouterr().out
    assert "ransomware_ttp, data2" in out and "stage 5, backup destruction" in out and "47s" in out
    readme.write_text("**Headline metric:** not measured yet.\n")
    assert main(["--runs", str(runs), "--check", str(readme)]) == 1


def test_the_command_line_says_which_fetch_is_missing(tmp_path, capsys):
    runs = tmp_path / "runs.yml"
    runs.write_text(yaml.safe_dump({"runs": [{"name": "x", "files": ["malware/nope/sysmon.log"], "seen": True,
                                              "encryption": {"process": "x", "file": "y"}}]}))
    assert main(["--runs", str(runs)]) == 2
    assert "datasets/fetch.sh --metric" in capsys.readouterr().err


@pytest.mark.parametrize("broken", ["runs: [{name: x}]", "not: runs"])
def test_a_malformed_runs_file_is_an_error_not_a_traceback(tmp_path, broken):
    runs = tmp_path / "runs.yml"
    runs.write_text(broken)
    assert main(["--runs", str(runs)]) == 2
