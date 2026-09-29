"""Push correlated incidents to IntelPulse, which enriches them and writes the ticket.

    python -m dwellwatch.correlate FILES --push    # correlate, then push every incident

IntelPulse (https://github.com/vinitrami-Soc/intelpulse) takes them at POST /api/alerts. Where to
send them comes from the environment or a .env file, never from the command line or the repository:

    INTELPULSE_WEBHOOK_URL   e.g. http://localhost:8000/api/alerts
    INTELPULSE_API_TOKEN     only if the IntelPulse deployment sets API_TOKEN

What goes over the wire (payload()) is the incident as IntelPulse's alert: its severity, its reason,
the host and accounts it concerns, its ATT&CK techniques, and the signals behind it with the event
fields that fired them, at most five per rule. Indicators in that text are defanged (hxxp, [.]) so a
ticket or a log line never holds a live link; IntelPulse refangs them to enrich them. The SHA-256 of
each process a signal names is sent as an explicit indicator: that is what threat intelligence can
look up. The alert's id is fixed by the incident's entity, first signal and stages, so a retried
push is the same alert (IntelPulse answers with the case it already made), and a new stage is a new one.

A dead, slow or refusing endpoint never stops a detection run: push() logs why and returns it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .burst import NOTE_BURST_RULE_ID, NOTE_BURST_TITLE
from .models import STAGE_NAMES, Incident, Signal, account_key, host_key
from .newsource import NEW_SOURCE_RULE_ID, NEW_SOURCE_TITLE
from .replay import Rule

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
TIMEOUT = 10.0  # seconds: long enough for IntelPulse to triage, short enough not to hold a run up
PER_RULE = 5  # evidence items per rule; 83 identical ransom notes do not need 83 rows
MAX_EVIDENCE = 200  # IntelPulse's limit
MAX_TEXT = 4_000  # IntelPulse's limit per evidence item
SHA256_EVIDENCE = re.compile(r"^SHA256=([0-9A-Fa-f]{64})$")


# --- defanging --------------------------------------------------------------------------------

_URL = re.compile(r"\bh(tt)(ps?)://([^\s/|\"'<>]+)", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A dotted name whose last label could be a top-level domain, as long as it is not a file extension.
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]{1,63}\.)+([A-Za-z]{2,24})\b")
FILE_EXTENSIONS = frozenset({
    "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "js", "hta", "jar", "lnk", "scr", "msi",
    "txt", "log", "csv", "json", "xml", "html", "htm", "ini", "cfg", "dat", "db", "tmp", "bak", "dit", "hiv",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "zip", "rar", "7z", "gz", "tar", "iso", "dmp",
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "readme", "local", "lan", "internal", "localdomain",
})


def defang(text: str) -> str:
    """URLs, IPv4 addresses and domain names made safe to paste: hxxp, 10[.]0[.]0[.]1, example[.]com.
    File names are left alone (cmd.exe stays cmd.exe), and so are internal names such as
    corp.local, which nothing on the internet resolves."""
    text = _URL.sub(lambda m: f"hxx{m.group(2)}://{m.group(3).replace('.', '[.]')}", text)
    text = _IPV4.sub(lambda m: m.group().replace(".", "[.]"), text)
    return _DOMAIN.sub(lambda m: m.group() if m.group(1).lower() in FILE_EXTENSIONS
                       else m.group().replace(".", "[.]"), text)


# --- the payload ------------------------------------------------------------------------------


def rule_titles(rules: Iterable[Rule]) -> dict[str, str]:
    """Every signal source's title by id: the Sigma rules and the two counters."""
    titles = {rule.id: rule.title for rule in rules}
    titles[NOTE_BURST_RULE_ID] = NOTE_BURST_TITLE
    titles[NEW_SOURCE_RULE_ID] = NEW_SOURCE_TITLE
    return titles


def alert_id(incident: Incident) -> str:
    """Fixed by what the incident is about, when it began and which stages it has."""
    key = "|".join([incident.entity_kind, incident.entity, _iso(incident.first_seen),
                    ",".join(str(int(stage)) for stage in incident.stages)])
    return "dw-" + hashlib.sha256(key.encode()).hexdigest()[:16]


def payload(incident: Incident, titles: Mapping[str, str]) -> dict:
    """The incident as the JSON body of IntelPulse's POST /api/alerts."""
    signals = sorted(incident.signals, key=lambda s: (s.timestamp, s.stage))
    what = "host" if incident.entity_kind == "host" else "account"
    return {
        "source": "dwellwatch",
        "alert_id": alert_id(incident),
        "title": f"DwellWatch: {incident.severity.name} incident on {what} {defang(incident.entity)}",
        "severity": incident.severity.name.lower(),
        "description": defang(f"{incident.reason} {len(signals)} signal(s), "
                              f"{incident.first_seen.astimezone(UTC):%Y-%m-%d %H:%M:%S} to "
                              f"{incident.last_seen.astimezone(UTC):%Y-%m-%d %H:%M:%S} UTC."),
        "entities": _entities(signals),
        "attack_techniques": sorted({s.attack_technique for s in signals}),
        "first_seen": _iso(incident.first_seen),
        "last_seen": _iso(incident.last_seen),
        "indicators": _hashes(signals),
        "evidence": _evidence(signals, titles),
    }


def _entities(signals: list[Signal]) -> list[dict[str, str]]:
    hosts = sorted({key for s in signals if (key := host_key(s.host))})
    users = sorted({s.user for s in signals if s.user and account_key(s.user)})
    return ([{"kind": "host", "name": defang(host)} for host in hosts[:25]]
            + [{"kind": "user", "name": user} for user in users[:25]])


def _hashes(signals: list[Signal]) -> list[str]:
    found = {m.group(1).lower() for s in signals for name, value in s.evidence
             if name == "Hashes" and (m := SHA256_EVIDENCE.match(value))}
    return sorted(found)[:100]


def _evidence(signals: list[Signal], titles: Mapping[str, str]) -> list[dict[str, str]]:
    shown: Counter[str] = Counter()
    items = []
    for signal in signals:
        shown[signal.rule_id] += 1
        if shown[signal.rule_id] > PER_RULE:
            continue
        title = titles.get(signal.rule_id, signal.rule_id)
        label = (f"stage {int(signal.stage)} ({STAGE_NAMES[signal.stage]}): {title}, "
                 f"{host_key(signal.host) or '-'}, {signal.user or '-'}")
        text = defang(" | ".join(f"{name}: {value}" for name, value in signal.evidence))
        items.append({"time": _iso(signal.timestamp), "label": defang(label)[:300],
                      "text": text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"})
    for rule_id, count in shown.items():
        if count > PER_RULE and len(items) < MAX_EVIDENCE:
            items.append({"time": None, "label": f"{count - PER_RULE} more from {titles.get(rule_id, rule_id)}",
                          "text": ""})
    return items[:MAX_EVIDENCE]


def _iso(when: datetime) -> str:
    return when.astimezone(UTC).isoformat().replace("+00:00", "Z")


# --- delivery ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Delivery:
    """What happened to one incident's push."""

    alert_id: str
    delivered: bool
    status: int | None  # the HTTP status, if IntelPulse answered at all
    detail: str  # the case and its report when delivered, otherwise why not
    case_id: str | None = None


@dataclass(frozen=True)
class Endpoint:
    url: str
    token: str | None = None


class ConfigurationError(ValueError):
    """Pushing is asked for but not set up; nothing was sent."""


DOTENV = ROOT / ".env"


def endpoint(environ: Mapping[str, str] | None = None, dotenv: Path | None = None) -> Endpoint:
    """Where to push, from the environment first and a .env file (DOTENV by default) second."""
    values = _dotenv(DOTENV if dotenv is None else dotenv)
    values.update({k: v for k, v in (os.environ if environ is None else environ).items() if v})
    url = values.get("INTELPULSE_WEBHOOK_URL", "").strip()
    if not url:
        raise ConfigurationError("INTELPULSE_WEBHOOK_URL is not set (in the environment or .env)")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigurationError("INTELPULSE_WEBHOOK_URL must be an http:// or https:// URL")
    if parts.username or parts.password:
        raise ConfigurationError("put the token in INTELPULSE_API_TOKEN, not in the URL")
    return Endpoint(url, values.get("INTELPULSE_API_TOKEN", "").strip() or None)


def _dotenv(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        name, equals, value = line.strip().partition("=")
        if equals and name and not name.startswith("#"):
            values[name.strip()] = value.strip().strip("'\"")
    return values


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the token to wherever it points. None is followed: it is an error."""

    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


_OPENER = urllib.request.build_opener(_NoRedirects)


def push(incidents: Iterable[Incident], titles: Mapping[str, str], target: Endpoint,
         timeout: float = TIMEOUT) -> list[Delivery]:
    """Push each incident; never raise for the endpoint's sake. Failures are logged and returned."""
    return [_push_one(payload(incident, titles), target, timeout) for incident in incidents]


def _push_one(body: dict, target: Endpoint, timeout: float) -> Delivery:
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "User-Agent": f"DwellWatch/{__version__}"}
    if target.token:
        headers["Authorization"] = f"Bearer {target.token}"
    request = urllib.request.Request(target.url, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            status, answer = response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        delivery = Delivery(body["alert_id"], False, error.code, f"IntelPulse refused it: {_reason(error)}")
    except (urllib.error.URLError, OSError) as error:  # refused, unreachable, timed out
        reason = getattr(error, "reason", error)
        delivery = Delivery(body["alert_id"], False, None, f"IntelPulse could not be reached: {reason}")
    except ValueError:  # an answer that is not JSON
        delivery = Delivery(body["alert_id"], False, None, "IntelPulse answered, but not with JSON")
    else:
        case = answer.get("case_id") if isinstance(answer, dict) else None
        if not case:
            delivery = Delivery(body["alert_id"], False, status, "IntelPulse answered without a case")
        else:
            again = " (already received)" if answer.get("duplicate") else ""
            detail = (f"case {case}{again}, ticket level {answer.get('ticket_level', '?')}, "
                      f"report {answer.get('report', '-')}")
            delivery = Delivery(body["alert_id"], True, status, detail, case)
    log = logger.info if delivery.delivered else logger.warning
    log("push %s: %s", body["alert_id"], delivery.detail)
    return delivery


def _reason(error: urllib.error.HTTPError) -> str:
    """IntelPulse's own explanation, trimmed; never the request, which holds the token."""
    try:
        detail = json.loads(error.read() or b"{}").get("detail")
    except (ValueError, AttributeError, OSError):
        detail = None
    text = detail if isinstance(detail, str) else json.dumps(detail)[:200] if detail else ""
    return f"{error.code} {text or error.reason}".strip()[:300]
