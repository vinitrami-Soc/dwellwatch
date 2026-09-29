"""Stage 4 by counting: an account logging on from a source it has not used, to several hosts, fast.

Lateral movement with a stolen account is made of ordinary logons, one at a time: network logons
(Security 4624, logon type 3) for SMB, WMI or PsExec, and remote desktop logons (type 10). What
gives it away is where they come from and how fast they spread:

    An account logging on (type 3 or 10) from a source it has not logged on from in the
    previous MEMORY (14 days), and from there reaching HOSTS (2) or more hosts within WINDOW
    (1 hour) of that first logon, is a stage 4 signal (T1021), timed at the logon that reaches
    the second host. Once per account and source; after the hour the source is simply known.

"New" needs history, so the counter learns from every remote logon it sees and judges nothing
until it has seen LEARNING (14 days) of them; before that, every source would be new. A short
recording replayed alone therefore raises nothing: give it a baseline of normal activity recorded
before it (python -m dwellwatch.correlate --baseline).

A source is 4624's IpAddress, so a laptop given a new address by DHCP is a new source; in a lab
with fixed addresses that does not happen. Logons from the machine itself (loopback, or no
address) are not remote. Machine accounts, anonymous logons and service identities are left out,
as in correlation. Domain accounts are compared by name without their domain, because Windows
logs one account both as CORP\\jdoe and as corp.local\\jdoe; a local account, whose domain is the
host's own name, stays tied to its host, so WS01's Administrator is not the domain's.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from typing import NamedTuple

from .models import Severity, Signal, Stage, account_key, host_key
from .replay import SECURITY, Event, event_time, normalise

HOSTS = 2
WINDOW = timedelta(hours=1)
MEMORY = timedelta(days=14)
LEARNING = MEMORY
REMOTE_LOGON_TYPES = frozenset({"3", "10"})  # network, remote desktop
NEW_SOURCE_RULE_ID = "3e47cd41-0641-48e5-ac2c-b75e83e8d1cd"  # stands in for a Sigma rule's id
NEW_SOURCE_TITLE = "DwellWatch Account Reaches Several Hosts From A New Source"


class Logon(NamedTuple):
    when: datetime
    account: str  # lower case: a domain account's name alone, a local account's host\name
    source: str  # the IP address it came from
    host: str  # the host logged on to, short name
    user: str  # the account as logged, for the signal
    computer: str  # the host as logged, for the signal
    learning_only: bool  # from a baseline: teaches what is normal, never alerts
    logon_type: str = ""


def remote_logon(event: Event, *, learning_only: bool = False) -> Logon | None:
    """`event` as a remote logon by a person's account, or None if it is not one."""
    if event.get("Channel") != SECURITY or event.get("EventID") != "4624":
        return None
    if event.get("LogonType") not in REMOTE_LOGON_TYPES:
        return None
    event = normalise(event)
    account, host, source = account_key(event.get("User")), host_key(event.get("Computer", "")), _source(event)
    if not (account and host and source):
        return None
    domain, _, name = account.rpartition("\\")
    account = f"{host}\\{name}" if host_key(domain) == host else name
    return Logon(event_time(event), account, source, host, event["User"], event.get("Computer", ""), learning_only,
                 event.get("LogonType", ""))


def _source(event: Event) -> str | None:
    try:
        address = ipaddress.ip_address(event.get("IpAddress", "").strip())
    except ValueError:  # "-" or empty: Windows recorded no address
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(address)


class NewSources:
    """Notes remote logons as events stream past; signals() then finds the new sources that spread.

    Events can arrive in any order, so logons are kept, compactly, and ordered only when signals()
    is asked for.
    """

    def __init__(self, hosts: int = HOSTS, window: timedelta = WINDOW, memory: timedelta = MEMORY,
                 learning: timedelta = LEARNING) -> None:
        if hosts < 1:
            raise ValueError("a new source has to reach at least one host")
        self.hosts, self.window, self.memory, self.learning = hosts, window, memory, learning
        self._logons: list[Logon] = []

    def learn(self, event: Event) -> None:
        """Take `event` as normal activity: it shapes what counts as new but never alerts."""
        logon = remote_logon(event, learning_only=True)
        if logon:
            self._logons.append(logon)

    def add(self, event: Event) -> None:
        logon = remote_logon(event)
        if logon:
            self._logons.append(logon)

    def watch(self, events: Iterable[Event]) -> Iterator[Event]:
        """Pass `events` through unchanged, noting the remote logons on the way."""
        for event in events:
            self.add(event)
            yield event

    def signals(self) -> list[Signal]:
        """One stage 4 signal per new source that reaches enough hosts in time, in time order."""
        logons = sorted(self._logons)
        if not logons:
            return []
        judged_from = logons[0].when + self.learning
        last_seen: dict[tuple[str, str], datetime] = {}
        spreading: dict[tuple[str, str], tuple[datetime, set[str]]] = {}  # new pairs inside their window
        found = []
        for logon in logons:
            pair = (logon.account, logon.source)
            if pair in spreading and logon.when - spreading[pair][0] > self.window:
                del spreading[pair]  # its hour is over: from now on the source is known
            seen = last_seen.get(pair)
            if pair not in spreading and not logon.learning_only and logon.when >= judged_from and (
                    seen is None or logon.when - seen > self.memory):
                spreading[pair] = (logon.when, set())
            last_seen[pair] = logon.when
            if pair in spreading and not logon.learning_only:
                reached = spreading[pair][1]
                before = len(reached)
                reached.add(logon.host)
                if before < self.hosts <= len(reached):
                    found.append(Signal(
                        stage=Stage.LATERAL_MOVEMENT,
                        host=logon.computer,
                        user=logon.user,
                        timestamp=logon.when,
                        rule_id=NEW_SOURCE_RULE_ID,
                        attack_technique="T1021",
                        severity=Severity.MEDIUM,
                        evidence=(("IpAddress", logon.source), ("LogonType", logon.logon_type),
                                  ("Hosts", ", ".join(sorted(reached)))),
                    ))
        return found


def new_sources(events: Iterable[Event], baseline: Iterable[Event] = (), **settings) -> list[Signal]:
    """The spreading new sources in `events`, judged against `baseline` too: see the module docstring."""
    counter = NewSources(**settings)
    for event in baseline:
        counter.learn(event)
    for event in events:
        counter.add(event)
    return counter.signals()
