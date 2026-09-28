<h1 align="center">DwellWatch</h1>

<p align="center">
  <b>Ransomware early warning for the weeks before encryption.</b><br>
  Detection-as-code for each stage of a help-desk-led intrusion, plus correlation<br>
  that turns weak signals on one user or host into a single high-confidence incident.
</p>

<p align="center">
  <a href="https://github.com/vinitrami-Soc/dwellwatch/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/vinitrami-Soc/dwellwatch/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.11 and 3.12" src="https://img.shields.io/badge/python-3.11%20%7C%203.12-3776ab">
  <a href="LICENSE"><img alt="MIT licence" src="https://img.shields.io/badge/license-MIT-green"></a>
  <img alt="Detections in Sigma" src="https://img.shields.io/badge/detections-Sigma-8a2be2">
  <img alt="Mapped to MITRE ATT&CK" src="https://img.shields.io/badge/mapped%20to-MITRE%20ATT%26CK-c00">
</p>

> **Status: in progress.** Phases 0 and 1 are done: the replay engine and the first three rules
> (stage 5, backup destruction), tested on real Atomic Red Team telemetry. Stages 1 to 4 and 6,
> correlation and the metric are still to come. See the [roadmap](#roadmap).

**Headline metric:** _not measured yet._ Once the chain has been emulated, this line will read
"First alert fired N minutes before encryption in X of Y emulated runs", with the denominator and
the measurement method published alongside it.

## What it is

DwellWatch is a small Windows lab plus a detection-as-code repository that catches a help-desk-led
ransomware intrusion during the weeks the attackers are inside, not at the moment they encrypt files.
It emulates the attack chain seen in the 2025 attacks on UK retailers stage by stage, ships tested
Sigma rules for each stage (converted to Wazuh, Splunk SPL and Microsoft Sentinel KQL), correlates
several weak signals on the same user or host into one high-confidence incident, and pushes that
incident to [IntelPulse](https://github.com/vinitrami-Soc/intelpulse) for enrichment and a ticket.
It also produces a one-page help-desk verification checklist and a small-business readiness page,
so it is useful to people outside a SOC too.

## Why dwell time

In a help-desk-led intrusion the attacker does not break in; they phone the service desk,
impersonate an employee and get a password or MFA reset. From there they spend days or weeks
discovering the network, stealing credentials and deleting backups before a single file is
encrypted. Every one of those steps leaves Windows telemetry. Encryption is the receipt, not the
robbery: DwellWatch is built to alert during the robbery.

## The attack chain it detects

Stages 1 to 5 happen during dwell time and are the ones worth catching. Stage 6 is the backstop.

| # | Stage | What the attacker does | Primary telemetry | ATT&CK |
|---|---|---|---|---|
| 1 | Help-desk reset abuse | Impersonates an employee, gets a password or MFA reset | Windows Security 4724, 4738; group adds 4728, 4732, 4756 | T1078, T1098, T1556 |
| 2 | Remote tooling and discovery | Installs remote access, runs discovery commands | Sysmon 1 (process creation), 3 (network) | T1219, T1087, T1018 |
| 3 | Credential theft | Copies the AD database or reads LSASS | Sysmon 10 (access to lsass), 11 (NTDS.dit copy); Security 4662 with replication rights | T1003.001, T1003.003 |
| 4 | Lateral movement | Moves host to host with the stolen account | Security 4624 logon types 3 and 10; Sysmon 1 for psexec and wmic | T1021, T1570 |
| 5 | Backup destruction | Deletes shadow copies and backups before encrypting | Sysmon 1: vssadmin, wbadmin, bcdedit, diskshadow, wmic, reagentc | T1490 |
| 6 | Encryption (backstop) | Mass file changes, ransom notes | Wazuh FIM burst; canary file modification | T1486 |

## Detections so far

| Stage | Rule | Fires on |
|---|---|---|
| 5 | [Shadow Copies Deleted With vssadmin](sigma/stage5_backup_destruction/vssadmin_shadow_delete.yml) | `vssadmin delete shadows` |
| 5 | [Backup Catalogue Deleted With wbadmin](sigma/stage5_backup_destruction/wbadmin_delete_catalog.yml) | `wbadmin delete catalog` |
| 5 | [Windows Recovery Disabled With bcdedit](sigma/stage5_backup_destruction/bcdedit_recovery_disabled.yml) | `bcdedit ... recoveryenabled no`, `bootstatuspolicy ignoreallfailures` |

On real data from Splunk's attack_data, the Atomic Red Team T1490 run (285 events) raises exactly
one alert per targeted command, 4 in all, and none for the `cmd.exe` processes that launched them.
A 7,010-event T1003.003 run, which uses vssadmin and wmic to *create* shadow copies, raises none.

Replayed unchanged against recordings they were not written against (ransomware runs from
attack_data, including Chaos, Clop, Conti, LockBit, REvil and Ryuk, plus all 278 EVTX-ATTACK-SAMPLES
files), the rules fired on **14 of 14** in-scope destructive commands with **no false positives in
392,824 events**. The same data shows what they miss: wmic and PowerShell shadow-copy deletion,
Clop's `vssadmin resize shadowstorage`, and ransomware that deletes copies without a command line.
Details, the exact commands and the misses are in [docs/lab-architecture.md](docs/lab-architecture.md).

## When a signal becomes an incident

One `vssadmin delete shadows` on its own might be an administrator. A password reset, then NTDS.dit
access, then shadow-copy deletion on the same account is an attack. DwellWatch raises an incident
when **two or more distinct stages appear on the same user or host within 24 hours**, and treats
any incident that includes credential theft (stage 3) or backup destruction (stage 5) as critical.
This is risk-based alerting: individual rules stay sensitive, and correlation keeps the noise down.

## How it runs

- **Replay mode** runs the rules offline against recorded Windows event logs, today from
  [Splunk attack_data](https://github.com/splunk/attack_data), fetched at a pinned commit and
  checked against pinned SHA-256 hashes. It needs no virtual machines, works on a 16 GB laptop
  and is what CI runs.
- **Live mode** (planned) runs [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  tests on lab VMs (domain controller, Windows 11, Wazuh manager) and detects them in Wazuh.

See [docs/lab-architecture.md](docs/lab-architecture.md) for both.

## Roadmap

- [x] **Phase 0:** repository scaffold, data model, CI
- [x] **Phase 1:** replay engine and the first detections (stage 5, backup destruction)
- [ ] **Phase 2:** pySigma conversion to Wazuh, SPL and KQL
- [ ] **Phase 3:** rules for stages 1 to 4 and 6
- [ ] **Phase 4:** the correlation engine
- [ ] **Phase 5:** the dwell-time metric
- [ ] **Phase 6:** IntelPulse webhook integration
- [ ] **Phase 7:** help-desk checklist and small-business readiness page

## Repository layout

```
sigma/            detection rules, one folder per stage, plus correlation/  (source of truth)
converted/        generated Wazuh, Splunk and Sentinel versions of every rule
src/dwellwatch/   replay, correlation, metric and webhook code
tests/            offline pytest suite, run in CI
datasets/         replay data, fetched by script and never committed
atomics/          notes on each Atomic Red Team run
docs/             lab architecture, threat model, detection catalogue, method
```

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
datasets/fetch.sh          # about 13 MB of real telemetry; without it the real-data tests skip
ruff check
pytest

# replay any Windows event XML or evtx_dump JSON Lines file through the rules
python -m dwellwatch.replay datasets/attack_data/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log
```

## Safety

DwellWatch only emulates. Attack telemetry comes from Atomic Red Team, run on snapshotted lab VMs
that nothing else depends on, or from published datasets. Encryption is emulated with Atomic Red
Team's T1486 tests against a folder of dummy files; there is no encryptor, keylogger or C2 in this
repository. It stores hashes, never malware samples, and any committed sample data has its IP
addresses and usernames sanitised. Secrets live in `.env`, which is ignored; `.env.example` shows
the variables.

## Related projects

DwellWatch is one of three SOC projects that fit together:

- [PhishHawk](https://github.com/vinitrami-Soc/phishhawk) triages reported phishing email.
- [IntelPulse](https://github.com/vinitrami-Soc/intelpulse) enriches indicators and writes the ticket.
- DwellWatch detects the intrusion and hands IntelPulse the incident.

## Licence

[MIT](LICENSE) © 2026 Vinit Rami
