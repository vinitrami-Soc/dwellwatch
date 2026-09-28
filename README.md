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

> **Status: in progress.** Phases 0 to 4 are done: the replay engine, 26 Sigma rules across all
> six stages, tested on real Atomic Red Team, ransomware and attack-sample telemetry and converted
> for Wazuh, Splunk and Sentinel, and the correlation engine that turns them into incidents. The
> dwell-time metric, the IntelPulse webhook and the help-desk pages are still to come. See the
> [roadmap](#roadmap).

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
| 1 | Help-desk reset abuse | Impersonates an employee, gets a password or MFA reset | Windows Security 4724 (password reset); group adds 4728, 4732, 4756. MFA resets are in the identity provider's logs, not Windows' | T1078, T1098, T1556 |
| 2 | Remote tooling and discovery | Installs remote access, runs discovery commands | Sysmon 1 or Security 4688 (process creation) | T1219, T1087, T1018, T1482 |
| 3 | Credential theft | Copies the AD database or reads LSASS | Sysmon 10 (access to lsass), 11 (dump files, NTDS.dit copies); process creation for dump and copy commands; Security 4662 with replication rights | T1003.001, T1003.002, T1003.003, T1003.006 |
| 4 | Lateral movement | Moves host to host with the stolen account | Security 4624 logon types 9 and 10; process creation for PsExec, Impacket and remote WMI | T1021.001, T1021.002, T1047, T1550.002 |
| 5 | Backup destruction | Deletes shadow copies and backups before encrypting | Sysmon 1: vssadmin, wbadmin, bcdedit, diskshadow, wmic, reagentc | T1490 |
| 6 | Encryption (backstop) | Mass file changes, ransom notes | Sysmon 11 (notes, canary files, one process spraying the same note into 20 folders); disk and file encryption commands; in the live lab, Wazuh FIM bursts and canaries | T1486 |

## Detections so far

| Stage | Rule | Fires on |
|---|---|---|
| 1 | [Password Reset On Another Account](sigma/stage1_helpdesk/password_reset_by_another_account.yml) | one account resetting another's password (4724); a weak signal on its own, for correlation |
| 1 | [Member Added To A Privileged Group](sigma/stage1_helpdesk/privileged_group_member_added.yml) | an add to Domain, Enterprise or Schema Admins, Administrators, the Operators groups or DnsAdmins |
| 2 | [Remote Access Tool Started](sigma/stage2_remote_discovery/remote_access_tool_started.yml) | AnyDesk, TeamViewer, ScreenConnect, GoToAssist, Splashtop, RustDesk, Atera, Tailscale, ngrok and others, renamed or not |
| 2 | [Domain Trusts Or Controllers Listed](sigma/stage2_remote_discovery/domain_trust_discovery.yml) | `nltest /domain_trusts` or `/dclist`, dsquery for trusts, PowerView's trust and DC functions |
| 2 | [Active Directory Enumerated With AdFind, SharpHound, AD Explorer Or PowerView](sigma/stage2_remote_discovery/ad_recon_tool.yml) | AdFind or SharpHound (renamed too), AD Explorer snapshots, PowerView's account and computer functions |
| 2 | [Domain Queried With net](sigma/stage2_remote_discovery/net_domain_query.yml) | `net user`, `group`, `accounts` or `view` with `/domain`, one alert per command |
| 3 | [LSASS Memory Opened For Credential Theft](sigma/stage3_credential_theft/lsass_memory_access.yml) | LSASS opened through the dump functions, or with full or read access by anything but the system processes (Sysmon 10) |
| 3 | [LSASS Dumped From The Command Line](sigma/stage3_credential_theft/lsass_dump_command.yml) | procdump or PPLdump on lsass, comsvcs MiniDump, rdrleakdiag, mimikatz commands |
| 3 | [AD Database Copied](sigma/stage3_credential_theft/ntds_database_copied.yml) | `ntdsutil ifm`, NTDS.dit read out of a shadow copy, `esentutl /vss` |
| 3 | [Credential Hives Saved Or Copied](sigma/stage3_credential_theft/registry_hives_copied.yml) | `reg save` of SAM, SYSTEM or SECURITY, or the hives read out of a shadow copy |
| 3 | [Directory Replication Requested By A User Account](sigma/stage3_credential_theft/dcsync_by_non_dc_account.yml) | DCSync from any account that is not a domain controller's (Security 4662) |
| 3 | [LSASS Dump Or AD Database Written To Disk](sigma/stage3_credential_theft/credential_dump_file_written.yml) | an LSASS dump file, or NTDS.dit outside its home folder (Sysmon 11) |
| 4 | [Remote Execution Through PsExec Or Impacket](sigma/stage4_lateral_movement/remote_exec_psexec_impacket.yml) | PsExec to another host, PSEXESVC starting, Impacket-style output written back through `\\127.0.0.1\` |
| 4 | [Process Started On Another Host With WMI](sigma/stage4_lateral_movement/wmi_remote_process.yml) | `wmic /node: process call create`, `Invoke-WmiMethod`/`Invoke-CimMethod` with `-ComputerName` |
| 4 | [Remote Desktop Logon](sigma/stage4_lateral_movement/rdp_logon.yml) | every RDP logon (4624 type 10); a weak signal for correlation |
| 4 | [Logon With Credentials Injected For Another Account](sigma/stage4_lateral_movement/pass_the_hash_logon.yml) | the type 9 `seclogo` logon that pass-the-hash leaves on the attacker's machine |
| 6 | [Ransom Note Written](sigma/stage6_encryption/ransom_note_written.yml) | a page named like a ransom note (`HOW_TO_DECRYPT`, `RESTORE_MY_FILES`, `YOUR_FILES.txt`) |
| 6 | [DwellWatch Canary File Touched](sigma/stage6_encryption/canary_file_touched.yml) | any write to a file carrying the canary token |
| 6 | [Disk Encryption Turned Against The Owner](sigma/stage6_encryption/disk_encryption_abuse.yml) | BitLocker protectors deleted or password-locked, DiskCryptor |
| 6 | [Files Encrypted With A Command-Line Tool](sigma/stage6_encryption/files_encrypted_with_cli_tool.yml) | gpg, openssl or 7-Zip encrypting with a passphrase on the command line |
| 6 | [Same File Name Written Into Many Folders](src/dwellwatch/burst.py) (a count, not a Sigma rule) | one process writing one file name into 20 folders within 10 minutes: a ransom-note spray, whatever the note is called |
| 6 | [Wazuh FIM burst and canary](wazuh/dwellwatch_fim_rules.xml) (Wazuh only) | 50 file changes by one process in watched folders within a minute; a canary document changed, renamed or deleted |
| 5 | [Shadow Copies Deleted With vssadmin](sigma/stage5_backup_destruction/vssadmin_shadow_delete.yml) | `vssadmin delete shadows` |
| 5 | [Backup Catalogue Deleted With wbadmin](sigma/stage5_backup_destruction/wbadmin_delete_catalog.yml) | `wbadmin delete catalog` |
| 5 | [Windows Recovery Disabled With bcdedit](sigma/stage5_backup_destruction/bcdedit_recovery_disabled.yml) | `bcdedit ... recoveryenabled no`, `bootstatuspolicy ignoreallfailures` |
| 5 | [Shadow Copies Deleted With wmic](sigma/stage5_backup_destruction/wmic_shadowcopy_delete.yml) | `wmic shadowcopy delete` |
| 5 | [Shadow Copies Deleted With PowerShell](sigma/stage5_backup_destruction/powershell_shadowcopy_delete.yml) | `Win32_ShadowCopy` with `.Delete()`, `Remove-WmiObject` or `Remove-CimInstance` |
| 5 | [Shadow Copies Deleted With Encoded PowerShell](sigma/stage5_backup_destruction/powershell_encoded_shadowcopy_delete.yml) | the same, hidden with `-EncodedCommand` |

On Splunk's attack_data, the stage 1 rules fire on all 61 password resets and all 5 privileged
group adds in four real Security logs, and stay quiet on an add to a group that grants nothing.
On data they were not written against (EVTX-ATTACK-SAMPLES), they fired 4 times, all on attacks:
noPac, a post-Zerologon password reset, and Guest and Network Service made local administrators.

The stage 2 rules fire on every remote-access tool, trust query, AdFind, PowerView and
`net ... /domain` command in four real attack_data runs, once per command and never on the
shell or download around it. On data they were not written against, their first version caught
6 of 8 discovery commands from Conti's Cobalt Strike session and an Atomic run, with no false
positives; the two misses (`net view /domain`, PowerView's `Get-DomainController`) are now
fixed.

The stage 3 rules catch every LSASS dumping method in the Atomic T1003.001 run (procdump, a
renamed copy, comsvcs, Dumpert, Task Manager, a mimikatz-like tool) while 110 ordinary LSASS
accesses stay quiet, every step of an NTDS.dit theft, and mimikatz's DCSync. On data they were
not written against, their first version caught 13 of 15 credential-theft samples, with one false
positive (Process Monitor opening LSASS). rdrleakdiag's dump is now covered; MalSeclogon, and
DCSync run as a domain controller's machine account, are known gaps.

Stage 4 is deliberately narrow, and its unseen-data result says so plainly. Its rules caught
PsExec, Impacket's wmiexec and dcomexec, mimikatz's pass-the-hash and RDP tunnelling in
EVTX-ATTACK-SAMPLES, but not WinRM, PowerShell remoting, SharpRDP, remote services or tasks,
DCOM or target-side WMI. Correlation is what connects such movement to the stages around it.

Stage 6 is the backstop. Its rules fire on DiskCryptor and BitLocker abuse in attack_data and stay
quiet on ordinary READMEs. Honestly scored, the ransom-note rule caught one ransomware family of
seven in the unseen recordings: most notes are named "readme", like ordinary documentation. What
all seven share is one process writing the same note into many folders, so
[`burst.py`](src/dwellwatch/burst.py) now counts that: one process writing one file name into 20
folders within 10 minutes is a stage 6 signal. It fires in 8 of the 9 recordings that hold such a
spray and on no ordinary software (whose most is 14 folders), but the 20 was set after seeing both
sides, so that is a fit, not a blind result. In Wazuh the same job is file integrity monitoring,
configured rather than written in Sigma ([`wazuh/`](wazuh)); the canary files are the dependable
backstop in the live lab.

For stage 5, the Atomic Red Team T1490 run from attack_data (285 events) raises exactly
one alert per targeted command, 6 in all, and none for the `cmd.exe` processes that launched them.
A 7,010-event T1003.003 run, which uses vssadmin, wmic and PowerShell to *create* shadow copies,
raises no stage 5 alert (it steals NTDS.dit, which the stage 3 rules catch).

The first three rules were then replayed unchanged against recordings they were not written
against: ransomware runs from attack_data (Chaos, Clop, Conti, LockBit, REvil, Ryuk and others)
and all 278 EVTX-ATTACK-SAMPLES files, 392,824 events. They fired on **14 of 14** in-scope
destructive commands with **no false positives**. That data also showed the wmic, PowerShell and
encoded PowerShell deletions they missed (REvil's, for one), so the last three rules were written
to close that gap. On the same data all six rules now fire on 26 of 26 with no false positives,
but for the last three that is a regression check, not an unseen test. Still missed: Clop's
`vssadmin resize shadowstorage`. Details and exact commands are in
[docs/lab-architecture.md](docs/lab-architecture.md).

## When a signal becomes an incident

One `vssadmin delete shadows` on its own might be an administrator. A password reset, then NTDS.dit
access, then shadow-copy deletion on the same account is an attack.
[`correlate.py`](src/dwellwatch/correlate.py) raises an incident when **two or more distinct
stages appear on the same host or account within a rolling 24 hours**, and scales its severity:

- two stages are high; three or more, or two within an hour of each other, are critical;
- any incident that includes credential theft (stage 3) or backup destruction (stage 5) is
  critical whatever the count, and none is less severe than its worst signal (a touched canary
  file is critical on its own);
- SYSTEM, service and machine accounts never link signals, since every Windows host has them.

Every incident says why, in a sentence:

```
$ python -m dwellwatch.correlate datasets/attack_data/datasets/malware/ransomware_ttp/data2/windows-sysmon.log
85 signal(s), 1 incident(s)

CRITICAL  host win-dc-385  2021-06-21 14:30Z to 2021-06-21 14:31Z  85 signal(s)
  Stages 5 (backup destruction) and 6 (encryption) on host win-dc-385 within 1m; critical because it includes backup destruction.
```

On the real recordings, the 20 pinned single-technique runs (up to 66 signals each) raise no
incident, and across the unseen recordings four incidents appear, each on a real multi-stage
attack: Conti's Cobalt Strike session, an Atomic Red Team run, a ransomware run, and Clop, whose
incident leans on one stage 3 false positive. Adding the note-spray count turns four more
ransomware runs (Chaos, LockBit, REvil, Ryuk) into incidents and gives Clop's a genuine second
stage; that count's threshold was set on these same recordings, so those four are not an unseen
result. The command line counts sprays alongside the rules. Details are in
[docs/lab-architecture.md](docs/lab-architecture.md#correlation-on-real-data). For SIEMs, the
same rule is written in Sigma's correlation syntax in
[`sigma/correlation/two_stage_24h.yml`](sigma/correlation/two_stage_24h.yml).

## How it runs

- **Replay mode** runs the rules offline against recorded Windows event logs, today from
  [Splunk attack_data](https://github.com/splunk/attack_data), fetched at a pinned commit and
  checked against pinned SHA-256 hashes. It needs no virtual machines, works on a 16 GB laptop
  and is what CI runs.
- **Live mode** (planned) runs [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  tests on lab VMs (domain controller, Windows 11, Wazuh manager) and detects them in Wazuh.

See [docs/lab-architecture.md](docs/lab-architecture.md) for both.

## Deploying the rules

Every Sigma rule is converted for three SIEMs, and the results are committed so they can be read
and copied without running anything:

| SIEM | Files | Covers |
|---|---|---|
| Wazuh 4.14.8 | [`converted/wazuh/`](converted/wazuh) (local rules: copy into `/var/ossec/etc/rules/`) | Sysmon events 1, 10 and 11, Security 4688, and the Security events the stage 1 and 3 rules read |
| Splunk | [`converted/splunk/`](converted/splunk) (SPL searches) | Sysmon events 1, 10 and 11; Security events collected as XML |
| Microsoft Sentinel | [`converted/sentinel/`](converted/sentinel) (KQL) | Process creation from Sysmon, Security 4688 and Defender for Endpoint, through ASIM `imProcessCreate`; file creation through `imFileEvent`; Security-log rules over `SecurityEvent`. Not Sysmon 10, which Sentinel has no table for |

`python -m dwellwatch.convert` (or `make convert`) regenerates them, and CI fails if they fall
out of date. Stage 6's file integrity monitoring is Wazuh configuration, not Sigma: [`wazuh/`](wazuh)
holds three hand-written rules (a burst of changes by one process in watched folders, a canary
changed or deleted, and the per-file rule the burst counts) and the agent's `syscheck` block. Wazuh has no pySigma backend, so its rules are generated by DwellWatch itself and
tested to fire on exactly the events the replay engine flags. What each target can and cannot
express, and the converter problems found on the way, are in the
[detection catalogue](docs/detection-catalogue.md).

## Roadmap

- [x] **Phase 0:** repository scaffold, data model, CI
- [x] **Phase 1:** replay engine and the first detections (stage 5, backup destruction)
- [x] **Phase 2:** conversion to Wazuh, SPL and KQL
- [x] **Phase 3:** rules for stages 1 to 4 and 6
- [x] **Phase 4:** the correlation engine
- [ ] **Phase 5:** the dwell-time metric
- [ ] **Phase 6:** IntelPulse webhook integration
- [ ] **Phase 7:** help-desk checklist and small-business readiness page

## Repository layout

```
sigma/            detection rules, one folder per stage, plus correlation/  (source of truth)
converted/        generated Wazuh, Splunk and Sentinel versions of every rule
wazuh/            hand-written Wazuh FIM rules and agent config for stage 6 (not from Sigma)
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
datasets/fetch.sh          # about 77 MB of real telemetry; without it the real-data tests skip
ruff check
pytest
python -m dwellwatch.convert   # after changing a rule: regenerate converted/ (make convert)

# replay any Windows event XML or evtx_dump JSON Lines file through the rules
python -m dwellwatch.replay datasets/attack_data/datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log
# ...and correlate the signals of one or more files, read as one timeline, into incidents
python -m dwellwatch.correlate datasets/attack_data/datasets/malware/ransomware_ttp/data2/windows-sysmon.log
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
