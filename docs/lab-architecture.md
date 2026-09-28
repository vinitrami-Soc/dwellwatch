# Lab architecture

DwellWatch runs in two modes that share the same rules and the same Python code.

| Mode | Where the events come from | Status |
|---|---|---|
| **Replay** | Recorded Windows event logs from Splunk's [attack_data](https://github.com/splunk/attack_data), fetched by `datasets/fetch.sh` | Built (Phase 1). Runs on a laptop and in CI |
| **Live** | Atomic Red Team tests run on lab VMs, collected by Wazuh | Planned; see [Live lab](#live-lab-planned) |

## Replay datasets

`datasets/fetch.sh` fetches twenty-one files from one pinned commit of attack_data
(`52c9d8a53167872293c9d0ca359b5166fb25e243`) and checks each one against a pinned SHA-256.
Nothing it fetches is committed: `datasets/` is gitignored apart from the script and
`runs.yml`. `datasets/fetch.sh --metric` also fetches the eleven ransomware recordings the
headline metric is measured on (about 520 MB more), listed and labelled in
[`datasets/runs.yml`](../datasets/runs.yml) and described in [metric-method.md](metric-method.md).

| File (under `datasets/attack_techniques/`) | What it records | Events | Role |
|---|---|---|---|
| `T1490/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1490 tests 1 to 6 on a domain controller: vssadmin, wmic and PowerShell shadow-copy deletion, `wbadmin delete catalog`, bcdedit recovery tampering, `wbadmin delete systemstatebackup` | 285 Sysmon | Attack: every stage 5 rule must fire on its command |
| `T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log` | The same shadow-copy deletion, seen by Security 4688 instead of Sysmon | 4 Security | Attack: the rules must work without Sysmon |
| `T1003.003/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1003.003 (NTDS.dit theft): `vssadmin create shadow`, `wmic shadowcopy call create`, PowerShell's `Win32_ShadowCopy.Create()`, `ntdsutil ifm`, NTDS.dit and SYSTEM copied out of a shadow copy, `reg save HKLM\SYSTEM`, the test runner's own `-EncodedCommand` PowerShell, plus the host's ordinary background activity | 7,010 Sysmon | Control for stage 5: no stage 5 rule may fire. Attack for stage 3: each theft step fires |
| `T1003.001/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1003.001: LSASS dumped with procdump (and a renamed copy), comsvcs.dll's MiniDump, Dumpert, Task Manager and a mimikatz-like tool, with the host's ordinary LSASS access around them | 7,960 Sysmon (6,909 of them event 10) | Attack and control: every dumping tool fires; svchost, csrss, wininit, WMI and PowerShell opening LSASS do not |
| `T1003.006/mimikatz/xml-windows-security.log` | DCSync with mimikatz from a user account | 11 Security | Attack: each replication request fires |
| `T1003.006/impacket/windows-security-xml.log` | DCSync with Impacket's secretsdump, run as the domain controller's machine account | 7 Security | Known blind spot: nothing fires, and the test pins that |
| `T1021.002/atomic_red_team/windows-sysmon.log` | PsExec run against `\\localhost`, and PsExec run locally with `-s` to save a registry key as SYSTEM | 10 Sysmon | Attack and control: the remote PsExec fires; the local one does not |
| `T1047/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1047: wmic queries, `wmic /node: ... process call create`, local `wmic process call create`, plus a host's background activity | 6,571 Sysmon | Attack and control: only the process creation on a node fires |
| `T1021.001/rdp_session_established/4624_10_logon.log` | RDP logons to two domain controllers | 16 Security | Attack: every RDP logon fires and names its account |
| `T1486/dcrypt/windows-sysmon.log` | DiskCryptor downloaded, installed and run, as in Atomic Red Team's T1486 DiskCryptor test and Mamba ransomware | 343 Sysmon | Attack: each DiskCryptor binary fires; its installer stub does not |
| `T1486/bitlocker_sus_commands/bitlocker_sus_commands.log` | `manage-bde -protectors -delete C:` | 1 Sysmon | Attack: it fires |
| `T1486/sam_sam_note/windows-sysmon.log` | A SamSam ransom-note run whose Sysmon log holds no note, but does hold the Splunk forwarder writing its own `README.txt`, among 8,500 events | 8,491 Sysmon | Control: nothing fires |
| `../malware/ransomware_ttp/data2/windows-sysmon.log` | A ransomware run that deletes shadow copies and writes `HOW_TO_RESTORE_MY_FILES.txt` into 83 folders; first used as unseen data, pinned in Phase 4 | 4,623 Sysmon | Correlation: one critical incident, backup destruction and encryption within a minute |
| `T1098/windows_multiple_passwords_changed/windows_multiple_passwords_changed.log` | An administrator resetting 40 accounts' passwords on a domain controller, with the PowerShell that did it | 345 (133 Security) | Attack: one stage 1 reset signal per reset, each naming the reset account |
| `T1098/account_manipulation/xml-windows-security.log` | Accounts created, enabled and reset (21 resets), and four group adds: three to Domain Admins, one of them an account adding itself, and one to a workstation's `None` group | 430 Security | Attack and control: the Domain Admins adds fire; the `None` add, and 400 other account events, do not |
| `T1098/dnsadmins_member_added/windows-security.log` | An account added to DnsAdmins, whose members can make the DNS service load code | 228 (173 Security) | Attack: the one add fires |
| `T1136.001/atomic_red_team/xml-windows-security.log` | Atomic Red Team T1136.001: a local account created and added to Administrators | 2 Security | Attack: the add fires; creating the account does not |
| `T1219/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1219: AnyDesk, TeamViewer and GoToAssist downloaded with PowerShell, installed and started | 26 Sysmon | Attack: each tool process fires; the downloads and installers around them do not |
| `T1219/screenconnect/screenconnect_sysmon.log` | ScreenConnect installed through its ClickOnce launcher and run as a service | 105 Sysmon | Attack: the ScreenConnect service and client fire |
| `T1482/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1482: `nltest /domain_trusts`, `dsquery` for trusted domains, PowerView's trust functions and AdFind | 515 Sysmon | Attack: each query fires once, on the tool; the `cmd.exe` that launched it does not |
| `T1087.002/AD_discovery/windows-sysmon.log` | Domain account listing: `net user /domain` in three spellings, PowerView's `Get-DomainUser`, `Get-ADUser`, `dsquery user`, WMI's `ds_user`, plus 7,000 events of a domain controller's background activity | 7,070 Sysmon | Attack and control: net and PowerView fire once per command; the everyday admin listings do not |

**Why the control is attack data.** attack_data has no folder of benign Windows activity. The
T1003.003 run is the next best thing, and arguably a harder test: it runs the same tools as
backup destruction (vssadmin, wmic, PowerShell's Win32_ShadowCopy) to *create* shadow copies,
which is also what backup software does every night. A rule that keys on the tool or on the
word "shadow" fails here; a rule that keys on the destructive verb passes. It also carries
7,000 events of ordinary Windows background noise.

### Fetching them

```bash
datasets/fetch.sh
```

The script is safe to re-run: it only fetches what is missing or fails its checksum. With
git-lfs installed, it runs these commands (paths shortened here to `T1490/...`; the script uses
the full `datasets/attack_techniques/...` paths):

```bash
git init datasets/attack_data
git -C datasets/attack_data remote add origin https://github.com/splunk/attack_data
git -C datasets/attack_data lfs install --local --skip-smudge
git -C datasets/attack_data fetch --depth 1 origin 52c9d8a53167872293c9d0ca359b5166fb25e243
git -C datasets/attack_data sparse-checkout set --no-cone /T1490/... /T1490/... /T1003.003/...
GIT_LFS_SKIP_SMUDGE=1 git -C datasets/attack_data checkout --detach 52c9d8a53167872293c9d0ca359b5166fb25e243
git -C datasets/attack_data lfs pull --include="T1490/...,T1490/...,T1003.003/..."
```

The commit fetch brings the whole tree as LFS pointer files, a few MB, and none of the 9 GB of
content; `lfs pull --include` then downloads only the listed files. It deliberately does not use
`--filter=blob:none`, because `git lfs pull` lists the tree with object sizes and would then
fetch each of the repository's thousands of missing blobs one request at a time.

Without git-lfs, or if the LFS download fails (some corporate proxies block it), the script
downloads the same files from GitHub's LFS media host instead:

```bash
curl -fsSL -o <file> https://media.githubusercontent.com/media/splunk/attack_data/<commit>/<path>
```

Either way, every file is checked against the SHA-256 pinned in the script, and a mismatch
exits non-zero.

### Replaying them

```bash
A=datasets/attack_data/datasets/attack_techniques
python -m dwellwatch.replay $A/T1490/atomic_red_team/windows-sysmon.log \
    $A/T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log \
    $A/T1003.003/atomic_red_team/windows-sysmon.log
```

```
.../T1490/atomic_red_team/windows-sysmon.log: 6 signal(s) from 285 event(s)
  2021-01-22 20:43:31Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Shadow Copies Deleted With vssadmin
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Shadow Copies Deleted With wmic
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Backup Catalogue Deleted With wbadmin
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Windows Recovery Disabled With bcdedit
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Windows Recovery Disabled With bcdedit
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Shadow Copies Deleted With PowerShell
.../T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log: 2 signal(s) from 4 event(s)
  2023-10-03 15:53:57Z  stage 5  T1490  high  ar-win-dc.attackrange.local  ATTACKRANGE\Administrator  Shadow Copies Deleted With vssadmin
  2023-10-03 15:53:58Z  stage 5  T1490  high  ar-win-dc.attackrange.local  ATTACKRANGE\Administrator  Shadow Copies Deleted With wmic
.../T1003.003/atomic_red_team/windows-sysmon.log: 0 signal(s) from 7010 event(s)
```

The hosts and accounts are Splunk's Attack Range lab, as recorded upstream.

What that run shows, and what it does not:

- Each rule fires once per command. The `cmd.exe /c "..."` process that launched each command
  carries the same words but is not a second alert, because the rules match on the binary too.
- The bcdedit rule fires twice because the atomic test runs two separate bcdedit commands.
- **Not caught yet:** the same run deletes system-state backups with
  `wbadmin delete systemstatebackup -keepVersions:0`. No rule covers it, and the tests pin the
  current count, so adding one will show up as a deliberate test change.

`pytest` asserts all of the above. CI runs `datasets/fetch.sh` first and sets
`DWELLWATCH_REQUIRE_DATASETS=1`, so a missing dataset fails the build instead of skipping.

### Stage 1 on real data

The four stage 1 files replay to 66 signals, the number `pytest` pins:

- **Resets.** 61 resets, 61 signals, each naming the account that was reset rather than the
  administrator who reset it, because the reset account is the one a caller now holds. The bulk
  reset run also logs one 4738 ("user account changed") per reset, 40 of each, which is why
  4738 has no rule of its own: it would count every reset twice.
- **Group adds.** Five adds to privileged groups (three to Domain Admins, one to DnsAdmins, one
  to a host's Administrators), five signals. One of the Domain Admins adds is `unpriv2` adding
  itself. The add to a workstation's `None` group stays quiet.
- **SIDs arrive as names here.** Splunk's export resolves `TargetSid` to a name
  (`ATTACKRANGE\Domain Admins`), so in these files the rule matches on group names. On a raw
  EVTX export the well-known SIDs match, which also covers domains whose groups have
  non-English names.

These files shaped the rules, so they show the rules work on real events, not how they
generalise. They also hold little ordinary Security traffic (672 other Security events), so they
cannot measure the false-positive rate on a real domain's Security log. The reset rule fires on
every reset by design; telling a malicious reset from a routine one is correlation's job.

**On data the rules were not written against**, the 392,824 events of the round below, which
include 1,577 Security events from EVTX-ATTACK-SAMPLES, the stage 1 rules fired four times, all
on attacks: a machine account's password reset in a noPac (CVE-2021-42287) run, a remote
password reset over RPC after Zerologon, and Guest and Network Service each added to the local
Administrators group. They are the only resets and group adds in that data, so this shows the
rules catching attacks they were not written for, not how quiet they stay. The five 4738
events it also holds (an ACL-abuse sample changing another user's attributes) record no password
change, so no reset was missed there; they also show why a 4738 rule would be noisy.

### Stage 2 on real data

The four stage 2 files replay to 37 signals, the number `pytest` pins:

- **Remote-access tools**: 20 alerts, one per tool process. The Atomic run starts AnyDesk five
  times, TeamViewer twice (installer and client) and GoToAssist eight times (its launcher twice
  and six helper processes, caught by product name); ScreenConnect runs its service twice and its
  client three times. The PowerShell downloads, the msiexec install and the batch file around
  them stay quiet.
- **Trusts**: `nltest` three times, `dsquery` once and PowerView once, each one alert; the
  `cmd.exe` processes that launched them stay quiet. AdFind, run twice in the same test, fires the
  recon rule.
- **Accounts**: eight `net user /domain` commands (in the spellings `/do`, `/domain` and
  `users`), each one alert on `net1.exe` and none on the `net.exe` that started it, and two
  PowerView `Get-DomainUser` calls. `Get-ADUser -Filter *`, `dsquery user` and WMI's `ds_user`
  listing are in the same run and are not matched, by choice (see the catalogue).

**On data the rules were not written against** (the round below), the first version of the
stage 2 rules fired on 6 of 8 in-scope commands, all in Conti's Cobalt Strike session and the
PanacheSysmon Atomic sample, with **no false positives**: Conti's `net group "Domain Admins"
/domain` and `"Enterprise Admins"`, `nltest /DOMAIN_TRUSTS` (typed twice, once as
`/ DOMAIN_TRUSTS`), and PowerView's `Get-DomainComputer` twice. It missed two:

- `net view /domain` (PanacheSysmon). net.exe runs `view` itself instead of handing it to
  net1.exe, which the rule had assumed of every net command. Two separate recordings show it.
- PowerView's `Get-DomainController` (Conti), which was not in the trust and controller rule.

Both were fixed, and Conti's two `net group ... / domain` commands, typed with a space, now match
too. With the fixes the rules fire on all 10; for the four commands the fixes cover, that is a
regression check, not an unseen test. The unseen data holds no remote-access tool, AdFind, SharpHound or AD Explorer, so
the remote-tool rule has no unseen result either way: it fired on nothing in 392,824 events.
Commands that stayed quiet, correctly: local `net user` (a webshell sample), `net view`
without `/domain`, `net session`, `net use`, and Ryuk's and Prestige's `net stop`.

### Stage 3 on real data

The three stage 3 files and the T1003.003 run replay to the counts `pytest` pins:

- **LSASS (T1003.001 run)**: 66 alerts. The access rule fires 53 times, on every tool that read
  LSASS: a mimikatz-like tool named by a GUID (38 times; it opens LSASS repeatedly), procdump and
  its renamed copy, Dumpert, comsvcs through rundll32, and Task Manager. The command-line rule
  fires 8 times (procdump, the renamed copy, comsvcs, and the `cmd.exe` carrying mimikatz's
  `sekurlsa::` command, because mimikatz itself never started), and the file rule 5 times, on
  every dump named after LSASS. The run's 110 other LSASS accesses (svchost, services, csrss and
  wininit, PowerShell's `Get-Process`, Task Manager listing processes) stay quiet, and so do the
  shells and downloads.
  Dumpert's `dumpert.dmp` is not named after LSASS, so only the access rule sees that dump.
- **NTDS.dit (T1003.003 run)**: ntdsutil's IFM snapshot, `reg save HKLM\SYSTEM`, and one
  `cmd.exe` that copies both NTDS.dit and SYSTEM out of a shadow copy, which fires both the AD
  database and hives rules.
- **DCSync**: mimikatz asks for replication four times as `Administrator`, four alerts. Impacket's
  secretsdump, run as the domain controller's own machine account `AR-WIN-DC$`, raises nothing:
  that is indistinguishable here from domain controllers replicating, and the test pins it.

**On data the rules were not written against**, the first version of the stage 3 rules caught 13
of 15 credential-theft samples: every mimikatz variant (the executable, Invoke-Mimikatz twice,
BabyShark's), procdump, Task Manager, Dumpert and its variant, PPLdump (twice, once through a
vulnerable driver), meterpreter's hashdump, comsvcs MiniDump, Conti's Cobalt Strike beacon reading
LSASS, the Panache Atomic run's NTDS.dit and hive copies and seven `reg save` commands, and a
three-request DCSync. They missed two:

- **rdrleakdiag**, a Windows diagnostic tool, dumping LSASS with `/fullmemdmp`: its access was
  recorded as Sysmon event 8, not 10, and its dump is named `minidump_668.dmp`. Its switch is now
  in the command-line rule, a regression check from here on.
- **MalSeclogon**, which borrows an LSASS handle through the seclogon service with access `0x1410`,
  the mask WMI and Task Manager use all the time. Still missed; no rule separates it without
  also alerting on those.

PPLdump's command line was added to the command-line rule at the same time; both of its runs had
already been caught through LSASS access and the dump file.

Alerts that were not credential theft by a person: Sysinternals Process Monitor, run by whoever
recorded the Clop sample, opened LSASS with full access (**one false positive**); and the LockBit
and Ryuk binaries each opened LSASS with full access, which is malware at work, though not
necessarily reading credentials. Stayed quiet, correctly: 1,672 ordinary LSASS accesses in the
ransomware recordings (svchost, WMI, an EDR agent with `0x40`), domain controllers replicating as
`DC1$`, WerFault handling other processes' crashes, and commands that never ran because the tool
was not on the host (`procdump`, `ntdsutil` in the Panache run).

### Stage 4 on real data

attack_data has little lateral movement in a format replay reads (its pass-the-hash run is in
Splunk's plain-text export), so stage 4 leans on planted events and the unseen round. The three
pinned files: PsExec against `\\localhost` fires once, and the same run's local `PsExec -s`
stays quiet; `wmic /node:"127.0.0.1" process call create` fires once, and the run's local
`wmic process call create`, `/node:` queries and process deletion stay quiet; all 16 RDP logons
fire, each naming the account that logged on.

**On data the rules were not written against**, the first version of the stage 4 rules caught:
PsExec's service starting on a target, Impacket's wmiexec and dcomexec (three commands each),
mimikatz's pass-the-hash on the machine it ran from, and both RDP-tunnelling samples (RDP from
127.0.0.1). What else fired: PSEXESVC for a local `psexec -s` used to get SYSTEM (twice), and the
pass-the-hash rule on three other attacks that start processes with injected credentials (token
duplication and manipulation, MalSeclogon). Those are attacks, but not lateral movement. One
false positive: `wmic /node:localhost shadowcopy call create`, which makes a shadow copy; the
rule now requires `process call create`. One miss that was the same technique in a different
spelling: smbmap writing its output to `\\127.0.0.1\C$\<random>` rather than Impacket's names;
the rule now matches any output written back through `\\127.0.0.1\`. Both fixes are regression
checks from here on.

Missed, and left as documented gaps: WinRM and PowerShell remoting (the Clop, `ransomware_ttp`
and T1490 recordings hold about 140 WinRM-started processes running the same few encoded
PowerShell commands, which look like the lab's own provisioning, not the attack; a WinRM rule
would fire on all of them), SharpRDP, a remote scheduled task, services
installed remotely (System 7045), share access (5145), explicit-credential logons (4648), DCOM,
processes WMI starts on the target (Conti's Cobalt Strike beacon among them), and a local
pass-the-hash seen only as an NTLM network logon.

**The new-source counter** ([`newsource.py`](../src/dwellwatch/newsource.py)), added in Phase 4,
has nothing real to fire on yet. Across every recording here, the pinned files and the unseen
round's 392,824 events, there are 39 remote logons by people's accounts, in 11 files, each a snapshot of minutes to five days with no earlier history to learn
from, so with its defaults the counter judges none of them. Judged from the first logon with no
learning at all, where every source is new, it still raises nothing: no source reaches a second
host within an hour. (Before local accounts were kept apart from domain accounts of the same name,
it did: the pinned RDP recording's 10.0.1.12 reaching the domain's Administrator on `ar-win-dc`
and `ar-win-dc-2`'s local Administrator 24 seconds apart.) Its firing is tested on planted
events; the live lab's lateral-movement run, replayed with a baseline of normal days before it,
is its first real test.

### Stage 6 on real data

The pinned files: DiskCryptor's two `dcrypt.exe` runs and `dcinst -setup` fire, its Inno Setup
stub does not; the BitLocker protector deletion fires; the SamSam run, and the log forwarder's
`README.txt` in it, stay quiet. attack_data holds no file encrypted with gpg, openssl or 7-Zip and
no DwellWatch canary, so those rules are tested on planted events until the live lab runs.

**On data the rules were not written against**, with one caveat: the file names in the
ransomware recordings had already been printed by the stage 3 scan before the note rule was
written, so this is not a blind test, and none of those names were added to the rule. The note
rule caught **one family of seven**: 83 `HOW_TO_RESTORE_MY_FILES.txt` notes in a
`ransomware_ttp` run, with no false positives. It missed Chaos (`read_it.txt`, 118 folders), Clop
(`ClopReadMe.txt`, 245; `README_README.txt`, 40), Conti (`readme.txt`), LockBit
(`<id>.README.txt`, 749), Prestige (`README`) and Ryuk (`RyukReadMe.html`, 71). Most families
call the note some form of "readme", and so does ordinary software (the log forwarder wrote
`README.txt` in three of these recordings), so matching more names would trade misses for false
positives. What every one of these runs shares is volume: one process writing the same file name
into dozens or hundreds of folders, or `System` doing it over SMB (932 `readme.txt` in
one Conti run). That is now counted by [`burst.py`](../src/dwellwatch/burst.py): one process
writing one file name into 20 folders within 10 minutes. It fires in 8 of the 9 recordings that
hold such a spray (not REvil's second run, at 15 folders) and on no ordinary software, whose most
is 14. The 20 was chosen after measuring these same recordings, so this is a fit, not a blind
result; the numbers are in the
[detection catalogue](detection-catalogue.md#counting-note-sprays-and-fim-bursts). In the live
lab, Wazuh's file integrity monitoring and the canary files do the same job. No
disk-encryption or command-line encryption tool appears in the unseen data, so those two rules
have no unseen result.

### Tested on data the rules were not written against

The datasets above shaped the rules, so they cannot show how the rules generalise. On
2026-09-28 the first three rules (vssadmin, wbadmin, bcdedit) were also replayed, unchanged,
against recordings they had never seen:

- **Ransomware in attack_data** (same pinned commit): Chaos, Clop (two runs), Conti (three),
  LockBit, Prestige, REvil (two), Ryuk, the `malware/ransomware_ttp` runs, and two more T1490
  folders (`ransomware_notes`, `shadowcopy_del`). 15 files, 355,460 events.
- **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)**: all 278 `.evtx`
  files, 37,364 events, converted twice with two independent parsers (the Rust `evtx` crate
  behind `evtx_dump`, to JSON Lines; `python-evtx`, to XML). Both conversions gave the same
  events and the same signals.

The expected answer came from a separate scan for every backup-related process (vssadmin,
wbadmin, bcdedit, wmic shadowcopy, diskshadow, reagentc, PowerShell's Win32_ShadowCopy),
including the base64 inside every PowerShell `-EncodedCommand` (149 of them), each labelled by
hand as in or out of a rule's scope.

| First three rules, unseen data | Result |
|---|---|
| In-scope destructive commands | **14 of 14 fired**: vssadmin in `ransomware_notes`, Chaos, Clop (twice, as `vssadmin Delete Shadows`), Prestige and the EVTX Atomic run; bcdedit in `ransomware_notes`, Chaos, `ransomware_ttp` and the EVTX Atomic run (two each, except `ransomware_ttp` with one); wbadmin catalogue deletion in the EVTX Atomic run |
| False positives | **0 in 392,824 events**, including the real clean-up commands `bcdedit ... recoveryenabled yes` and `bootstatuspolicy DisplayAllFailures`, `vssadmin list shadows`, `vssadmin create shadow`, `wmic shadowcopy` listing, and malware run from inside a shadow copy |

The same data showed 12 deletions those three rules could not see, done with other tools:
`wmic shadowcopy delete` (Chaos, `ransomware_notes`, `shadowcopy_del`), PowerShell's
`Win32_ShadowCopy` with `.Delete()` or `Remove-CimInstance` (`ransomware_notes`,
`ransomware_ttp`), and the same PowerShell hidden with `-EncodedCommand`, which is how REvil
deletes shadow copies (five times in one run, twice in the other). The wmic, PowerShell and
encoded PowerShell rules were written to close that gap. On the same data all six rules fire on
**26 of 26** with **0 false positives**, including the other 142 encoded PowerShell commands,
which do other things. For those three rules this is a regression check, because the data informed them; it is
not evidence of how they generalise.

Still **not** caught:

- **Clop shrinks shadow storage** with `vssadmin resize shadowstorage /maxsize=401MB` on six
  drives, which makes Windows discard the existing shadow copies. The vssadmin rule looks only
  for `delete shadows`.
- **Encoded PowerShell in other spellings.** The encoded rule matches the base64 of fixed
  strings, so `WIN32_SHADOWCOPY` in capitals, or a class name built from pieces, gets past it.
  PowerShell script block logging (event 4104) records the decoded script and would close this.
- **No command line at all**: the Conti, LockBit and Ryuk recordings contain no command-line
  shadow-copy deletion, plain or encoded. Whether those samples deleted copies in-process or
  never reached that step, a process-creation rule cannot see it. That is the case stage 6
  (file activity) and correlation across stages exist for.
- **A command that never ran**: in Chaos and `ransomware_notes`, `cmd.exe /c wbadmin delete
  catalog` appears but no wbadmin process follows. On the Chaos host the command was handed to
  `mmc.exe` with `wbadmin.msc`, so nothing was deleted. The rules alert on the process that does
  the damage, not on the shell that asked for it, so neither run raised a wbadmin alert.

The same exercise found four ways a real export broke the replay reader, since fixed and
covered by tests: files with a UTF-8 byte-order mark, UTF-16 files (what PowerShell 5.1's `>`
writes), unreadable formats reported as a confusing JSON error, and a missing file ending in a
traceback. Reading is now streamed, so the largest file (166 MB) replays in 22 MB of memory.

## Correlation on real data

Each recording was replayed through all 26 rules and its signals correlated on their own
(recordings come from different labs and years, so they are not one timeline).

**No incident where there is only one technique.** None of the 20 pinned recordings, each of one
technique, raises an incident, including the LSASS run with 66 signals and the bulk password
reset with 40: every signal in each is the same stage. `pytest` pins this for all 20.

**One incident for each multi-stage attack the rules see**, across the unseen recordings:

| Recording | Incident | Stages | Within |
|---|---|---|---|
| Conti's Cobalt Strike session (attack_data) | critical, host `win-dc-58` | discovery (2), credential theft (3) | 1 minute |
| PanacheSysmon Atomic Red Team run (EVTX-ATTACK-SAMPLES) | critical, host `msedgewin10` | discovery (2), credential theft (3), backup destruction (5) | 24 minutes |
| `ransomware_ttp` data2 (attack_data, now pinned) | critical, host `win-dc-385` | backup destruction (5), 83 ransom notes (6) | 1 minute |
| Clop, run a (attack_data) | critical, host `win-dc-654` | credential theft (3), backup destruction (5) | 7 minutes |

The Clop incident has to be read with care: its stage 3 signal is the one false positive from
stage 3's unseen round, Process Monitor opening LSASS, run by whoever recorded the sample. The
backup destruction is Clop's. The host was under attack, but the incident is right for a wrong
reason.

**Attacks that stay single-stage on the rules alone, and why.** LockBit and Ryuk show only their
binaries opening LSASS (stage 3); Chaos, REvil, Prestige and a second `ransomware_ttp` run only
backup destruction (stage 5). Their other stages were either not in the recording or not
detected by a rule; for Chaos, LockBit, REvil and Ryuk the missed stage is the ransom notes.

**With the note-spray count** ([`burst.py`](../src/dwellwatch/burst.py), which
`python -m dwellwatch.correlate` runs alongside the rules), four of those become incidents. The
count's threshold was set on these same recordings, so these four are not an unseen result:

| Recording | Incident | Stages | Within |
|---|---|---|---|
| Chaos | critical, host `win-dc-ctus-attack-range-661` | backup destruction (5), note spray (6) | 2 seconds |
| LockBit | critical, host `win-dc-ctus-attack-range-221` | credential theft (3), note spray (6) | the same second |
| REvil, first run | critical, host `win-dc-410` | backup destruction (5), two note sprays (6) | 55 minutes |
| Ryuk | critical, host `win-client-4137150` | credential theft (3), note spray (6) | 40 seconds |

Clop's incident gains its note sprays too, so it no longer rests on the Process Monitor false
positive: backup destruction and the sprays make it an incident on their own. Clop's second run
and one Conti run spray notes with no other stage detected on the host, so they stay single-stage.
In Chaos the notes start a second before the shadow copies are deleted: encryption is not always
the last stage seen, which the dwell-time metric (Phase 5) has to allow for.

**What the SIEM translations lose.** [`sigma/correlation/two_stage_24h.yml`](../sigma/correlation/two_stage_24h.yml)
expresses the rule in Sigma's correlation syntax over DwellWatch's own alerts. pySigma turns it
into a Splunk search with `bin _time span=24h`, fixed day-long buckets: two stages either side of
a bucket boundary are missed, where `correlate.py`'s rolling window catches them. The Sigma
version also has one severity, not the scale, and no de-duplication of host and account
incidents. pySigma's Kusto backend has no correlation support, so Sentinel users would write the
equivalent KQL by hand.

## How replay evaluates a rule

1. **Read** the file: Windows event XML with one `<Event>` per record (attack_data, `wevtutil`),
   JSON Lines from `evtx_dump -o jsonl`, or already-flat JSON. Each event becomes one flat
   dictionary of System fields (`EventID`, `Channel`, `Computer`, `TimeCreated`) plus its
   EventData fields.
2. **Normalise.** Security 4688 names things differently from Sysmon 1, so it gets the Sysmon
   names that process_creation rules are written against: `NewProcessName` becomes `Image` and
   `ParentProcessName` becomes `ParentImage`. Every Security event also gets a `User`, the account
   correlation follows: the account acted on for a password reset or change (4723, 4724, 4738)
   or a logon (4624, 4625), because that is the account the attacker now holds; for other events,
   such as a group change, where the target is the group, the account that acted. Sysmon event 10
   takes its `User` from `SourceUser`, the account of the process reaching into another, when
   the Sysmon version records it (older ones, as in attack_data, do not; those signals carry the
   host only).
3. **Gate by logsource.** A rule only sees the events its Sigma logsource covers. For
   `process_creation` that is Sysmon event 1 and Security event 4688; `process_access` is Sysmon
   event 10 and `file_event` Sysmon event 11; for `service: security` it is every Security event,
   and the rule names its own EventIDs.
4. **Match.** pySigma parses the rule, exactly as the converters do, and replay
   evaluates pySigma's condition tree: `and`, `or`, `not`, `1 of` / `all of`, and the field
   modifiers pySigma turns into wildcards or regular expressions (`contains`, `startswith`,
   `endswith`, `all`, `re`, `cased`, and `wide|base64offset` for encoded command lines), plus
   numbers and `null`. Strings match case-insensitively, as Sigma specifies.
5. **Refuse what it cannot evaluate.** A rule that needs anything else (CIDR, field references,
   keyword searches, a logsource with no mapping yet) is rejected when it is loaded, with its
   path and the reason. It is never silently treated as "no match".

## Live lab (planned)

Not built yet. The plan, from the project brief:

- **VMs:** a Windows Server domain controller, a Windows 11 workstation, a Wazuh manager and a
  Kali attacker, on an isolated host-only network. Comfortable on 32 GB of RAM; on 16 GB, run
  one Windows VM at a time or stay in replay mode, where the detection work is identical.
- **Telemetry:** Sysmon and Windows Security auditing (including process command lines) on
  both Windows machines, shipped by the Wazuh agent, plus Wazuh file integrity monitoring with
  who-data on the file share and shared documents, where the canary files live
  ([`wazuh/agent_syscheck.xml`](../wazuh/agent_syscheck.xml)).
- **Baseline:** at least 14 days of ordinary activity recorded before any emulation, so the
  new-source counter knows which sources each account normally uses
  (`python -m dwellwatch.correlate --baseline`).
- **Emulation:** Atomic Red Team only, on snapshotted VMs that nothing else depends on.
- **Versions:** pinned here once installed. The Wazuh 4.14.x line is the target.
