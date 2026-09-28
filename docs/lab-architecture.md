# Lab architecture

DwellWatch runs in two modes that share the same rules and the same Python code.

| Mode | Where the events come from | Status |
|---|---|---|
| **Replay** | Recorded Windows event logs from Splunk's [attack_data](https://github.com/splunk/attack_data), fetched by `datasets/fetch.sh` | Built (Phase 1). Runs on a laptop and in CI |
| **Live** | Atomic Red Team tests run on lab VMs, collected by Wazuh | Planned; see [Live lab](#live-lab-planned) |

## Replay datasets

`datasets/fetch.sh` fetches three files from one pinned commit of attack_data
(`52c9d8a53167872293c9d0ca359b5166fb25e243`) and checks each one against a pinned SHA-256.
Nothing it fetches is committed: `datasets/` is gitignored apart from the script.

| File (under `datasets/attack_techniques/`) | What it records | Events | Role |
|---|---|---|---|
| `T1490/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1490 tests 1 to 6 on a domain controller: vssadmin, wmic and PowerShell shadow-copy deletion, `wbadmin delete catalog`, bcdedit recovery tampering, `wbadmin delete systemstatebackup` | 285 Sysmon | Attack: every stage 5 rule must fire on its command |
| `T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log` | The same shadow-copy deletion, seen by Security 4688 instead of Sysmon | 4 Security | Attack: the rules must work without Sysmon |
| `T1003.003/atomic_red_team/windows-sysmon.log` | Atomic Red Team T1003.003 (NTDS.dit theft): `vssadmin create shadow`, `wmic shadowcopy call create`, `ntdsutil ifm`, plus the host's ordinary background activity | 7,010 Sysmon | Control: no stage 5 rule may fire |

**Why the control is attack data.** attack_data has no folder of benign Windows activity. The
T1003.003 run is the next best thing, and arguably a harder test: it runs the same binaries as
backup destruction (vssadmin, wmic) to *create* shadow copies, which is also what backup
software does every night. A rule that keys on the binary or on the word "shadow" fails here;
a rule that keys on the destructive verb passes. It also carries 7,000 events of ordinary
Windows background noise.

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
content; `lfs pull --include` then downloads only the three files. It deliberately does not use
`--filter=blob:none`, because `git lfs pull` lists the tree with object sizes and would then
fetch each of the repository's thousands of missing blobs one request at a time.

Without git-lfs, or if the LFS download fails (some corporate proxies block it), the script
downloads the same three files from GitHub's LFS media host instead:

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
.../T1490/atomic_red_team/windows-sysmon.log: 4 signal(s) from 285 event(s)
  2021-01-22 20:43:31Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Shadow Copies Deleted With vssadmin
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Backup Catalogue Deleted With wbadmin
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Windows Recovery Disabled With bcdedit
  2021-01-22 20:43:32Z  stage 5  T1490  high  win-dc-770.attackrange.local  ATTACKRANGE\Administrator  Windows Recovery Disabled With bcdedit
.../T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log: 1 signal(s) from 4 event(s)
  2023-10-03 15:53:57Z  stage 5  T1490  high  ar-win-dc.attackrange.local  ATTACKRANGE\Administrator  Shadow Copies Deleted With vssadmin
.../T1003.003/atomic_red_team/windows-sysmon.log: 0 signal(s) from 7010 event(s)
```

The hosts and accounts are Splunk's Attack Range lab, as recorded upstream.

What that run shows, and what it does not:

- Each rule fires once per command. The `cmd.exe /c "..."` process that launched each command
  carries the same words but is not a second alert, because the rules match on the binary too.
- The bcdedit rule fires twice because the atomic test runs two separate bcdedit commands.
- **Not caught yet:** the same T1490 run also deletes shadow copies with `wmic shadowcopy delete`
  and with PowerShell's `Win32_ShadowCopy.Delete()`, and deletes system-state backups with
  `wbadmin delete systemstatebackup -keepVersions:0`. No rule covers these yet, and the tests
  pin the current count, so adding a rule for them will show up as a deliberate test change.

`pytest` asserts all of the above. CI runs `datasets/fetch.sh` first and sets
`DWELLWATCH_REQUIRE_DATASETS=1`, so a missing dataset fails the build instead of skipping.

### Tested on data the rules were not written against

The datasets above shaped the rules, so they cannot show how the rules generalise. On
2026-09-28 the rules were also replayed, unchanged, against recordings they had never seen:

- **Ransomware in attack_data** (same pinned commit): Chaos, Clop (two runs), Conti (three),
  LockBit, Prestige, REvil (two), Ryuk, the `malware/ransomware_ttp` runs, and two more T1490
  folders (`ransomware_notes`, `shadowcopy_del`). 15 files, 355,460 events.
- **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)**: all 278 `.evtx`
  files, 37,364 events, converted twice with two independent parsers (the Rust `evtx` crate
  behind `evtx_dump`, to JSON Lines; `python-evtx`, to XML). Both conversions gave the same
  events and the same signals.

The expected answer came from a separate keyword scan for every backup-related process
(vssadmin, wbadmin, bcdedit, wmic shadowcopy, diskshadow, reagentc), labelled by hand as in or
out of each rule's scope.

| | Result |
|---|---|
| In-scope destructive commands | **14 of 14 fired**: vssadmin in `ransomware_notes`, Chaos, Clop (twice, as `vssadmin Delete Shadows`), Prestige and the EVTX Atomic run; bcdedit in `ransomware_notes`, Chaos, `ransomware_ttp` and the EVTX Atomic run (two each, except `ransomware_ttp` with one); wbadmin catalogue deletion in the EVTX Atomic run |
| False positives | **0 in 392,824 events**, including the real clean-up commands `bcdedit ... recoveryenabled yes` and `bootstatuspolicy DisplayAllFailures`, `vssadmin list shadows`, `vssadmin create shadow`, `wmic shadowcopy` listing, and malware run from inside a shadow copy |

What the same data showed is **not** caught yet:

- **Clop shrinks shadow storage** with `vssadmin resize shadowstorage /maxsize=401MB` on six
  drives, which makes Windows discard the existing shadow copies. The vssadmin rule looks only
  for `delete shadows`.
- **wmic and PowerShell deletion**: `wmic shadowcopy delete` (Chaos, the Atomic runs) and
  `Get-CimInstance Win32_ShadowCopy | Remove-CimInstance` (`ransomware_ttp`).
- **No command line at all**: the Conti, LockBit, REvil and Ryuk recordings contain no
  command-line shadow-copy deletion. Whether those samples deleted copies in-process or never
  reached that step, a process-creation rule cannot see it. That is the case stage 6 (file
  activity) and correlation across stages exist for.
- **A command that never ran**: in Chaos and `ransomware_notes`, `cmd.exe /c wbadmin delete
  catalog` appears but no wbadmin process follows. On the Chaos host the command was handed to
  `mmc.exe` with `wbadmin.msc`, so nothing was deleted. The rules alert on the process that does
  the damage, not on the shell that asked for it, so neither run raised a wbadmin alert.

The same exercise found four ways a real export broke the replay reader, since fixed and
covered by tests: files with a UTF-8 byte-order mark, UTF-16 files (what PowerShell 5.1's `>`
writes), unreadable formats reported as a confusing JSON error, and a missing file ending in a
traceback. Reading is now streamed, so the largest file (166 MB) replays in 22 MB of memory.

## How replay evaluates a rule

1. **Read** the file: Windows event XML with one `<Event>` per record (attack_data, `wevtutil`),
   JSON Lines from `evtx_dump -o jsonl`, or already-flat JSON. Each event becomes one flat
   dictionary of System fields (`EventID`, `Channel`, `Computer`, `TimeCreated`) plus its
   EventData fields.
2. **Normalise.** Security 4688 names things differently from Sysmon 1, so it gets the Sysmon
   names that process_creation rules are written against: `NewProcessName` becomes `Image`,
   `ParentProcessName` becomes `ParentImage`, and the account becomes `User`.
3. **Gate by logsource.** A rule only sees the events its Sigma logsource covers. For
   `process_creation` that is Sysmon event 1 and Security event 4688.
4. **Match.** pySigma parses the rule, exactly as the converters will in Phase 2, and replay
   evaluates pySigma's condition tree: `and`, `or`, `not`, `1 of` / `all of`, and the field
   modifiers pySigma turns into wildcards or regular expressions (`contains`, `startswith`,
   `endswith`, `all`, `re`, `cased`), plus numbers and `null`. Strings match case-insensitively,
   as Sigma specifies.
5. **Refuse what it cannot evaluate.** A rule that needs anything else (CIDR, field references,
   keyword searches, a logsource with no mapping yet) is rejected when it is loaded, with its
   path and the reason. It is never silently treated as "no match".

## Live lab (planned)

Not built yet. The plan, from the project brief:

- **VMs:** a Windows Server domain controller, a Windows 11 workstation, a Wazuh manager and a
  Kali attacker, on an isolated host-only network. Comfortable on 32 GB of RAM; on 16 GB, run
  one Windows VM at a time or stay in replay mode, where the detection work is identical.
- **Telemetry:** Sysmon and Windows Security auditing (including process command lines) on
  both Windows machines, shipped by the Wazuh agent.
- **Emulation:** Atomic Red Team only, on snapshotted VMs that nothing else depends on.
- **Versions:** pinned here once installed. The Wazuh 4.14.x line is the target.
