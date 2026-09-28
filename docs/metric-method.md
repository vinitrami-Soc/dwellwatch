# How the headline metric is measured

The README leads with:

> First alert fired a median of 0.9 minutes before encryption in 6 of 11 replayed ransomware
> runs. No correlated incident was raised before encryption in any of them.

This page says exactly what that measures, how to reproduce it, and what it does not show. The
short version: it measures how early DwellWatch sees ransomware *preparing* to encrypt on the
machine it runs on. It does not yet measure what DwellWatch is built for, which is catching the
help-desk-led intrusion days before that. No public recording holds that chain; the live lab will.

## Reproduce it

```
datasets/fetch.sh --metric                       # the test datasets plus the 11 runs, about 600 MB, hash-checked
python -m dwellwatch.metric --check README.md    # measure every run; fail if the README says otherwise
```

CI runs the same two commands in its `headline metric` job on every push, so the README's
number cannot drift from what the code and data give.

## Definitions

**A run** is one recording from [splunk/attack_data](https://github.com/splunk/attack_data), at
the commit `datasets/fetch.sh` pins, in which ransomware encrypted files. All 11 are listed, with
their labels, in [`datasets/runs.yml`](../datasets/runs.yml). They are every recording at that
commit in which ransomware writes ransom notes into a Sysmon log. The other ransomware recordings
there stop before encryption: Conti's Cobalt Strike session and its leaked tooling, a second
`ransomware_ttp` run, and REvil side-loading its DLL through `MsMpEng.exe`.

**Encryption starts** at the run's first ransom note: the first file written whose path matches
the note's name, by the process that writes the notes. Both are labelled by hand from the events
(for example `ClopReadMe.txt` by `clop.exe`; `readme.txt` by `System` where Conti encrypted a
share over SMB). The note is the proxy because ransomware writes it as it reaches each folder,
and because it is visible in Sysmon's file events. Some families encrypt a folder before writing
its note, so encryption may start a little earlier, which would shorten the leads further.

`metric.measure()` can also use the first stage 6 signal as the start, which is how the project
brief first defined the metric. The headline does not, because that would let a slow stage 6
detection pass for a long lead. DwellWatch's own stage 6 signal came between 0 and 32 seconds after
the first note in 9 runs, and not at all in Prestige (two notes) and REvil's second run (15
folders, under the note-spray count's threshold of 20).

**An alert** is any signal: a Sigma rule firing, or either counter (note sprays, a new source
spreading). **The first alert** is the earliest signal strictly before encryption starts. Signals
that fired on activity that was not the attack are left out; `runs.yml` lists the two, with the
reason for each:

- Clop, run a: Process Monitor, run by whoever recorded the sample, opening LSASS. Counted, it
  would have been the first alert, 23.5 minutes before encryption; it detected the wrong thing.
- Chaos, spreading to root drives: Process Hacker reading LSASS, after encryption had started.

**The lead** is encryption start minus the first alert. **The headline** is the median lead over
the runs that had a first alert (X), out of all runs (Y). Under 10 minutes it is given to a tenth
of a minute.

**An incident** is what [`correlate.py`](../src/dwellwatch/correlate.py) raises: two stages on one
host or account within 24 hours. It is raised at its first signal of a second stage. The
incident line of the headline compares that moment with encryption start, in the same way.

## Results

```
run                               seen  encryption (UTC)     first alert                   lead      encryption seen  incident
Chaos                             yes   2023-01-11 14:21:19  none before encryption        -         4s after         5s after
Chaos, spreading to root drives   no    2023-01-17 10:32:00  none before encryption        -         <1s after        1s after
Clop, run a                       yes   2021-03-16 14:01:44  stage 5, backup destruction   16.5 min  <1s after        <1s after
Clop, run b                       yes   2021-03-12 15:23:10  none before encryption        -         <1s after        none
Conti                             yes   2021-06-04 14:28:29  none before encryption        -         <1s after        none
LockBit                           yes   2023-01-16 11:47:23  stage 3, credential theft     <1s       <1s after        <1s after
Prestige                          yes   2022-11-30 09:43:11  none before encryption        -         none             none
ransomware_ttp, data2             yes   2021-06-21 14:31:28  stage 5, backup destruction   47s       <1s after        <1s after
REvil, run 1                      yes   2021-06-02 08:45:07  stage 5, backup destruction   49.0 min  15s after        15s after
REvil, run 2                      yes   2021-06-04 08:37:18  stage 5, backup destruction   65s       none             none
Ryuk                              yes   2020-11-16 13:24:03  stage 3, credential theft     8s        32s after        32s after
```

`seen` says whether the rules or thresholds were written or tuned with the run in view. "encryption
seen" is when DwellWatch's first stage 6 signal came, relative to the first note; "incident" is
when correlation first raised an incident. The six leads, in order: 0.05 seconds (LockBit's binary
opened LSASS 49 milliseconds before its first note), 8 seconds, 47 seconds, 65 seconds, 16.5
minutes and 49 minutes. Their median is 56 seconds: 0.9 minutes.

## What it does not show

1. **These are detonations, not intrusions.** Each recording starts with the ransomware already on
   the machine, started by whoever ran the lab. The help-desk reset, the remote tooling and the
   lateral movement that make up a real intrusion's dwell time (stages 1, 2 and 4) are not in them.
   What is measured is the ransomware's own last-minute preparation, deleting shadow copies or
   reading LSASS, before its first file. A median under a minute is what that looks like.
2. **The rules were shaped by these runs.** Ten of the 11 were used when the rules and the note
   spray's threshold were written or tuned (as unseen data first, then to fix what they showed).
   Only "Chaos, spreading to root drives" was never looked at before being measured; on it,
   nothing fired before encryption, and the note spray fired 0.7 seconds after the first note.
3. **Eleven runs is a small sample**, from seven families, three of them twice. One run more or
   less moves the median a long way: it sits between 47 and 65 seconds, with 16.5 and 49 minutes
   above them.
4. **The times are the recordings' own.** Each lead is the difference between two event times in
   one recording, taken from that lab machine's clock, so it is time that really passed there.
   Runs come from different labs and years and are never put on one timeline. Replay also skips
   everything between an event and an analyst: shipping, SIEM ingestion and alerting delay add
   seconds to minutes in a live deployment, which the live lab will measure.
5. **No incident before encryption, in any run.** Before encryption each run shows at most one
   stage (backup destruction or credential theft), so correlation, which needs two, has to wait
   for encryption itself. That is the expected result for detonations and the reason the brief's
   earlier stages exist: an intrusion's reset, discovery and lateral movement are what would give
   correlation its second stage hours or days ahead.

## The full chain

The brief asks for the full chain to be run in replay. There is no public recording of the
help-desk-led chain end to end, and building one by stitching single-technique recordings onto a
timeline would mean choosing both the timing, which is the thing measured, and the hosts and
accounts that link the stages, which is what correlation is judged on. So it is not done: the
number above comes only from recordings as they happened. The chain is checked on planted events
in the tests (correlation's case (d), and `test_metric.py`'s full chain), which shows that the
pieces fit together, not how early they fire. The live lab's emulated chain, run with Atomic Red
Team on snapshotted VMs after a baseline of ordinary days, is where the full-chain number will come
from; this page will then gain a second table, and the README's line a second number.
