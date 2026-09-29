# Run notes

One file per emulated run, named for its date (`2026-10-02-run-1.md`), so every number the metric
reports can be traced to what was run, when, and on what. The metric's lead times come from these
times, so write them down as you go, in UTC.

Run tests only on the lab VM ([docs/lab-architecture.md](../docs/lab-architecture.md#live-lab)),
from a snapshot, with the internet cut, and read each test before running it, as Red Canary asks.

## Template

```markdown
# Run <n>, <date>

- Snapshot restored: `clean` / `ready`
- Box and version (`vagrant box list`):
- Sysmon version (printed by provisioning):
- Invoke-AtomicRedTeam version, and the atomics commit:
- Baseline export used:

| Stage | ATT&CK | Atomic test (GUID) | Started (UTC) | Finished (UTC) | Notes |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 5 | | | | | |
| 6 | T1486 | | | | against `C:\Shares\Finance` only |

- Export folder: `lab/exports/<time>/`
- `python -m dwellwatch.correlate` output: signals, incidents, first stage to fire
- Anything that did not go as planned:
```
