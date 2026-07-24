# Part 1 — Authentication Log Analysis

## How to run

```bash
python3 analysis.py --log 4_auth_log.txt
```

`--log` defaults to `4_auth_log.txt` in the current folder, so the script
also runs with no arguments if the log sits next to it. Point `--log` at
any comparable OpenSSH-style log to reuse the script.

## Requirements

- Python 3.10+ (uses `list[str] | None` type hints)
- `matplotlib` (`pip install matplotlib`)
- No other third-party packages

## Input

- A plain-text OpenSSH-style auth log, one event per line, e.g.:
  `Jul 06 00:01:27 backup01 sshd[7878]: Failed password for arun from 198.51.100.24 port 47182 ssh2`

## Outputs (written to `output/`)

| File | Contents |
|---|---|
| `summary_counts.csv` | Count of each event type (failed/accepted password, invalid user, max-auth-exceeded, connection-closed-preauth, session opened/closed, sudo, reverse-DNS break-in warning) |
| `top_source_ips.csv` | Every source IP seen in a `Failed password` line, sorted by count |
| `username_counts.csv` | Every username seen in a `Failed password` line, sorted by count |
| `ip_overlap.csv` | Per-IP failed count, accepted count, whether that IP also appears in `Invalid user` lines, and how many reverse-DNS break-in warnings it triggered — supports checking whether a heavy-failure source ever succeeded, ever tried non-existent accounts, or was independently flagged by sshd itself |
| `daily_failed_summary.csv` | Per-day total failed attempts, split into the top single contributing IP vs. all other sources that day |
| `top_source_ips.png` | Top 10 source IPs by failed password count |
| `chosen_visualisation.png` | Daily timeline of failed attempts, split by top single source vs. all other sources |

## Key decisions Made

- **Failed attempts** are identified by the exact substring `"Failed password"`.
- **Usernames** are extracted with an ordered list of regex patterns (reference `USERNAME_PATTERNS` in `analysis.py`). Ordering — e.g. `Failed password for invalid user X` are checked before the more general `Failed password for X`, otherwise "invalid" would be captured as a username. Lines that don't match any pattern (e.g. `sudo:` lines, `CRON` lines) return `None` and are excluded from username counts.
- **Source IPs** are extracted with a generic IPv4 regex (`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`).
- **Timestamps** have no year, so a single year (`ASSUMED_YEAR = 2026`, set at the top of `analysis.py`) is added to every parsed timestamp. 
- **Unmatched/ambiguous lines**: any line that doesn't match a known event keyword is simply not counted in `summary_counts.csv` (e.g. `CRON` lines beyond session open/close, generic PAM lines).
- **A ninth event type, `possible_break_in_warning`** was added after reconciliation identified 80 unclassified SSHD reverse-DNS lookup warnings. This warning alone does not indicate an intrusion; it is most useful when correlated with other suspicious activity from the same IP.

## Known limitations

- Case-sensitive keyword matching only (no lowercasevariants).
- IPv4 regex only — no IPv6 support.
- Single-host log (`backup01` only) — findings do not generalise to other hosts.
