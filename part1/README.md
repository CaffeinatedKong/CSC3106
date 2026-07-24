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
- Assumed UTF-8 encoded, one event per line, no year in the timestamp.

## Outputs (written to `output/`)

| File | Contents |
|---|---|
| `summary_counts.csv` | Count of each event type (failed/accepted password, invalid user, max-auth-exceeded, connection-closed-preauth, session opened/closed, sudo, reverse-DNS break-in warning) |
| `top_source_ips.csv` | Every source IP seen in a `Failed password` line, sorted by count |
| `username_counts.csv` | Every username seen in a `Failed password` line, sorted by count |
| `ip_overlap.csv` | Per-IP failed count, accepted count, whether that IP also appears in `Invalid user` lines, and how many reverse-DNS break-in warnings it triggered — supports checking whether a heavy-failure source ever succeeded, ever tried non-existent accounts, or was independently flagged by sshd itself |
| `daily_failed_summary.csv` | Per-day total failed attempts, split into the top single contributing IP vs. all other sources that day |
| `top_source_ips.png` | **Mandatory visualisation** — top 10 source IPs by failed password count |
| `chosen_visualisation.png` | **Chosen visualisation** — daily timeline of failed attempts, split by top single source vs. all other sources |

## Key decisions

- **Failed attempts** are identified by the exact substring `"Failed password"`. This is case-sensitive and specific to OpenSSH's default phrasing; a different daemon or a lower-case variant would be missed silently.
- **Usernames** are extracted with an ordered list of regex patterns (see `USERNAME_PATTERNS` in `analysis.py`). Order matters — e.g. `Failed password for invalid user X` must be checked before the more general `Failed password for X`, otherwise "invalid" would be captured as a username. Lines that don't match any pattern (e.g. `sudo:` lines, `CRON` lines) return `None` and are excluded from username counts rather than guessed.
- **Source IPs** are extracted with a generic IPv4 regex (`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`). This does not validate octet ranges (0–255) and does not distinguish which *field* the IP came from — it will match any dotted-decimal-looking string on the line. In this log, IPs only ever appear in the source-address position, so this hasn't caused any observed false positives, but it isn't guaranteed for a different log.
- **The `port` field is the client's ephemeral source port** (values observed up to ~65000), not the server's SSH listening port. The log contains no field indicating which port `sshd` was listening on — this is a limitation to flag if a report references "SSH port" security.
- **Timestamps** have no year, so a single year (`ASSUMED_YEAR = 2026`, set at the top of `analysis.py`) is added to every parsed timestamp. This will be wrong if the real log spans a year boundary — not the case here since the log covers `Jul 06`–`Jul 12` only.
- **Unmatched/ambiguous lines**: any line that doesn't match a known event keyword is simply not counted in `summary_counts.csv` (e.g. `CRON` lines beyond session open/close, generic PAM lines). They are still present in the raw line count printed to the console, so nothing is silently dropped from the file — only from specific counters.
- **Event counts are phrase occurrences, not guaranteed unique incidents.** A repeated or duplicated log entry would be counted twice.
- **A ninth event type, `possible_break_in_warning`, was added after a reconciliation check.** Summing the original 8 event-type counts against the total line count left 80 lines unaccounted for. Inspecting them showed they were all sshd's own reverse-DNS (PTR lookup) sanity check — `reverse mapping checking getaddrinfo for unknown.example [IP] failed - POSSIBLE BREAK-IN ATTEMPT!` — a line type not anticipated from the Lab 1–2 teaching log, which didn't include it. This is now a tracked category, and `sum(summary_counts.csv counts) == total line count` (12,000) can be used as a standing sanity check when adapting this script to a different log. **Interpretation caveat:** this warning is sshd's built-in heuristic and fires on any failed reverse-DNS lookup — it is not on its own evidence of an intrusion (many legitimate hosts lack a PTR record). It is meaningful mainly as a second, independent signal when it coincides with other suspicious activity from the same IP (see `ip_overlap.csv`).

## Known limitations

- Case-sensitive keyword matching only (no lowercase/alternate-daemon variants).
- IPv4 regex only — no IPv6 support.
- No octet-range validation on IPs.
- Daily time window in the chosen visualisation is a methodological choice — it shows which *days* carry unusual volume but hides *when within the day* those attempts happened. An hourly window would show that instead, at the cost of a noisier chart.
- Single-host log (`backup01` only) — findings do not generalise to other hosts.
