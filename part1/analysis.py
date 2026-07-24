"""
analysis.py
CSC3106 Mini-Project Part 1 - Data-Driven Authentication Log Analysis

Reads a raw OpenSSH-style auth log, extracts authentication events,
usernames and source IPs, saves summary CSVs, and produces the two
required visualisations:
    1. output/top_source_ips.png      - top source IPs by failed auth (mandatory)
    2. output/chosen_visualisation.png - daily timeline of failed attempts,
                                          split by top single source vs all others

Design follows the Lab 1-4 techniques:
    - manual-inspection-informed regex patterns (Lab 1)
    - keyword event counting + IP/username regex extraction (Lab 2)
    - timestamp parsing + time-windowed timeline (Lab 3)
    - CSV outputs structured to feed directly into the asset-focused
      risk matrix (Lab 4)

Usage:
    python analysis.py                      # uses default LOG_FILE below
    python analysis.py --log path/to/log     # or point at any comparable log
"""

import re
import csv
import argparse
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")  # headless-safe backend, no display needed
import matplotlib.pyplot as plt

# --------------------------------------------------------------------------
# CONFIGURATION (kept at the top so a reviewer can adapt this to a
# comparable log without touching the logic below)
# --------------------------------------------------------------------------

DEFAULT_LOG_FILE = "4_auth_log.txt"
OUTPUT_DIR = Path("output")

# This teaching log omits the year in its timestamps (e.g. "Jul 06 00:01:27").
# Python still needs a year internally to parse and sort timestamps, so this
# assumed year is used ONLY inside datetime objects. Report-facing outputs
# and figure labels intentionally omit the year to match the raw log format.
# It will be WRONG if the real log spans a year boundary (e.g. Dec -> Jan).
ASSUMED_YEAR = 2026

TOP_N_IPS = 10  # how many source IPs to show in the mandatory bar chart

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Username extraction patterns, IN PRIORITY ORDER. Order matters:
# more specific patterns (e.g. "invalid user") must be tried before the
# more general ones, otherwise a word like "invalid" would be captured
# as the username. Patterns below were chosen after manually inspecting
# this log's actual message formats (Lab 1, Technique 1).
USERNAME_PATTERNS = [
    r"Failed password for invalid user (\S+) from",
    r"Failed password for (\S+) from",
    r"Invalid user (\S+) from",
    r"Accepted password for (\S+) from",
    r"session opened for user (\S+)",
    r"session closed for user (\S+)",
    r"maximum authentication attempts exceeded for (\S+) from",
    r"Connection closed by authenticating user (\S+)",
]

# Event classification. Each event type maps to substrings that identify it.
# A single log line may match more than one category; counts are
# independent tallies of phrase occurrences, not a guarantee of unique
# incidents (see Lab 2 "Critical limitation").
EVENT_KEYWORDS = {
    "failed_password":        ["Failed password"],
    "accepted_password":      ["Accepted password"],
    "invalid_user":           ["Invalid user"],
    "max_auth_exceeded":      ["maximum authentication attempts exceeded"],
    "connection_closed_preauth": ["Connection closed by authenticating user"],
    "session_opened":         ["session opened"],
    "session_closed":         ["session closed"],
    "sudo_command":           ["sudo:"],
    # sshd's own reverse-DNS (PTR) sanity check: logged whenever the
    # connecting IP's reverse lookup fails, independent of any password
    # attempt on that connection. Not on its own evidence of compromise -
    # a missing PTR record is common and non-malicious - but a second,
    # independent signal worth cross-referencing against failed/accepted
    # logins from the same IP.
    "possible_break_in_warning": ["POSSIBLE BREAK-IN ATTEMPT"],
}

# Pulls the IP out of "...getaddrinfo for unknown.example [IP] failed..."
BREAK_IN_WARNING_IP_PATTERN = re.compile(r"getaddrinfo for \S+ \[([\d.]+)\] failed")


# --------------------------------------------------------------------------
# EXTRACTION HELPERS
# --------------------------------------------------------------------------

def read_log(path: Path) -> list[str]:
    """Read the raw log file and return a list of lines (no trailing newlines).
    Assumes UTF-8 encoding and one event per line, consistent with Lab 1/2.
    """
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def extract_ips(line: str) -> list[str]:
    """Return all IPv4-looking addresses found on the line.
    Note: this is a syntactic match only - it does not validate octet
    ranges (0-255) and will not detect IPv6 addresses (Lab 2 limitation).
    """
    return IP_PATTERN.findall(line)


def extract_username(line: str) -> str | None:
    """Try each username pattern in priority order; return the first match.
    Returns None if no pattern matches, so unmatched lines (sudo lines,
    CRON lines, etc.) are explicitly excluded rather than silently
    mis-attributed (Lab 2, Technique 8).
    """
    for pattern in USERNAME_PATTERNS:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None


def extract_timestamp(line: str, year: int = ASSUMED_YEAR) -> datetime | None:
    """Parse the first three space-separated tokens (e.g. 'Jul 06 00:01:27')
    into a datetime, adding an internal assumed year only because Python
    needs one for sorting/bucketing. The year is not shown in report-facing
    CSV date labels or figure axes.

    Returns None on any line that doesn't match this format, so the caller
    can skip it rather than crash (Lab 3, Technique 2).
    """
    parts = line.split(maxsplit=3)
    if len(parts) < 3:
        return None
    month, day, time_str = parts[0], parts[1], parts[2]
    try:
        return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def format_log_day(ts: datetime) -> str:
    """Return a display label that matches the raw log style and omits year.
    Example: datetime(2026, 7, 6) -> 'Jul 06'.
    """
    return ts.strftime("%b %d")


def classify_events(lines: list[str]) -> dict[str, int]:
    """Count occurrences of each known event type across the log."""
    counts = {key: 0 for key in EVENT_KEYWORDS}
    for line in lines:
        for event_type, keywords in EVENT_KEYWORDS.items():
            if any(keyword in line for keyword in keywords):
                counts[event_type] += 1
    return counts


# --------------------------------------------------------------------------
# OUTPUT HELPERS
# --------------------------------------------------------------------------

def save_counter_to_csv(counter: Counter, output_path: Path, header1: str, header2: str) -> None:
    """Save a Counter to CSV, most common first (Lab 2, Technique 10)."""
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([header1, header2])
        for item, count in counter.most_common():
            writer.writerow([item, count])


def save_summary_counts(event_counts: dict[str, int], output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["event_type", "count"])
        for event_type, count in event_counts.items():
            writer.writerow([event_type, count])


# --------------------------------------------------------------------------
# VISUALISATIONS
# --------------------------------------------------------------------------

def plot_top_source_ips(failed_ip_counts: Counter, output_path: Path, top_n: int = TOP_N_IPS) -> None:
    """MANDATORY visualisation: top source IPs by failed authentication attempts."""
    top_items = failed_ip_counts.most_common(top_n)
    if not top_items:
        return
    ips, counts = zip(*top_items)

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(ips, counts, color="#c0392b")
    ax.set_title("Top Source IPs by Failed Authentication Attempts")
    ax.set_xlabel("Source IP")
    ax.set_ylabel("Failed password attempts")
    ax.tick_params(axis="x", rotation=45)
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(count),
                ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)


def plot_daily_timeline(lines: list[str], output_path: Path) -> dict:
    """CHOSEN visualisation: daily timeline of failed password attempts,
    split into (a) the single largest contributing source IP that day and
    (b) all other sources combined that day.

    Time window = 1 calendar day. This is a methodological choice (Lab 3,
    Technique 3): a daily window is coarse enough to show which days carry
    unusually high failure volume, at the cost of hiding *when within the
    day* those attempts happened (a finer window, e.g. hourly, would be
    needed for that - see README limitations).

    The split into "top single IP" vs "other sources" is computed
    dynamically per day (not hard-coded to specific IP addresses), so this
    script generalises to any comparable log without editing IP values.

    Returns a dict of per-day stats, used to also write a supporting CSV.
    """
    # Use datetime.date keys internally for correct sorting, but display
    # labels without year so the output matches the raw log format.
    daily_ip_counts: dict[datetime.date, Counter] = defaultdict(Counter)

    for line in lines:
        if "Failed password" not in line:
            continue
        ts = extract_timestamp(line)
        if ts is None:
            continue
        day_key = ts.date()
        for ip in extract_ips(line):
            daily_ip_counts[day_key][ip] += 1

    day_keys = sorted(daily_ip_counts.keys())
    day_labels = [format_log_day(datetime.combine(day, datetime.min.time())) for day in day_keys]
    top_ip_values, other_values, top_ip_labels = [], [], []

    for day in day_keys:
        counter = daily_ip_counts[day]
        if not counter:
            top_ip_values.append(0)
            other_values.append(0)
            top_ip_labels.append("")
            continue
        top_ip, top_count = counter.most_common(1)[0]
        total = sum(counter.values())
        top_ip_values.append(top_count)
        other_values.append(total - top_count)
        top_ip_labels.append(top_ip)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(day_labels, top_ip_values, label="Top single source IP that day", color="#c0392b")
    ax.bar(day_labels, other_values, bottom=top_ip_values, label="All other sources combined", color="#7f8c8d")
    ax.set_title("Failed Password Attempts per Day\n(split: top single source vs. all other sources)")
    ax.set_xlabel("Log date (month/day only; year omitted in raw log)")
    ax.set_ylabel("Failed password attempts")
    ax.tick_params(axis="x", rotation=45)
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)

    return {
        "day_labels": day_labels,
        "top_ip_values": top_ip_values,
        "other_values": other_values,
        "top_ip_labels": top_ip_labels,
    }


def save_daily_timeline_csv(timeline_stats: dict, output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["log_day", "top_source_ip", "top_source_failed_count", "other_sources_failed_count", "total_failed"])
        for day_label, top_ip, top_val, other_val in zip(
            timeline_stats["day_labels"], timeline_stats["top_ip_labels"],
            timeline_stats["top_ip_values"], timeline_stats["other_values"]
        ):
            writer.writerow([day_label, top_ip, top_val, other_val, top_val + other_val])


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Analyse an OpenSSH-style auth log.")
    parser.add_argument("--log", default=DEFAULT_LOG_FILE, help="Path to the raw log file")
    args = parser.parse_args()

    log_path = Path(args.log)
    OUTPUT_DIR.mkdir(exist_ok=True)

    lines = read_log(log_path)
    print(f"Read {len(lines)} lines from {log_path}")

    # --- Event counting ---
    event_counts = classify_events(lines)
    save_summary_counts(event_counts, OUTPUT_DIR / "summary_counts.csv")

    # --- IP extraction ---
    failed_ip_counts = Counter()
    accepted_ip_counts = Counter()
    invalid_user_ip_counts = Counter()
    break_in_warning_ip_counts = Counter()
    for line in lines:
        ips = extract_ips(line)
        if "Failed password" in line:
            for ip in ips:
                failed_ip_counts[ip] += 1
        if "Accepted password" in line:
            for ip in ips:
                accepted_ip_counts[ip] += 1
        if "Invalid user" in line:
            for ip in ips:
                invalid_user_ip_counts[ip] += 1
        if "POSSIBLE BREAK-IN ATTEMPT" in line:
            match = BREAK_IN_WARNING_IP_PATTERN.search(line)
            if match:
                break_in_warning_ip_counts[match.group(1)] += 1

    save_counter_to_csv(failed_ip_counts, OUTPUT_DIR / "top_source_ips.csv", "ip_address", "failed_password_count")

    # --- Username extraction (from Failed password lines only) ---
    failed_username_counts = Counter()
    for line in lines:
        if "Failed password" in line:
            user = extract_username(line)
            if user:
                failed_username_counts[user] += 1
    save_counter_to_csv(failed_username_counts, OUTPUT_DIR / "username_counts.csv", "username", "failed_password_count")

    # --- Overlap check: which failed-IPs ever succeeded? (Lab 2, Technique 9 style) ---
    overlap_ips = set(failed_ip_counts) & set(accepted_ip_counts)
    with open(OUTPUT_DIR / "ip_overlap.csv", "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "ip_address", "failed_count", "accepted_count",
            "also_in_invalid_user_lines", "reverse_dns_breakin_warnings",
        ])
        for ip in sorted(failed_ip_counts, key=lambda k: -failed_ip_counts[k]):
            writer.writerow([
                ip, failed_ip_counts[ip], accepted_ip_counts.get(ip, 0),
                "yes" if ip in invalid_user_ip_counts else "no",
                break_in_warning_ip_counts.get(ip, 0),
            ])

    # --- Visualisation 1 (mandatory) ---
    plot_top_source_ips(failed_ip_counts, OUTPUT_DIR / "top_source_ips.png")

    # --- Visualisation 2 (chosen) ---
    timeline_stats = plot_daily_timeline(lines, OUTPUT_DIR / "chosen_visualisation.png")
    save_daily_timeline_csv(timeline_stats, OUTPUT_DIR / "daily_failed_summary.csv")

    # --- Console summary for quick sanity-check ---
    print("\nEvent counts:", event_counts)
    print("\nTop 5 source IPs by failed password count:")
    for ip, count in failed_ip_counts.most_common(5):
        print(f"  {ip}: {count}")
    print("\nIPs with both failed AND accepted logins:", overlap_ips)
    print(f"\nOutputs written to: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
