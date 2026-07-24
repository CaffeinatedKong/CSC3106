"""
analysis.py
CSC3106 Mini-Project Part 1 - Data-Driven Authentication Log Analysis

Reads a raw OpenSSH-style auth log, extracts authentication events,
usernames and source IPs, saves summary CSVs, and produces the two
required visualisations:
    1. output/top_source_ips.png      - top source IPs by failed auth
    2. output/chosen_visualisation.png - daily timeline of failed attempts, split by top single source vs all others
"""

import re
import csv
import argparse
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# --------------------------------------------------------------------------
# CONFIGURATION 
# --------------------------------------------------------------------------

DEFAULT_LOG_FILE = "4_auth_log.txt"
OUTPUT_DIR = Path("output")
ASSUMED_YEAR = 2026

TOP_N_IPS = 10  # Max source IPs to show in the mandatory bar chart

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Username extraction patterns
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

# Event classification
EVENT_KEYWORDS = {
    "failed_password":        ["Failed password"],
    "accepted_password":      ["Accepted password"],
    "invalid_user":           ["Invalid user"],
    "max_auth_exceeded":      ["maximum authentication attempts exceeded"],
    "connection_closed_preauth": ["Connection closed by authenticating user"],
    "session_opened":         ["session opened"],
    "session_closed":         ["session closed"],
    "sudo_command":           ["sudo:"],
    "possible_break_in_warning": ["POSSIBLE BREAK-IN ATTEMPT"],
}

# Regex to extract the IP out of log
BREAK_IN_WARNING_IP_PATTERN = re.compile(r"getaddrinfo for \S+ \[([\d.]+)\] failed")


# --------------------------------------------------------------------------
# EXTRACTION HELPERS
# --------------------------------------------------------------------------

def read_log(path: Path) -> list[str]:
    # Read the raw log file
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def extract_ips(line: str) -> list[str]:
    # Return all IPv4-looking addresses
    return IP_PATTERN.findall(line)


def extract_username(line: str) -> str | None:
    # Return the first username found in the line, or None if no match.
    for pattern in USERNAME_PATTERNS:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None


def extract_timestamp(line: str, year: int = ASSUMED_YEAR) -> datetime | None:
    """Parse the first three space-separated tokens (e.g. 'Jul 06 00:01:27')
    into a datetime. Return None if failed.
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
    """ Convert Datetime to date string E.g datetime(2026, 7, 6) -> 'Jul 06' """
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
    """Save a Counter to CSV """
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
    """ Visualisation 1: top source IPs by failed authentication attempts """
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
    split into:
       (a) the single largest contributing source IP that day and
       (b) all other sources combined that day.
    """
    # Use datetime.date keys for sorting
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

    # Event counting
    event_counts = classify_events(lines)
    save_summary_counts(event_counts, OUTPUT_DIR / "summary_counts.csv")

    # IP extraction
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

    # Username extraction
    failed_username_counts = Counter()
    for line in lines:
        if "Failed password" in line:
            user = extract_username(line)
            if user:
                failed_username_counts[user] += 1
    save_counter_to_csv(failed_username_counts, OUTPUT_DIR / "username_counts.csv", "username", "failed_password_count")

    # Check which failed-IPs ever succeeded?
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

    # Visualisation 1: Top Source IPs
    plot_top_source_ips(failed_ip_counts, OUTPUT_DIR / "top_source_ips.png")

    # Visualisation 2: Chosen Visualisation 
    timeline_stats = plot_daily_timeline(lines, OUTPUT_DIR / "chosen_visualisation.png")
    save_daily_timeline_csv(timeline_stats, OUTPUT_DIR / "daily_failed_summary.csv")

    # Summary Checks
    print("\nEvent counts:", event_counts)
    print("\nTop 5 source IPs by failed password count:")
    for ip, count in failed_ip_counts.most_common(5):
        print(f"  {ip}: {count}")
    print("\nIPs with both failed AND accepted logins:", overlap_ips)
    print(f"\nOutputs written to: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
