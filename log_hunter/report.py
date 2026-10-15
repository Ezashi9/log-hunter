import json
from collections import Counter
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

from .detectors import Alert
from .parser import Event

SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


def summarise(events: list[Event]) -> dict:
    failed = [e for e in events if e.kind == "failed"]
    times = [e.time for e in events]
    return {
        "events_parsed": len(events),
        "first_event": min(times).isoformat() if times else None,
        "last_event": max(times).isoformat() if times else None,
        "failed_logins": len(failed),
        "successful_logins": sum(e.kind == "accepted" for e in events),
        "unique_attacking_ips": len({e.ip for e in failed}),
        "top_attacking_ips": Counter(e.ip for e in failed).most_common(10),
        "top_targeted_usernames": Counter(e.user for e in failed if e.user).most_common(10),
        "failed_on_nonexistent_accounts": sum(e.invalid_user for e in failed),
        "failed_logins_timeline": _timeline(failed, timedelta(minutes=10)),
    }


def _timeline(failed: list[Event], bucket: timedelta) -> list[list]:
    """Failed logins per bucket, including empty buckets so quiet periods show as zero."""
    if not failed:
        return []
    start = min(e.time for e in failed)
    counts = Counter(int((e.time - start) / bucket) for e in failed)
    return [[(start + bucket * i).isoformat(), counts.get(i, 0)] for i in range(max(counts) + 1)]


def print_console(summary: dict, alerts: list[Alert]) -> None:
    print(f"\nParsed {summary['events_parsed']} security events "
          f"({summary['first_event']} -> {summary['last_event']})")
    print(f"  Failed logins:      {summary['failed_logins']} "
          f"({summary['failed_on_nonexistent_accounts']} on accounts that don't exist)")
    print(f"  Successful logins:  {summary['successful_logins']}")
    print(f"  Attacking IPs:      {summary['unique_attacking_ips']}\n")

    for a in sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], -a.count)):
        attack = f" [{', '.join(a.attack_ids)}]" if a.attack_ids else ""
        print(f"[{a.severity.upper():6}] {a.rule:22} {a.ip:16} {a.detail}{attack}")
    print()


def write_json(path: Path, summary: dict, alerts: list[Alert]) -> None:
    def encode(a: Alert) -> dict:
        d = asdict(a)
        d["first_seen"] = a.first_seen.isoformat()
        d["last_seen"] = a.last_seen.isoformat()
        return d

    flagged_ips = sorted({a.ip for a in alerts if a.severity != "info"})
    path.write_text(json.dumps({
        "summary": summary,
        "flagged_ips": flagged_ips,
        "alerts": [encode(a) for a in alerts],
    }, indent=2), encoding="utf-8")


def write_charts(out_dir: Path, events: list[Event], summary: dict) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return []

    made = []
    failed = [e for e in events if e.kind == "failed"]

    if failed:
        bucket = timedelta(minutes=10)
        start = min(e.time for e in failed)
        counts = Counter(int((e.time - start) / bucket) for e in failed)
        xs = range(max(counts) + 1)
        labels = [(start + bucket * i).strftime("%H:%M") for i in xs]
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.bar(labels, [counts.get(i, 0) for i in xs], color="#c0392b")
        ax.set_title("Failed SSH logins per 10 minutes")
        ax.set_ylabel("Failed logins")
        ax.tick_params(axis="x", rotation=45)
        step = max(1, len(labels) // 15)
        for i, lbl in enumerate(ax.get_xticklabels()):
            lbl.set_visible(i % step == 0)
        fig.tight_layout()
        fig.savefig(out_dir / "failed_logins_over_time.png", dpi=120)
        plt.close(fig)
        made.append("failed_logins_over_time.png")

    for key, title, fname, colour in (
        ("top_attacking_ips", "Top attacking IPs (failed logins)", "top_ips.png", "#2c3e50"),
        ("top_targeted_usernames", "Most-targeted usernames", "top_usernames.png", "#8e44ad"),
    ):
        rows = summary[key]
        if not rows:
            continue
        names, values = zip(*reversed(rows))
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.barh(names, values, color=colour)
        ax.set_title(title)
        ax.set_xlabel("Failed logins")
        fig.tight_layout()
        fig.savefig(out_dir / fname, dpi=120)
        plt.close(fig)
        made.append(fname)

    return made


def write_markdown(path: Path, summary: dict, alerts: list[Alert], charts: list[str], source: str) -> None:
    lines = [
        "# Log Hunter report",
        "",
        f"**Source:** `{source}`  ",
        f"**Period:** {summary['first_event']} to {summary['last_event']}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Security events parsed | {summary['events_parsed']} |",
        f"| Failed logins | {summary['failed_logins']} |",
        f"| ...on accounts that don't exist | {summary['failed_on_nonexistent_accounts']} |",
        f"| Successful logins | {summary['successful_logins']} |",
        f"| Unique attacking IPs | {summary['unique_attacking_ips']} |",
        "",
        "## Alerts",
        "",
        "| Severity | Rule | ATT&CK | IP | Detail | First seen | Last seen |",
        "|---|---|---|---|---|---|---|",
    ]
    for a in sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], -a.count)):
        attack = ", ".join(a.attack_ids) or "-"
        lines.append(f"| {a.severity} | {a.rule} | {attack} | {a.ip} | {a.detail} | "
                     f"{a.first_seen:%Y-%m-%d %H:%M:%S} | {a.last_seen:%Y-%m-%d %H:%M:%S} |")

    lines += ["", "## Most-targeted usernames", "", "| Username | Failed attempts |", "|---|---|"]
    lines += [f"| {u} | {n} |" for u, n in summary["top_targeted_usernames"]]

    if charts:
        lines += ["", "## Charts", ""]
        lines += [f"![{c}]({c})" for c in charts]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
