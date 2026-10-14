import argparse
from datetime import timedelta
from pathlib import Path

from .detectors import run_all
from .parser import parse_file
from .report import print_console, summarise, write_charts, write_json, write_markdown


def main() -> None:
    p = argparse.ArgumentParser(prog="log_hunter", description="Detect attacks in OpenSSH auth logs.")
    p.add_argument("logfile", help="path to an sshd log (e.g. /var/log/auth.log)")
    p.add_argument("--year", type=int, default=None,
                   help="year of the first log line (syslog timestamps omit it; default: most recent past date)")
    p.add_argument("--out", default="reports", help="output folder for report, JSON and charts")
    p.add_argument("--threshold", type=int, default=10,
                   help="failed logins from one IP inside the window that count as brute force")
    p.add_argument("--window", type=int, default=5, help="brute-force window in minutes")
    p.add_argument("--spray", type=int, default=5,
                   help="distinct usernames from one IP that count as username spraying")
    args = p.parse_args()

    events = parse_file(args.logfile, args.year)
    alerts = run_all(events, args.threshold, timedelta(minutes=args.window), args.spray)
    summary = summarise(events)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    charts = write_charts(out, events, summary)
    write_json(out / "alerts.json", summary, alerts)
    write_markdown(out / "report.md", summary, alerts, charts, args.logfile)

    print_console(summary, alerts)
    print(f"Report written to {out / 'report.md'} (JSON: {out / 'alerts.json'})")


if __name__ == "__main__":
    main()
