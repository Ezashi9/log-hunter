"""Run every scenario through Log Hunter and score it.

  python -m detection_tests.run              print the results table
  python -m detection_tests.run --write FILE also save it as Markdown
"""
import argparse
from datetime import timedelta
from pathlib import Path

from log_hunter.detectors import run_all
from log_hunter.parser import parse_lines

from .scenarios import build

DEFAULTS = {"bf_threshold": 10, "bf_window": timedelta(minutes=5), "spray_threshold": 5}


def evaluate():
    results = []
    for sc in build():
        events = list(parse_lines(sc.lines, 2020))
        fired = {a.rule for a in run_all(events, **DEFAULTS) if a.severity != "info"}
        missed = sc.expected - fired
        extra = fired - sc.expected
        results.append({
            "scenario": sc, "events": len(events), "fired": fired,
            "missed": missed, "false_positives": extra, "passed": not missed and not extra,
        })
    return results


def to_markdown(results) -> str:
    passed = sum(r["passed"] for r in results)
    lines = [f"**{passed} of {len(results)} scenarios pass.**", "",
             "| Scenario | Expected alerts | Raised | Result |", "|---|---|---|---|"]
    for r in results:
        sc = r["scenario"]
        exp = ", ".join(sorted(sc.expected)) or "none"
        got = ", ".join(sorted(r["fired"])) or "none"
        if r["passed"]:
            verdict = "pass"
        else:
            parts = []
            if r["missed"]:
                parts.append("missed " + ", ".join(sorted(r["missed"])))
            if r["false_positives"]:
                parts.append("false alarm: " + ", ".join(sorted(r["false_positives"])))
            verdict = "**FAIL** (" + "; ".join(parts) + ")"
        lines.append(f"| {sc.name} | {exp} | {got} | {verdict} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--write", help="save the results table to this Markdown file")
    args = p.parse_args()
    results = evaluate()
    md = to_markdown(results)
    print(md)
    for r in results:
        if not r["passed"]:
            print(f"- {r['scenario'].name}: parsed {r['events']} events. {r['scenario'].description}")
    if args.write:
        Path(args.write).write_text(md, encoding="utf-8")


if __name__ == "__main__":
    main()
