import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<msg>.*)$"
)

# Source addresses can be IPv4 or IPv6: an IPv4-only pattern silently drops IPv6 attackers.
# Usernames are attacker-controlled and can contain spaces, so match lazily up to " from <ip>".
FAILED_RE = re.compile(
    r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+"
)
INVALID_USER_RE = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>[0-9A-Fa-f:.]+)")
# syslog collapses identical lines into one "message repeated N times" line.
REPEATED_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[ (?P<inner>.*)\]$")
BREAKIN_RE = re.compile(
    r"reverse mapping checking getaddrinfo for \S+ \[(?P<ip>[0-9A-Fa-f:.]+)\] failed - POSSIBLE BREAK-IN ATTEMPT!"
)


@dataclass(frozen=True)
class Event:
    time: datetime
    kind: str  # "failed" | "accepted" | "invalid_user" | "breakin_warning"
    ip: str
    user: Optional[str] = None
    method: Optional[str] = None
    invalid_user: bool = False


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> Iterator[Event]:
    # Syslog timestamps have no year, so roll it forward when the month wraps (Dec -> Jan).
    last_month = None
    for raw in lines:
        m = LINE_RE.match(raw.rstrip("\n"))
        if not m:
            continue
        if year is None:
            year = _guess_year(m["ts"])
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
        if last_month is not None and ts.month < last_month:
            year += 1
            ts = ts.replace(year=year)
        last_month = ts.month

        msg, repeats = m["msg"], 1
        if r := REPEATED_RE.match(msg):
            msg, repeats = r["inner"], int(r["n"])
        event = _classify(msg, ts)
        if event:
            for _ in range(repeats):
                yield event


def _classify(msg: str, ts: datetime) -> Optional[Event]:
    if m := FAILED_RE.search(msg):
        return Event(ts, "failed", m["ip"], m["user"], m["method"], bool(m["invalid"]))
    if m := ACCEPTED_RE.search(msg):
        return Event(ts, "accepted", m["ip"], m["user"], m["method"])
    if m := INVALID_USER_RE.search(msg):
        return Event(ts, "invalid_user", m["ip"], m["user"], invalid_user=True)
    if m := BREAKIN_RE.search(msg):
        return Event(ts, "breakin_warning", m["ip"])
    return None


def _guess_year(ts: str) -> int:
    # Logs describe the past, so if this year's date would be in the future it was last year.
    now = datetime.now()
    year = now.year
    while True:
        try:
            candidate = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
        except ValueError:  # Feb 29 in a non-leap year
            year -= 1
            continue
        if candidate <= now:
            return year
        year -= 1


def parse_file(path: str, year: Optional[int] = None) -> list[Event]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return list(parse_lines(f, year))
