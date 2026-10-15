"""Labelled test scenarios: synthetic sshd log lines with a known right answer.

Each scenario says which alert rules SHOULD fire. Anything else that fires
(other than info-level clean_login) counts as a false positive.
All IPs are from documentation ranges (RFC 5737 / RFC 3849), so none belong to anyone.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta

BASE = datetime(2020, 12, 10, 10, 0, 0)


@dataclass
class Scenario:
    name: str
    description: str
    lines: list[str]
    expected: set[str]


def _ts(t: datetime) -> str:
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S}"


def failed(t: datetime, ip: str, user: str = "root", invalid: bool = False, pid: int = 1000) -> str:
    who = f"invalid user {user}" if invalid else user
    return f"{_ts(t)} server sshd[{pid}]: Failed password for {who} from {ip} port 52000 ssh2"


def accepted(t: datetime, ip: str, user: str, pid: int = 2000) -> str:
    return f"{_ts(t)} server sshd[{pid}]: Accepted password for {user} from {ip} port 52001 ssh2"


def every(start: datetime, step: timedelta, n: int) -> list[datetime]:
    return [start + step * i for i in range(n)]


def build() -> list[Scenario]:
    s = []

    s.append(Scenario(
        "Fast brute force",
        "One IP makes 30 password guesses against root in 60 seconds.",
        [failed(t, "203.0.113.10") for t in every(BASE, timedelta(seconds=2), 30)],
        {"brute_force"},
    ))

    s.append(Scenario(
        "Real user, two typos",
        "A user mistypes their password twice, then logs in. Should raise no alert.",
        [failed(BASE, "198.51.100.20", "alice"), failed(BASE + timedelta(seconds=20), "198.51.100.20", "alice"),
         accepted(BASE + timedelta(seconds=40), "198.51.100.20", "alice")],
        set(),
    ))

    s.append(Scenario(
        "Real user, typos spread over a week",
        "Three typos on different days, then a normal login a week later. Should raise no alert.",
        [failed(BASE - timedelta(days=7), "198.51.100.21", "bob"),
         failed(BASE - timedelta(days=4), "198.51.100.21", "bob"),
         failed(BASE - timedelta(days=2), "198.51.100.21", "bob"),
         accepted(BASE, "198.51.100.21", "bob")],
        set(),
    ))

    s.append(Scenario(
        "Low and slow brute force",
        "One IP guesses once every 2 minutes for 80 minutes (40 attempts), staying under 10 per 5 minutes.",
        [failed(t, "203.0.113.11") for t in every(BASE, timedelta(minutes=2), 40)],
        {"brute_force"},
    ))

    s.append(Scenario(
        "Distributed brute force",
        "20 different IPs each try the admin account twice within 10 minutes. No single IP looks suspicious.",
        [failed(BASE + timedelta(seconds=15 * i + j), f"192.0.2.{i + 1}", "admin")
         for i in range(20) for j in (0, 5)],
        {"distributed_brute_force"},
    ))

    s.append(Scenario(
        "Username spraying",
        "One IP tries 8 different non-existent accounts, once each.",
        [failed(BASE + timedelta(seconds=10 * i), "203.0.113.12", u, invalid=True)
         for i, u in enumerate(["oracle", "test", "ubuntu", "git", "postgres", "deploy", "pi", "support"])],
        {"username_spray"},
    ))

    s.append(Scenario(
        "IPv6 brute force",
        "The fast brute force again, from an IPv6 address.",
        [failed(t, "2001:db8::bad:1") for t in every(BASE, timedelta(seconds=2), 30)],
        {"brute_force"},
    ))

    s.append(Scenario(
        "Compressed log lines",
        "syslog squashes repeats: 2 lines saying 'message repeated 6 times' hide 12 failures.",
        [f"{_ts(BASE)} server sshd[1000]: message repeated 6 times: [ Failed password for root from 203.0.113.13 port 52000 ssh2]",
         f"{_ts(BASE + timedelta(seconds=30))} server sshd[1000]: message repeated 6 times: [ Failed password for root from 203.0.113.13 port 52000 ssh2]"],
        {"brute_force"},
    ))

    weird = ["  root", "<script>alert(1)</script>", "admin;rm -rf /", "用户", "x" * 200, "' OR '1'='1"]
    s.append(Scenario(
        "Attacker-crafted usernames",
        "Usernames with spaces, HTML, shell characters, Unicode and very long strings. Parser must not crash or drop them.",
        [failed(BASE + timedelta(seconds=i), "203.0.113.14", u, invalid=True) for i, u in enumerate(weird)],
        {"username_spray"},
    ))

    s.append(Scenario(
        "Successful break-in",
        "15 fast guesses against root, then a successful login from the same IP.",
        [failed(t, "203.0.113.15") for t in every(BASE, timedelta(seconds=3), 15)]
        + [accepted(BASE + timedelta(seconds=50), "203.0.113.15", "root")],
        {"brute_force", "success_after_failure"},
    ))

    return s
