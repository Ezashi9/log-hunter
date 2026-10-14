from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parser import Event


@dataclass
class Alert:
    rule: str
    severity: str  # "high" | "medium" | "info"
    ip: str
    first_seen: datetime
    last_seen: datetime
    detail: str
    usernames: list[str] = field(default_factory=list)
    count: int = 0


def detect_brute_force(events: list[Event], threshold: int = 10, window: timedelta = timedelta(minutes=5)) -> list[Alert]:
    """Flag IPs with >= threshold failed logins inside any sliding time window."""
    failures = defaultdict(list)
    for e in events:
        if e.kind == "failed":
            failures[e.ip].append(e)

    alerts = []
    for ip, evs in failures.items():
        evs.sort(key=lambda e: e.time)
        recent: deque[Event] = deque()
        peak = 0
        for e in evs:
            recent.append(e)
            while e.time - recent[0].time > window:
                recent.popleft()
            peak = max(peak, len(recent))
        if peak >= threshold:
            users = sorted({e.user for e in evs if e.user})
            alerts.append(Alert(
                rule="brute_force",
                severity="high",
                ip=ip,
                first_seen=evs[0].time,
                last_seen=evs[-1].time,
                detail=f"{len(evs)} failed logins total, peak {peak} within {_fmt(window)}",
                usernames=users,
                count=len(evs),
            ))
    return sorted(alerts, key=lambda a: a.count, reverse=True)


def detect_username_spray(events: list[Event], threshold: int = 5) -> list[Alert]:
    """Flag IPs that try many different usernames: guessing accounts, not just passwords."""
    by_ip = defaultdict(list)
    for e in events:
        if e.kind in ("failed", "invalid_user") and e.user:
            by_ip[e.ip].append(e)

    alerts = []
    for ip, evs in by_ip.items():
        users = sorted({e.user for e in evs})
        if len(users) >= threshold:
            evs.sort(key=lambda e: e.time)
            alerts.append(Alert(
                rule="username_spray",
                severity="medium",
                ip=ip,
                first_seen=evs[0].time,
                last_seen=evs[-1].time,
                detail=f"tried {len(users)} different usernames",
                usernames=users,
                count=len(users),
            ))
    return sorted(alerts, key=lambda a: a.count, reverse=True)


def detect_success_after_failure(events: list[Event], min_failures: int = 3) -> list[Alert]:
    """A successful login from an IP that failed first may mean a guessed password worked."""
    failures_so_far = defaultdict(int)
    alerts = []
    for e in sorted(events, key=lambda e: e.time):
        if e.kind == "failed":
            failures_so_far[e.ip] += 1
        elif e.kind == "accepted":
            prior = failures_so_far[e.ip]
            if prior >= min_failures:
                alerts.append(Alert(
                    rule="success_after_failure",
                    severity="high",
                    ip=e.ip,
                    first_seen=e.time,
                    last_seen=e.time,
                    detail=f"login as '{e.user}' succeeded after {prior} failed attempts from this IP",
                    usernames=[e.user],
                    count=prior,
                ))
            else:
                alerts.append(Alert(
                    rule="clean_login",
                    severity="info",
                    ip=e.ip,
                    first_seen=e.time,
                    last_seen=e.time,
                    detail=f"login as '{e.user}' with {prior} prior failures from this IP (looks normal)",
                    usernames=[e.user],
                    count=prior,
                ))
    return alerts


def run_all(events: list[Event], bf_threshold: int, bf_window: timedelta, spray_threshold: int) -> list[Alert]:
    return (
        detect_success_after_failure(events)
        + detect_brute_force(events, bf_threshold, bf_window)
        + detect_username_spray(events, spray_threshold)
    )


def _fmt(td: timedelta) -> str:
    mins = int(td.total_seconds() // 60)
    return f"{mins} min" if mins else f"{int(td.total_seconds())} s"
