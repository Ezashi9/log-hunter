from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parser import Event

# MITRE ATT&CK (Enterprise) techniques and the tactics they serve in each rule.
# username_spray maps to the parent T1110: sshd logs don't record passwords,
# so spraying (.003) can't be told apart from guessing (.001) or stuffing (.004).
ATTACK_MAPPING: dict[str, tuple[list[str], list[str]]] = {
    "brute_force": (["T1110.001"], ["Credential Access"]),
    "distributed_brute_force": (["T1110"], ["Credential Access"]),
    "username_spray": (["T1110"], ["Credential Access"]),
    "success_after_failure": (["T1110", "T1078"], ["Credential Access", "Initial Access"]),
    "clean_login": ([], []),
}


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
    sources: list[str] = field(default_factory=list)
    attack_ids: list[str] = field(default_factory=list)
    attack_tactics: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.attack_ids and not self.attack_tactics:
            ids, tactics = ATTACK_MAPPING.get(self.rule, ([], []))
            self.attack_ids, self.attack_tactics = list(ids), list(tactics)


def _peak_in_window(times: list[datetime], window: timedelta) -> int:
    recent: deque[datetime] = deque()
    peak = 0
    for t in times:
        recent.append(t)
        while t - recent[0] > window:
            recent.popleft()
        peak = max(peak, len(recent))
    return peak


def detect_brute_force(events: list[Event], threshold: int = 10, window: timedelta = timedelta(minutes=5),
                       slow_threshold: int = 30, slow_window: timedelta = timedelta(hours=1)) -> list[Alert]:
    """Flag IPs with a burst of failures (fast window) or a sustained stream of them (slow window).

    The slow window catches "low and slow" guessing that deliberately stays under the fast threshold.
    """
    failures = defaultdict(list)
    for e in events:
        if e.kind == "failed":
            failures[e.ip].append(e)

    alerts = []
    for ip, evs in failures.items():
        evs.sort(key=lambda e: e.time)
        times = [e.time for e in evs]
        peak = _peak_in_window(times, window)
        slow_peak = _peak_in_window(times, slow_window)
        if peak >= threshold:
            detail = f"{len(evs)} failed logins total, peak {peak} within {_fmt(window)}"
        elif slow_peak >= slow_threshold:
            detail = (f"{len(evs)} failed logins total, {slow_peak} within {_fmt(slow_window)} "
                      f"(low and slow: never more than {peak} within {_fmt(window)})")
        else:
            continue
        alerts.append(Alert(
            rule="brute_force",
            severity="high",
            ip=ip,
            first_seen=evs[0].time,
            last_seen=evs[-1].time,
            detail=detail,
            usernames=sorted({e.user for e in evs if e.user}),
            count=len(evs),
        ))
    return sorted(alerts, key=lambda a: a.count, reverse=True)


def detect_distributed_brute_force(events: list[Event], min_sources: int = 10,
                                   window: timedelta = timedelta(minutes=10)) -> list[Alert]:
    """Flag one account being targeted by many different IPs at once, each staying below per-IP limits."""
    by_user = defaultdict(list)
    for e in events:
        if e.kind == "failed" and e.user:
            by_user[e.user].append(e)

    alerts = []
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e.time)
        recent: deque[Event] = deque()
        best: list[Event] = []
        for e in evs:
            recent.append(e)
            while e.time - recent[0].time > window:
                recent.popleft()
            if len({r.ip for r in recent}) > len({b.ip for b in best}):
                best = list(recent)
        sources = sorted({b.ip for b in best})
        if len(sources) >= min_sources:
            alerts.append(Alert(
                rule="distributed_brute_force",
                severity="medium",
                ip="multiple",
                first_seen=best[0].time,
                last_seen=best[-1].time,
                detail=f"account '{user}' targeted by {len(sources)} different IPs within {_fmt(window)}",
                usernames=[user],
                count=len(sources),
                sources=sources,
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


def detect_success_after_failure(events: list[Event], min_failures: int = 3,
                                 lookback: timedelta = timedelta(hours=1)) -> list[Alert]:
    """A successful login shortly after repeated failures from the same IP may mean a guessed password worked.

    Only failures within `lookback` count: a few typos spread over a week are normal, not an attack.
    """
    recent_failures: dict[str, deque] = defaultdict(deque)
    alerts = []
    for e in sorted(events, key=lambda e: e.time):
        if e.kind == "failed":
            recent_failures[e.ip].append(e.time)
        elif e.kind == "accepted":
            window = recent_failures[e.ip]
            while window and e.time - window[0] > lookback:
                window.popleft()
            prior = len(window)
            if prior >= min_failures:
                alerts.append(Alert(
                    rule="success_after_failure",
                    severity="high",
                    ip=e.ip,
                    first_seen=e.time,
                    last_seen=e.time,
                    detail=f"login as '{e.user}' succeeded after {prior} failed attempts from this IP in the last {_fmt(lookback)}",
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
                    detail=f"login as '{e.user}' with {prior} failures from this IP in the last {_fmt(lookback)} (looks normal)",
                    usernames=[e.user],
                    count=prior,
                ))
    return alerts


def run_all(events: list[Event], bf_threshold: int, bf_window: timedelta, spray_threshold: int) -> list[Alert]:
    return (
        detect_success_after_failure(events)
        + detect_brute_force(events, bf_threshold, bf_window)
        + detect_distributed_brute_force(events)
        + detect_username_spray(events, spray_threshold)
    )


def _fmt(td: timedelta) -> str:
    secs = int(td.total_seconds())
    if secs >= 3600 and secs % 3600 == 0:
        hours = secs // 3600
        return f"{hours} hour" + ("s" if hours > 1 else "")
    return f"{secs // 60} min" if secs >= 60 else f"{secs} s"
