import json
import tempfile
import unittest
import uuid
from datetime import timedelta
from pathlib import Path

import yaml

from log_hunter.detectors import (ATTACK_MAPPING, detect_brute_force, detect_success_after_failure,
                                  detect_username_spray, run_all)
from log_hunter.parser import parse_lines


def failed(t, ip, user="root", invalid=False):
    who = f"invalid user {user}" if invalid else user
    return f"Dec 10 {t} host sshd[1]: Failed password for {who} from {ip} port 2222 ssh2"


def accepted(t, ip, user):
    return f"Dec 10 {t} host sshd[1]: Accepted password for {user} from {ip} port 2222 ssh2"


class ParserTests(unittest.TestCase):
    def test_parses_failed_and_accepted(self):
        events = list(parse_lines([failed("10:00:00", "1.2.3.4"), accepted("10:01:00", "5.6.7.8", "alice")], 2020))
        self.assertEqual([e.kind for e in events], ["failed", "accepted"])
        self.assertEqual(events[0].ip, "1.2.3.4")
        self.assertEqual(events[1].user, "alice")

    def test_repeated_message_counts_every_attempt(self):
        line = ("Dec 10 07:13:56 host sshd[1]: message repeated 5 times: "
                "[ Failed password for root from 5.36.59.76 port 42393 ssh2]")
        events = list(parse_lines([line], 2020))
        self.assertEqual(len(events), 5)
        self.assertTrue(all(e.kind == "failed" and e.ip == "5.36.59.76" for e in events))

    def test_username_with_space_is_not_dropped(self):
        line = "Dec 10 08:24:35 host sshd[1]: Failed password for invalid user  0101 from 5.188.10.180 port 36279 ssh2"
        events = list(parse_lines([line], 2020))
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].invalid_user)
        self.assertEqual(events[0].user.strip(), "0101")

    def test_year_rolls_over_from_december_to_january(self):
        lines = [failed("23:59:59", "1.1.1.1"),
                 "Jan  1 00:00:01 host sshd[1]: Failed password for root from 1.1.1.1 port 1 ssh2"]
        events = list(parse_lines(lines, 2020))
        self.assertEqual(events[0].time.year, 2020)
        self.assertEqual(events[1].time.year, 2021)

    def test_ignores_unrelated_lines(self):
        self.assertEqual(list(parse_lines(["not a log line", "Dec 10 10:00:00 host cron[1]: job"], 2020)), [])


class DetectorTests(unittest.TestCase):
    def test_brute_force_uses_sliding_window(self):
        burst = [failed(f"10:00:{s:02d}", "9.9.9.9") for s in range(10)]
        slow = [failed(f"{h:02d}:00:00", "8.8.8.8") for h in range(10)]  # 10 failures, one per hour
        alerts = detect_brute_force(list(parse_lines(burst + slow, 2020)), threshold=10, window=timedelta(minutes=5))
        self.assertEqual([a.ip for a in alerts], ["9.9.9.9"])

    def test_username_spray(self):
        lines = [failed("10:00:00", "7.7.7.7", user=f"user{i}", invalid=True) for i in range(6)]
        alerts = detect_username_spray(list(parse_lines(lines, 2020)), threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 6)

    def test_success_after_failure_is_high_but_clean_login_is_info(self):
        lines = [failed(f"10:00:0{i}", "6.6.6.6") for i in range(3)]
        lines += [accepted("10:01:00", "6.6.6.6", "root"), accepted("10:02:00", "5.5.5.5", "alice")]
        alerts = detect_success_after_failure(list(parse_lines(lines, 2020)))
        by_ip = {a.ip: a for a in alerts}
        self.assertEqual(by_ip["6.6.6.6"].rule, "success_after_failure")
        self.assertEqual(by_ip["6.6.6.6"].severity, "high")
        self.assertEqual(by_ip["5.5.5.5"].severity, "info")


class ReportTests(unittest.TestCase):
    def test_timeline_includes_empty_buckets(self):
        from log_hunter.report import summarise
        lines = [failed("10:00:00", "1.1.1.1"), failed("10:01:00", "1.1.1.1"), failed("10:25:00", "1.1.1.1")]
        timeline = summarise(list(parse_lines(lines, 2020)))["failed_logins_timeline"]
        self.assertEqual([count for _, count in timeline], [2, 0, 1])
        self.assertEqual(timeline[0][0], "2020-12-10T10:00:00")


class AttackMappingTests(unittest.TestCase):
    def _alerts(self):
        lines = [failed(f"10:00:{s:02d}", "9.9.9.9", user=f"user{s % 6}") for s in range(12)]
        lines += [accepted("10:01:00", "9.9.9.9", "root"), accepted("10:02:00", "5.5.5.5", "alice")]
        return run_all(list(parse_lines(lines, 2020)), 10, timedelta(minutes=5), 5)

    def test_every_rule_is_mapped(self):
        from detection_tests.scenarios import build
        rules = set()
        for sc in build():
            events = list(parse_lines(sc.lines, 2020))
            rules |= {a.rule for a in run_all(events, 10, timedelta(minutes=5), 5)}
        self.assertEqual(rules, set(ATTACK_MAPPING))

    def test_alerts_carry_expected_techniques(self):
        by_rule = {a.rule: a for a in self._alerts()}
        self.assertEqual(by_rule["brute_force"].attack_ids, ["T1110.001"])
        self.assertEqual(by_rule["username_spray"].attack_ids, ["T1110"])
        self.assertEqual(by_rule["success_after_failure"].attack_ids, ["T1110", "T1078"])
        self.assertIn("Initial Access", by_rule["success_after_failure"].attack_tactics)
        self.assertEqual(by_rule["clean_login"].attack_ids, [])
        self.assertEqual(by_rule["brute_force"].attack_tactics, ["Credential Access"])

    def test_mapping_ids_are_well_formed(self):
        for ids, tactics in ATTACK_MAPPING.values():
            for t in ids:
                self.assertRegex(t, r"^T\d{4}(\.\d{3})?$")
            self.assertEqual(bool(ids), bool(tactics))

    def test_alerts_json_keeps_old_fields_and_adds_attack(self):
        from log_hunter.report import write_json
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "alerts.json"
            write_json(path, {}, self._alerts())
            data = json.loads(path.read_text(encoding="utf-8"))
        old = {"rule", "severity", "ip", "first_seen", "last_seen", "detail", "usernames", "count"}
        for a in data["alerts"]:
            self.assertLessEqual(old | {"attack_ids", "attack_tactics"}, set(a))


SIGMA_DIR = Path(__file__).resolve().parent.parent / "sigma"
SIGMA_REQUIRED = {"title", "id", "status", "description", "references", "author", "date", "level", "falsepositives"}


class SigmaRuleTests(unittest.TestCase):
    def _docs(self):
        files = sorted(SIGMA_DIR.glob("*.yml"))
        self.assertGreaterEqual(len(files), 4)
        for f in files:
            for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
                yield f, doc

    def test_every_rule_has_required_keys(self):
        for f, doc in self._docs():
            with self.subTest(file=f.name, title=doc.get("title")):
                self.assertLessEqual(SIGMA_REQUIRED, set(doc))
                self.assertEqual(uuid.UUID(doc["id"]).version, 4)
                self.assertEqual(doc["author"], "Eisa Chaudry")
                if "correlation" in doc:
                    self.assertTrue({"type", "rules", "group-by", "timespan"} <= set(doc["correlation"]))
                else:
                    self.assertEqual(doc["logsource"], {"product": "linux", "service": "sshd"})
                    self.assertIn("condition", doc["detection"])

    def test_ids_are_unique_and_references_resolve(self):
        docs = [d for _, d in self._docs()]
        ids = [d["id"] for d in docs]
        self.assertEqual(len(ids), len(set(ids)))
        names = {d["name"] for d in docs if "name" in d}
        for d in docs:
            for ref in d.get("correlation", {}).get("rules", []):
                self.assertIn(ref, names | set(ids))

    def test_sigma_tags_match_python_mapping(self):
        for rule, (ids, _) in ATTACK_MAPPING.items():
            if not ids:
                continue
            f = SIGMA_DIR / f"correlation_lnx_sshd_{rule}.yml"
            top = list(yaml.safe_load_all(f.read_text(encoding="utf-8")))[-1]
            self.assertEqual({t for t in top["tags"] if t.startswith("attack.t")},
                             {f"attack.{i.lower()}" for i in ids})


if __name__ == "__main__":
    unittest.main()
