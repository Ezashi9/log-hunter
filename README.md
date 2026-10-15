# Log Hunter

[![Tests](https://github.com/Ezashi9/log-hunter/actions/workflows/ci.yml/badge.svg)](https://github.com/Ezashi9/log-hunter/actions/workflows/ci.yml)

A Python tool that reads OpenSSH server logs and detects attacks: brute-force password guessing, username spraying, and successful logins that follow failed attempts (a sign a password may have been guessed).

It's the first part of **Home SOC**, a small security operations centre I'm building piece by piece. Log Hunter's JSON output is designed to feed the next tool, which checks attacker IPs against threat-intelligence sources.

## What it found in real server logs

I ran it against the [Loghub OpenSSH dataset](https://github.com/logpai/loghub/tree/master/OpenSSH): genuine logs from an internet-facing lab SSH server. The 2,000-line sample covers about four hours:

- **532 failed logins from 24 IP addresses.** 139 of them targeted accounts that don't exist, meaning the attacker was guessing usernames as well as passwords.
- **6 IPs flagged for brute force.** The worst, `183.62.140.253`, made 286 attempts in about 10 minutes, peaking at 147 within 5 minutes, almost all against `root`.
- **4 IPs flagged for username spraying.** One tried 28 different usernames (`admin`, `support`, `oracle`, `test`, ...).
- **1 successful login**, user `fztu`. It came from an IP with no previous failures, so the tool marks it as normal instead of raising a false alarm.
- `root` was targeted 378 times and `admin` 45 times. Attackers go for accounts that exist on almost every server.

Full output: [sample-report/report.md](sample-report/report.md)

![Failed logins over time](sample-report/failed_logins_over_time.png)
![Most-targeted usernames](sample-report/top_usernames.png)

## Detection rules and why they work this way

| Rule | Severity | Logic | Why this way |
|---|---|---|---|
| `brute_force` | high | ≥ 10 failed logins from one IP inside any **sliding** 5-minute window, **or** ≥ 30 inside any 1-hour window | A lifetime total would eventually flag a real user who mistypes a password once a week. A fixed clock window (e.g. 10:00–10:05) can miss a burst split across the boundary, such as 9 attempts at 10:04 and 9 at 10:06. A sliding window catches both. The 1-hour window catches "low and slow" guessing that deliberately stays under the 5-minute limit. |
| `distributed_brute_force` | medium | one account receives failed logins from ≥ 10 **different** IPs within 10 minutes | Botnets spread guesses across many addresses so no single IP crosses a per-IP limit. Grouping by the *targeted account* instead catches the campaign. |
| `username_spray` | medium | one IP tries ≥ 5 **different** usernames | Repeated tries on one account is password guessing. Many accounts means the attacker is trying to find which ones exist, which is a different behaviour worth separating. |
| `success_after_failure` | high | a successful login from an IP with ≥ 3 failures **in the previous hour** | This is the alert that matters most: it may mean a guessed password worked. Only recent failures count, because a few typos spread across a week are normal. |
| `clean_login` | info | a successful login with no meaningful failures | Logged so successful access is still visible, but not raised as an alarm. Too many false alarms train people to ignore alerts. |

All thresholds can be changed from the command line.

## Detections mapped to MITRE ATT&CK and Sigma

[MITRE ATT&CK](https://attack.mitre.org/) is a public catalogue of attacker techniques, each with an ID such as `T1110`. [Sigma](https://github.com/SigmaHQ/sigma) is a vendor-neutral format for writing detection rules that can be converted into queries for Splunk, Elastic and other SIEMs. Mapping alerts to ATT&CK lets a SOC see which techniques it can and can't detect, and Sigma means the same logic can run in whatever tool the team already uses.

| Rule | ATT&CK technique | Tactic | Sigma rule |
|---|---|---|---|
| `brute_force` | T1110.001 Brute Force: Password Guessing | Credential Access | [`correlation_lnx_sshd_brute_force.yml`](sigma/correlation_lnx_sshd_brute_force.yml) |
| `distributed_brute_force` | T1110 Brute Force | Credential Access | [`correlation_lnx_sshd_distributed_brute_force.yml`](sigma/correlation_lnx_sshd_distributed_brute_force.yml) |
| `username_spray` | T1110 Brute Force | Credential Access | [`correlation_lnx_sshd_username_spray.yml`](sigma/correlation_lnx_sshd_username_spray.yml) |
| `success_after_failure` | T1110 Brute Force, then T1078 Valid Accounts | Credential Access, Initial Access | [`correlation_lnx_sshd_success_after_failure.yml`](sigma/correlation_lnx_sshd_success_after_failure.yml) |
| `clean_login` | none (normal activity) | none | [`lnx_sshd_accepted_login.yml`](sigma/lnx_sshd_accepted_login.yml) |

Every alert in `alerts.json` carries `attack_ids` and `attack_tactics`, and the report shows the technique next to each alert.

**Why `username_spray` isn't mapped to Password Spraying (T1110.003).** Password spraying means trying one common password against many accounts. My rule sees one IP trying many usernames, but sshd never logs the password, so I can't tell spraying apart from password guessing (T1110.001) or credential stuffing with leaked username and password pairs (T1110.004). The honest mapping is the parent technique, Brute Force (T1110).

**Notes on the Sigma rules.** Each threshold rule uses a Sigma correlation (`event_count`, `value_count` or `temporal_ordered`) on top of a simple base rule in the same file. They assume the SIEM extracts the source address into a `src_ip` field and the account into `user`. They pass `sigma check` with the SigmaHQ validators. Some details differ from the Python version: Log Hunter uses a sliding window, while SIEMs usually count in fixed time buckets, and the username and success-after-failure rules look back 24 hours and 1 hour instead of over the whole log. `success_after_failure` uses `temporal_ordered`, which not every SIEM backend supports yet (the Splunk backend doesn't).

## Detection testing: 10 attack scenarios with known answers

Passing on one real log file doesn't prove a detector works. So I wrote 10 labelled scenarios ([`detection_tests/scenarios.py`](detection_tests/scenarios.py)): generated sshd log lines where I know in advance which alerts *should* fire, including normal activity that should raise nothing. All IPs come from documentation-only address ranges. Each scenario is scored for **missed detections** and **false alarms**:

| Scenario | First version | Now |
|---|---|---|
| Fast brute force (30 guesses in 60 s) | pass | pass |
| Real user, two typos then login | pass | pass |
| Real user, typos spread over a week, then login | **false alarm** | pass |
| Low and slow (1 guess every 2 min for 80 min) | **missed** | pass |
| Distributed (20 IPs, 2 guesses each, same account) | **missed** | pass |
| Username spraying | pass | pass |
| IPv6 brute force | **missed** | pass |
| Compressed syslog lines (`message repeated 6 times`) | pass | pass |
| Attacker-crafted usernames (HTML, shell characters, Unicode, 200 characters) | pass | pass |
| Successful break-in (15 guesses, then login) | pass | pass |
| **Total** | **6 / 10** | **10 / 10** |

What the four failures taught me:

1. **IPv6 attacks were invisible.** The parser only recognised IPv4 addresses, so 30 attack lines from an IPv6 address produced **zero** events, with no error. A tool that silently ignores data is worse than one that crashes. It now accepts both.
2. **Low and slow guessing slipped under the threshold.** An attacker making one guess every 2 minutes never hits 10 in 5 minutes. Added a second, longer window (30 in an hour).
3. **Distributed attacks were invisible to per-IP rules.** 20 IPs × 2 guesses each look harmless one at a time. Added `distributed_brute_force`, which groups by the *account being attacked* instead of the attacker.
4. **A real user's typos caused a false alarm.** `success_after_failure` counted failures forever, so three typos over a week plus a normal login looked like a break-in. It now only counts failures from the last hour.

After the fixes, the real Loghub results didn't change: same alerts, no new false alarms.

Run it yourself:

```bash
python -m detection_tests.run
```

The scenario suite is also part of the unit tests, so a change that breaks any detection fails the build.

**Known limits.** Thresholds are a trade-off: an attacker who stays under 10 in 5 minutes *and* 30 an hour from one IP, from fewer than 10 IPs at a time, won't be flagged. A determined attacker can always study published thresholds, which is why real SOCs combine rules like these with blocking tools (e.g. fail2ban), key-only SSH logins and threat intelligence.

## Problems I hit (and fixed)

Checking the tool's numbers against the raw log found two bugs, both now covered by tests:

1. **Repeated messages hid attacks.** syslog compresses identical lines into `message repeated 5 times: [ Failed password for root ... ]`. My first version counted that as one failure, and a plain text search counts it as zero. The parser now expands it into 5 events.
2. **An attacker-chosen username broke the parser.** One attacker tried the username ` 0101` (with a leading space). My original pattern assumed usernames have no spaces, so the line was silently dropped. Usernames are input the attacker controls, so the parser no longer makes assumptions about what they contain.

Syslog timestamps also don't include a year. The tool assumes the most recent date that isn't in the future (override with `--year`) and handles logs that cross from December into January.

## Usage

Requires Python 3.10+. Charts need `matplotlib` and the Sigma rule tests need `pyyaml`; the tool itself only uses the standard library.

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt

# get the sample data
curl -L -o data/OpenSSH_2k.log https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log

python -m log_hunter data/OpenSSH_2k.log
python -m log_hunter /var/log/auth.log --threshold 20 --window 10 --spray 8 --out my-report
```

Outputs, in `reports/` by default:
- `report.md`: summary, alerts and charts
- `alerts.json`: machine-readable alerts plus a `flagged_ips` list for other tools to use
- `*.png`: charts

Run the tests:

```bash
python -m unittest discover -s tests -t .
```

## Project layout

```
log_hunter/
  parser.py     raw log lines -> structured events
  detectors.py  the detection rules
  report.py     console output, Markdown, JSON and charts
  __main__.py   command-line interface
sigma/          the same detections as Sigma rules, for use in a SIEM
detection_tests/ labelled attack and normal-activity scenarios, and the scorer
tests/          unit tests for the parser, every rule, the ATT&CK mapping and the Sigma files
sample-report/  example output from the Loghub dataset
```

## Next steps

- **[IOC Enricher](https://github.com/Ezashi9/ioc-enricher)** (done): reads `alerts.json` and checks each flagged IP against AbuseIPDB threat intelligence.
- **Honeypot:** run a decoy SSH server on a throwaway cloud VM so Log Hunter analyses live attacks rather than a historical dataset.
- **[Dashboard](https://github.com/Ezashi9/home-soc-dashboard)** (done, [live demo](https://ezashi9.github.io/home-soc-dashboard/)): a web view of all of the above.

## Ethics and legal

This tool only **reads log files**; it doesn't scan or connect to anything. Only analyse logs from systems you own or are authorised to monitor. In the UK, accessing systems without permission is an offence under the Computer Misuse Act 1990.

## Data credit

Sample data from Loghub: Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.* IEEE ISSRE, 2023. The log timestamps don't record a year, so the year shown in the sample report is the tool's inference, not part of the dataset.
