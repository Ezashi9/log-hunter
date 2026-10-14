# Log Hunter

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
| `brute_force` | high | ≥ 10 failed logins from one IP inside any **sliding** 5-minute window | A lifetime total would eventually flag a real user who mistypes a password once a week. A fixed clock window (e.g. 10:00–10:05) can miss a burst split across the boundary, such as 9 attempts at 10:04 and 9 at 10:06. A sliding window catches both. |
| `username_spray` | medium | one IP tries ≥ 5 **different** usernames | Repeated tries on one account is password guessing. Many accounts means the attacker is trying to find which ones exist, which is a different behaviour worth separating. |
| `success_after_failure` | high | a successful login from an IP with ≥ 3 earlier failures | This is the alert that matters most: it may mean a guessed password worked. |
| `clean_login` | info | a successful login with no meaningful failures | Logged so successful access is still visible, but not raised as an alarm. Too many false alarms train people to ignore alerts. |

All thresholds can be changed from the command line.

## Problems I hit (and fixed)

Checking the tool's numbers against the raw log found two bugs, both now covered by tests:

1. **Repeated messages hid attacks.** syslog compresses identical lines into `message repeated 5 times: [ Failed password for root ... ]`. My first version counted that as one failure, and a plain text search counts it as zero. The parser now expands it into 5 events.
2. **An attacker-chosen username broke the parser.** One attacker tried the username ` 0101` (with a leading space). My original pattern assumed usernames have no spaces, so the line was silently dropped. Usernames are input the attacker controls, so the parser no longer makes assumptions about what they contain.

Syslog timestamps also don't include a year. The tool assumes the most recent date that isn't in the future (override with `--year`) and handles logs that cross from December into January.

## Usage

Requires Python 3.10+. Charts need `matplotlib`; everything else is the standard library.

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
  detectors.py  the three detection rules
  report.py     console output, Markdown, JSON and charts
  __main__.py   command-line interface
tests/          unit tests for the parser and every rule
sample-report/  example output from the Loghub dataset
```

## Next steps

- **[IOC Enricher](https://github.com/Ezashi9/ioc-enricher)** (done): reads `alerts.json` and checks each flagged IP against AbuseIPDB threat intelligence.
- **Honeypot:** run a decoy SSH server on a throwaway cloud VM so Log Hunter analyses live attacks rather than a historical dataset.
- **Dashboard:** a web view of all of the above.

## Ethics and legal

This tool only **reads log files**; it doesn't scan or connect to anything. Only analyse logs from systems you own or are authorised to monitor. In the UK, accessing systems without permission is an offence under the Computer Misuse Act 1990.

## Data credit

Sample data from Loghub: Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.* IEEE ISSRE, 2023. The log timestamps don't record a year, so the year shown in the sample report is the tool's inference, not part of the dataset.
