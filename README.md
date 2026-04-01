markdown

# COM5413 Security Portfolio: The Benji Protocol
**Operator:** Harry Corcoran (01/04/2026)

## Toolkit Components
| Tool Name | Script | Purpose |
| :--- | :--- | :--- |
| **Evidence Collector** | `log_parser.py` |Parses `auth.log` for failed SSH/Login attempts. |
| **Network Cartographer** | `scan.py` |Multi-threaded TCP port scanner with banner grabbing. |
| **Access Validator** | `brute.py` |Targeted SSH/FTP credential tester with mandatory delay. |
| **Web Enumerator** | `web_enum.py` |Automated HTTP recon, header analysis, and comment scraping. |

## Operational Environment
* **Platform:** Linux (Ubuntu/Kali) or Windows (PowerShell)
* **Language:** Python 3.10+
* **No Manual Input:** All tools use `argparse` for automation; `input()` is prohibited

## Installation & Setup

Clone the repository and set up a virtual environment:

```bash
# Clone and enter repo
git clone <your-repo-url>
cd COM5413_Security_Portfolio

# Initialize Virtual Environment
python3 -m venv .venv
source .venv/bin/activate  # Linux / macOS
# .\.venv\Scripts\Activate.ps1 # PowerShell

Install the required dependencies:

pip install -r requirements.txt

requirements.txt contains:
txt

paramiko==3.4.0
requests==2.31.0
beautifulsoup4==4.12.3
pytest==8.0.0

Field Examples
1. The Evidence Collector (log_parser.py)
bash

# Linux
python3 toolkit/task1_evidence_collector/log_parser.py /var/log/auth.log --output suspects.csv

# PowerShell
python log_parser.py auth.log --output suspects.csv

2. The Network Cartographer (scan.py)
bash

# Linux (Range scan)
python3 toolkit/task2_network_cartographer/scan.py 192.168.1.10 --ports 1-1024

# PowerShell (Specific ports)
python scan.py 10.0.0.5 --ports 21,22,80,443

3. The Access Validator (brute.py)
bash

# Linux (SSH)
python3 toolkit/task3_access_validator/brute.py 192.168.1.15 --service ssh --user root --wordlist /usr/share/wordlists/rockyou.txt

# PowerShell (FTP)
python brute.py 10.0.0.5 --service ftp --user admin --wordlist passwords.txt

4. The Web Enumerator (web_enum.py)
bash

# Linux (Standard Scan)
python3 toolkit/task4_web_enumerator/web_enum.py http://scanme.nmap.org --verbose

# PowerShell (Advanced Scan)
python web_enum.py http://10.10.10.5 --csv web_report.csv --paths "/config,/backup,/dev"

Build Log & AI Audit

    Build Log: docs/build.md – a notepad of all issues and challenges I had each week.

    AI Log: AI_LOG.md – logs of all AI that was used for debugging, etc.

Git Tags

There are tags at each milestone throughout this repository:

    w1 – Week 1: Evidence Collector

    w2 – Week 2: Network Cartographer

    w3 – Week 3: Access Validator

    w4 – Week 4: Web Enumerator

    hunt-final – Final submission after the Week 5 mission

Academic Integrity

All work is my own. Where AI was used (e.g., for debugging), it has been listed and documented within the university's AI policy and disability policy.


