# Cybersecurity Portfolio - Week 2, Day 11

## Topic: Processes, Sockets, Nmap Scanning & OverTheWire Bandit (Levels 16–20)

**Objective:** Perform local port scanning and service enumeration (`nmap`, `ss -tulnp`), compare file variations (`diff`), bypass hostile shell configuration traps via SSH command injection, exploit SetUID (`SUID`) binaries for privilege escalation, and utilize Netcat (`nc`) for inter-process socket communication to solve OverTheWire Bandit Levels 16 through 20.

### :hammer_and_wrench: Tools & Environment

* **Client OS:** Windows (PowerShell / WSL Ubuntu / OpenSSH Client)

* **Target Environment:** OverTheWire Bandit Wargame (`bandit.labs.overthewire.org`, Port `2220`)

* **Core Linux Utilities:** `ps aux`, `ss -tulnp`, `nmap`, `openssl`, `nano`, `chmod`, `diff`, `ssh`, `nc`

### :shield: Defensive Analysis: Top 3 Linux Persistence Mechanisms

During incident response, SOC analysts hunt for persistence (mechanisms attackers use to maintain access after reboots or password resets). The three most critical locations to audit in a Linux environment are:

1. **`~/.bashrc` (User Shell Startup Script):** This script executes automatically every time a user starts an interactive Bash session. Attackers append reverse shells or credential-stealing aliases to the bottom of this file. *(Note: This exact mechanism was weaponized in Bandit Level 18 to force an immediate logout upon connection).*

2. **`~/.ssh/authorized_keys` (SSH Backdoors):** Stores public cryptographic keys that are allowed to log into the account without a password. Attackers append their own public key here to bypass password authentication completely.

3. **`/etc/crontab` & `/var/spool/cron/` (Scheduled Tasks):** The Linux equivalent of Windows Task Scheduler. Attackers create hidden cron jobs to silently execute malware payloads or phone home to a Command & Control (C2) server every few minutes.

### :mag: Bandit Levels 16–20 Walkthrough & Visual Evidence

\*(Note: In accordance with OverTheWire