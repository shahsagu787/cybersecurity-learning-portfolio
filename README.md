# 🛡️ Cybersecurity Hands-On Learning Portfolio (2026–2027)

Welcome to my cybersecurity lab portfolio! I am documenting my 336-hour hands-on journey covering Network Forensics, Linux/Windows Internals, Web & API Vulnerabilities (OWASP Top 10:2025), SIEM Threat Hunting (KQL & Wazuh), and Python Security Automation.

## 📂 Phase 1: Foundations & Packet/Log Forensics (Weeks 1–4)

- [x] **Week 1:** Network Protocols, Wireshark Packet Analysis & Intro to KQL (`/Week-1-Networking`)
  - **Day 1:** [OSI Model, TCP/IP & 3-Way Handshake](Week-1-Networking/Day-01-TCP-Handshake.md)
  - **Day 2:** [DNS, ARP, DHCP & Traffic Filtering](Week-1-Networking/Day-02-DNS_ARP_Traffic_Lab-v2.md)
  - **Day 3:** [HTTP/HTTPS Internals, Headers, Cookies & JWTs](Week-1-Networking/Day-03-HTTP-and-Cookies.md)
  - **Day 4:** [Subnetting, CIDR, NAT & RFC 1918 Private IPs](Week-1-Networking/Day-04-Subnets-and-IPs.md)
  - **Day 5:** [Identifying Hosts in PCAPs](Week-1-Networking/Day-05-Host-ID-Notes-v3.md) & [Python Port Checker Script](Week-1-Networking/Day-05-Port-Checker.py)
  - **Day 6:** [Malicious PCAP Forensics & VirusTotal OSINT Report](Week-1-Networking/Day-06-First-PCAP-Report.md)
  - **Day 7:** [Intro to KQL & KC7 SOC Breach Investigation](Week-1-Networking/Day-07-KC7-KQL-Notes.md)

- [x] **Week 2:** Linux Internals, Permissions & OverTheWire Bandit 0–33 (`/Week-2-Linux-Security`)
  - **Day 8:** [Linux CLI, Hidden Files & Bandit 0–5](Week-2-Linux-Security/Day-8-Linux-CLI-Bandit-05-Notes.md)
  - **Day 9:** [Linux Permissions (chmod), SUID Bugs & Bandit 6–10](Week-2-Linux-Security/Day-09-Bandit-06-to-10-Permissions.md)
  - **Day 10:** [Encoding, Compression, SSH Keys & Bandit 11–15](Week-2-Linux-Security/Day-10-Encoding-Compression-SSHKeys-Bandit-11-to-15.md)
  - **Day 11:** [Processes, Open Sockets, Nmap & Bandit 16–20](Week-2-Linux-Security/Day-11-Bandit-16-to-20-Processes.md)
  - **Day 12:** [Cron Exploitation, Shell Escapes & Bandit 21–26](Week-2-Linux-Security/Day-12-Cron-Exploitation-Shell-Escapes-Log-Parser-Bandit-21-to-26.md) & [Python SSH Brute-Force Log Parser](Week-2-Linux-Security/Day-12-Log-Counter.py)
  - **Day 13:** [Leaked Secrets in Git & Bandit 27–33 Finale](Week-2-Linux-Security/Day-13-Bandit-27-to-33-Git-Leaks.md)
  - **Day 14:** [KC7 CloutHaus SOC Breach Report & VirusTotal Pivoting](Week-2-Linux-Security/Day-14-KC7-CloutHaus-Report.md)

- [ ] **Week 3:** Windows Internals, Active Directory, Event Logs & Sysmon (`/Week-3-Windows-Defense`)
- [ ] **Week 4:** Nmap Reconnaissance, CyberChef De-obfuscation & MITRE ATT&CK (`/Week-4-Recon-and-Frameworks`)

## 🛠️ Tools Practiced
* **Network & Recon:** Wireshark, Nmap, Netcat (`nc`), OpenSSL, `curl`, `nslookup`, Python (`socket`)
* **Endpoint, Linux & SIEM:** Linux CLI (Bash, `cron`, `chmod`, `find`, `ss`, `git`), Windows Event Viewer, Sysmon, KC7 Cyber (Azure Data Explorer / KQL), PowerShell (`Get-FileHash`)
* **Threat Intel & Decoding:** VirusTotal, CyberChef, Browser DevTools, Python Log Parsing
