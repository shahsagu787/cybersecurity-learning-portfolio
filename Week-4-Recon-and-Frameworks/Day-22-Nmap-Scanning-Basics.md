# Cybersecurity Portfolio - Week 4, Day 22

## Topic: Nmap Host Discovery & Port Scanning Basics (`-sT` vs `-sS`)

**Objective:**
Master host discovery and port scanning methodologies using **Nmap (Network Mapper)** within a WSL Ubuntu environment. Differentiate between TCP Connect scans (`-sT`) and SYN Stealth scans (`-sS`) by capturing and analyzing raw network traffic in **Wireshark**.

### :hammer_and_wrench: Tools & Environment

* **Host OS / Environment:** Windows 11 running Windows Subsystem for Linux (**WSL Ubuntu**)

* **Scanning Tool:** **Nmap** (Version 7.993)

* **Traffic Analysis:** **Wireshark**

* **Authorized Target:** `scanme.nmap.org` (`45.33.32.156`)

* **MITRE ATT&CK Mapping:** `T1046` (Network Service Discovery)

### :shield: Part 1: Host Discovery & Port Scanning Concepts

1. **Host Discovery (`-sn`):**
   Used to determine if a target host is active or "alive" on the network without scanning any individual ports. It sends ICMP echo requests or TCP SYN/ACK packets depending on local/remote network settings.

2. **Port States:**

   * **Open:** An application is actively listening and accepting connections on the port.

   * **Closed:** The port is accessible, but no service is listening (responds with a TCP `RST` packet).

   * **Filtered:** A firewall or packet filter is dropping or blocking packets, preventing Nmap from determining if the port is open or closed.

3. **TCP Connect Scan (`-sT` vs `-sS`):**

   * **`-sT` (TCP Connect Scan):** Relies on the operating system's networking API to complete a full 3-way handshake (`SYN` $\rightarrow$ `SYN-ACK` $\rightarrow$ `ACK`) and immediately tears it down with an `RST, ACK`. Highly reliable, but very noisy because target application logs record the connection.

   * **`-sS` (SYN Stealth Scan):** Sends a `SYN` packet and receives a `SYN-ACK`, but instead of completing the handshake with an `ACK`, it sends an `RST` ("half-open" scan). Requires root/administrator (`sudo`) privileges to craft raw packets.

### :mag: Part 2: Hands-On Nmap Execution & Terminal Evidence

#### 1. Host Discovery Ping Scan (`-sn`)

```
sagar_linux@SagarShah:~$ nmap -sn scanme.nmap.org


```

**Observed Evidence:**

```
Starting Nmap 7.993 ( https://nmap.org ) at 2026-11-16 12:39 +0000
Warning: Hostname scanme.nmap.org resolves to 2 IPs. Using 45.33.32.156.
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.27s latency).
Nmap done: 1 IP address (1 host up) scanned in 0.63 seconds


```

#### 2. Comprehensive Default Port Scan (`-sT` Top 1,000 Ports)

```
sagar_linux@SagarShah:~$ sudo nmap -sT scanme.nmap.org


```

**Observed Evidence:**

```
Not shown: 991 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
22/tcp   open     ssh
25/tcp   filtered smtp
80/tcp   open     http
135/tcp  filtered msrpc
139/tcp  filtered netbios-ssn
444/tcp  filtered snpp
445/tcp  filtered microsoft-ds
1434/tcp filtered ms-sql-m
9929/tcp open     nping-echo


```

### :computer: Part 3: Wireshark Network Traffic Analysis & Comparison

By filtering Wireshark captures for `tcp.port == 80` during targeted port scans against `scanme.nmap.org`, the mechanical differences between scan types were verified:

1. **TCP Connect Scan (`-sT`) on Port 80:**

  ```
  sagar_linux@SagarShah:~$ nmap -sT -p 80 scanme.nmap.org
  
  ```
  ![nmap-st-p80ForWireshark.png](nmap-st-p80ForWireshark.png)
   *(Screenshot: Executing target port 80 TCP Connect scan in WSL)*

   ![Wireshark-sT-p80.png](Wireshark-sT-p80.png)
   *(Screenshot: Wireshark packet capture filtered for tcp.port == 80 showing full 3-way handshake followed by [RST, ACK])*
   
   * **Packet Flow:** `[SYN]` $\rightarrow$ `[SYN, ACK]` $\rightarrow$ `[ACK]` followed instantly by `[RST, ACK]`.

   * **Forensic Insight:** Because a full 3-way handshake completes, web server access logs (e.g., Apache/Nginx) record the connection attempt.

3. **SYN Stealth Scan (`-sS`) on Port 80:**

  ```
  sagar_linux@SagarShah:~$ sudo nmap -sS -p 80 scanme.nmap.org
  
  ```
  ![nmap-sS-p80ForWireshark.png](nmap-sS-p80ForWireshark.png)
   *(Screenshot: Executing root-privileged SYN stealth scan against port 80)*

   ![Wireshark-sS-p80.png](Wireshark-sS-p80.png)
   *(Screenshot: Wireshark packet capture showing half-open [SYN] $\rightarrow$ [SYN, ACK] $\rightarrow$ [RST] flow)*
   
   * **Packet Flow:** `[SYN]` $\rightarrow$ `[SYN, ACK]` followed immediately by `[RST]` (skipping the final `[ACK]`).

   * **Forensic Insight:** The half-open state avoids triggering application-layer connection logs, though network-level IDSs or packet captures will easily flag the high volume of incoming `SYN` packets followed by `RST`.

### :bulb: Conclusion & SOC Analyst Takeaway

Successfully verified Nmap installation, executed host discovery and port scans against authorized targets (`scanme.nmap.org`), and correlated scan behavior with raw packet captures in Wireshark.

**SOC Analyst Takeaway:**
Attackers frequently use `-sS` (SYN Stealth scans) to map enterprise networks quietly while avoiding application-level logging. As defenders, relying solely on web or application server logs will blind us to reconnaissance; robust detection engineering requires network traffic monitoring (Zeek, Suricata, or flow logs) to spot anomalous half-open `SYN` bursts before exploitation occurs.
