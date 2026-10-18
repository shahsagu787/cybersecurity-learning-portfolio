# Cybersecurity Portfolio - Week 1, Day 4
## Topic: Subnetting, Ports, NAT & Firewalls

**Objective:** 
Understand how networks are logically divided using Subnet Masks and CIDR notation, and identify the difference between public and private IP ranges (RFC 1918).

### :hammer_and_wrench: Tools & Environment
* **OS:** Windows
* **CLI:** PowerShell (`ipconfig`)
* **Training:** Cisco Networking Basics (Network Addressing & NAT)

### :memo: Lab Walkthrough & Execution

**1. Foundational Theory**
* Completed targeted modules in the Cisco Networking Basics course, focusing on Layer 3 logical addressing (IPv4) and Network Address Translation (NAT).

**2. Local Network Inspection**
* Utilized Windows PowerShell to inspect the local machine's active network adapter configurations.
* Cross-referenced local IP assignments with RFC 1918 standards to verify internal network behavior.

### :mag: Key Observations & Network Analysis

By running `ipconfig` on the local machine, I identified the following network parameters:

* **Host IPv4 Address:** `192.168.1.76`
  * *Analysis:* This falls into the `192.168.0.0/16` block. According to RFC 1918, this is a **Private IP Address** strictly used for internal networks (like home Wi-Fi) and is not directly routable on the public internet. The local router uses NAT (Network Address Translation) to hide this IP from external public networks.
* **Subnet Mask:** `255.255.255.0`
  * *Analysis:* This translates to a **`/24` CIDR notation**. It indicates that the first three octets (`192.168.1`) are locked as the network address, leaving the final octet available for host devices. This allows for up to 256 IP addresses (254 usable) on this specific local subnet.

### :bulb: Conclusion
Successfully demonstrated the ability to inspect local IP configurations, manually calculate CIDR notation from a decimal subnet mask, and classify IP addresses according to RFC 1918 private networking standards.
