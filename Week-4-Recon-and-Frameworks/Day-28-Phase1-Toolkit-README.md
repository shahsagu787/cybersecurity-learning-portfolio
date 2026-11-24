# Phase 1 Python Security Toolkit (`Day-28-Phase1-Toolkit.py`)

## Objective
Consolidate three foundational Phase 1 security scripts—an authorized single-host TCP port checker (Day 5), a failed-login SSH log counter (Day 12), and a static Base64 text decoder (Day 19)—into a clean, menu-driven Python command-line utility (`Day-28-Phase1-Toolkit.py`) with input validation, socket timeouts, structured error handling, and safe file operations.

---

## Safe Scope & Ethical Guardrails
* **Authorized Network Targets Only:** Option 1 (`Authorized Port Check`) must only be run against systems you own or targets that explicitly permit testing (such as `scanme.nmap.org`). It checks a single host and single TCP port per run—it does not perform automated port sweeps or subnet scanning.
* **Benign Local Logs Only:** Option 2 (`Failed-Login Log Counter`) reads local log files in read-only mode (`"r"`) using `utf-8` encoding with safe character replacement (`errors="replace"`).
* **Static Display Only (Zero Execution):** Option 3 (`Base64 Text Decoder`) strictly decodes Base64 strings to text for visual inspection. It **never** passes decoded output to `eval()`, `exec()`, `os.system()`, or `subprocess`.

---

## Prerequisites & Usage

### Requirements
* **Python:** Python 3.8 or higher (tested on Windows 11 with PowerShell 5.1)
* **External Dependencies:** None (uses only Python standard library modules: `socket`, `base64`, `binascii`)

### How to Run (Windows PowerShell)
```powershell
python .\Day-28-Phase1-Toolkit.py
```

### Menu Options
1. **Authorized Port Check:** Prompts for an authorized hostname/IP and TCP port (`1–65535`), sets a `2.0`-second socket timeout, checks connectivity via `connect_ex()`, and always closes the socket in a `finally` block.
2. **Failed-Login Log Counter:** Prompts for a local log file path, scans line by line for `"Failed password"`, displays matching line numbers, and prints the total count.
3. **Base64 Text Decoder (Display Only):** Prompts for a Base64 string and text encoding (`1` for `UTF-8`, `2` for `UTF-16LE`), validates Base64 characters (`validate=True`), and prints the decoded text safely.
4. **Exit:** Cleanly exits the interactive loop.

---

## Verified Test Cases & Observed Outputs

All three functions and their input validation paths were tested incrementally in Windows PowerShell:

### Test 1: Option 1 — Authorized Port Check & Range Validation
* **Input A (Authorized Target):** Host `scanme.nmap.org`, Port `80`
  * **Observed Output:**
    ```text
    [*] Checking scanme.nmap.org:80 (authorized target only)...
    [+] OPEN: scanme.nmap.org:80 accepted a TCP connection.
    ```
* **Input B (Out-of-Range Port):** Host `scanme.nmap.org`, Port `66666`
  * **Observed Output:**
    ```text
    [!] Invalid input: Port must be between 1 and 65535.
    ```

### Test 2: Option 2 — Failed-Login Log Counter & Missing File Handling
* **Input A (Non-Existent File):** Path `file`
  * **Observed Output:**
    ```text
    [!] File not found: 'file' does not exist.
    ```
* **Input B (Benign Sample File `sample_auth.log` with 2 failed SSH lines and 1 accepted line):**
  * **Observed Output:**
    ```text
    [#1 | Line 1] Nov 24 10:00:01 lab sshd[101]: Failed password for invalid user admin from 192.0.2.10 port 51234 ssh2
    [#2 | Line 3] Nov 24 10:00:09 lab sshd[103]: Failed password for root from 192.0.2.10 port 51236 ssh2
    [+] Scan complete: Found 2 'Failed password' entries in 'sample_auth.log'.
    ```

### Test 3: Option 3 — Base64 Text Decoder (`UTF-8`, `UTF-16LE`, and Validation)
* **Input A (Standard `UTF-8` String):** `SGVsbG8gU2FnYXIh` (Encoding `1`)
  * **Observed Output:**
    ```text
    [+] Decoded Text (Display Only - Never Executed):
    --------------------------------------------------
    Hello Sagar!
    --------------------------------------------------
    ```
* **Input B (PowerShell `UTF-16LE` String):** `VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACAAUwBPAEMAJwA=` (Encoding `2`)
  * **Observed Output:**
    ```text
    [+] Decoded Text (Display Only - Never Executed):
    --------------------------------------------------
    Write-Host 'Hello SOC'
    --------------------------------------------------
    ```
* **Input C (Invalid Encoding Choice):** Choice `3`
  * **Observed Output:**
    ```text
    [!] Invalid choice: Enter 1 for UTF-8 or 2 for UTF-16LE.
    ```

---

## Limitations & Security Takeaway
* **Single-Host / Single-Port Scope:** Option 1 tests one TCP port at a time and does not perform service version fingerprinting or UDP scanning (use Nmap in authorized environments for deeper enumeration).
* **Fixed Search Pattern:** Option 2 matches the literal substring `"Failed password"` (standard OpenSSH format) and does not parse Windows EVTX binary logs or correlate source IP thresholds automatically.
* **Single-Layer Base64 Only:** Option 3 decodes single-layer `UTF-8` or `UTF-16LE` Base64 text; multi-stage obfuscation (such as XOR, Gzip compression, or nested encoding) requires manual static inspection in tools like CyberChef.

**Key Takeaway:**
Combining small, single-purpose scripts into a modular menu-driven toolkit teaches defensive coding habits—validating user input before processing, handling missing files and network timeouts gracefully, and treating untrusted encoded strings strictly as static data rather than executable instructions.