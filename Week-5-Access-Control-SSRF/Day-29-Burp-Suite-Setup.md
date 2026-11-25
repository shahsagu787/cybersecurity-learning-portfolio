# Cybersecurity Portfolio - Week 5, Day 29

## Topic: Burp Suite Community Setup, HTTPS Proxy Interception & Request Tampering in Repeater

**Objective:**
Configure **Burp Suite Community Edition** on Windows as a local intercepting HTTP/HTTPS proxy using its pre-configured Chromium browser. Isolate a network-level timeout using PowerShell diagnostics, intercept a live **HTTP/2 `POST`** request to `https://httpbin.org/forms/post`, and manually tamper with request body parameters inside **Burp Repeater** to verify server-side response changes.

### :hammer_and_wrench: Tools & Environment

* **Intercepting Proxy:** Burp Suite Community Edition (`v2026.11.2`, Temporary Project)

* **Client Browser:** Burp Built-in Chromium (`Proxy -> Intercept -> Open browser` with pre-trusted PortSwigger CA for automatic HTTPS decryption)

* **Network Diagnostics:** Windows PowerShell (`curl.exe`, `Test-NetConnection`)

* **Target Endpoint:** `https://httpbin.org/forms/post` $\rightarrow$ `POST /post HTTP/2`

* **OWASP / Security Relevance:** Foundational manual testing workflow for **OWASP Top 10** (Broken Access Control, Injection, Business Logic Flaws & Parameter Tampering)

### :shield: Part 1: How Burp Proxy & Burp Repeater Work

Normally, a web browser communicates directly with a web server (`Browser` $\leftrightarrow$ `Server`), making it difficult to modify requests after client-side validation runs. **Burp Suite** inserts itself as a local Man-in-the-Middle (MitM) proxy (`127.0.0.1:8080`) between the browser and the target server (`Browser` $\leftrightarrow$ `Burp Suite` $\leftrightarrow$ `Server`).

| Burp Suite Component | Core Function | Why Security Analysts & Pentesters Use It | 
| ----- | ----- | ----- | 
| **Burp Proxy (`Intercept` & `HTTP History`)** | Acts as a traffic checkpoint and recorder. **Intercept** pauses live HTTP/HTTPS requests mid-flight before they leave your machine; **HTTP History** logs every request and response passively in the background. | Inspects hidden form fields, session cookies, API headers, and background AJAX/XHR calls that never appear in the browser UI. | 
| **Burp Repeater (`Ctrl + R`)** | Opens a captured HTTP message in a dedicated manual testing tab where headers, cookies, HTTP methods, and body parameters can be edited and replayed repeatedly. | Tests how an application handles unexpected input, unauthorized IDs (IDOR), or tampered form fields without re-submitting browser forms—automatically recalculating headers such as `Content-Length`. | 

### :wrench: Part 2: Network & Antivirus Troubleshooting (`testphp.vulnweb.com`)

Before running the interception lab, navigating to the default test URL (`http://testphp.vulnweb.com/login.php`) returned **`Burp Suite Error: Failed to connect to testphp.vulnweb.com:80`**.

To confirm whether the issue was a misconfigured Burp proxy or a network-layer block, I tested connectivity outside Burp using Windows PowerShell:

```
curl.exe -I --max-time 5 http://testphp.vulnweb.com/login.php
# Result: curl: (28) Connection timed out after 5005 milliseconds

Test-NetConnection -ComputerName testphp.vulnweb.com -Port 80
# Result: WARNING: TCP connect to (44.228.249.3 : 80) failed | TcpTestSucceeded : False

```

* **Root Cause Isolation:** Seeing Burp's error banner proved Chromium was successfully routing through Burp's proxy, while `TcpTestSucceeded : False` in PowerShell confirmed the block occurred outside Burp (host-based firewall / Quick Heal Antivirus filtering or target host unavailability).

* **Resolution:** Rather than disabling endpoint protection, I pivoted to **`https://httpbin.org/forms/post`**, which simultaneously verified **automatic HTTPS/TLS interception** in Burp's built-in Chromium browser.

### :mag: Part 3: Live HTTPS `POST` Interception & Parameter Tampering

#### Step 1: Submitting the Baseline Form in Burp's Chromium Browser (`chromiumSS.png`)

Opened `https://httpbin.org/forms/post` inside Burp's built-in Chromium browser and filled out the form with baseline test values (`Customer name: Sagar`, `Pizza Size: Medium`, `Toppings: Onion, Mushroom`, `Delivery instructions: Original Request`) before toggling **Intercept on** and clicking **Submit order**.


*(Screenshot: Submitting the baseline HTTPS form inside Burp Suite's built-in Chromium browser prior to proxy interception)*

#### Step 2: Baseline Request & Server Response in Burp Repeater (`beforemodification.jpg`)

Sent the intercepted `POST /post HTTP/2` request directly to **Burp Repeater** (`Ctrl + R`), turned **Intercept off**, and clicked **Send** to record the unaltered baseline:

* **Request Headers & Body:**

  * `POST /post HTTP/2` (`Host: httpbin.org`)

  * `Content-Type: application/x-www-form-urlencoded`

  * `Content-Length: 146`

  * Body: `custname=Sagar&custtel=1212121212&custemail=abcd%40gmail.com&size=medium&topping=onion&topping=mushroom&delivery=14%3A15&comments=Original+Request`

* **Server Response:** `HTTP/2 200 OK` (`Content-Type: application/json`, `Content-Length: 1362`, total size `1,684 bytes` in `219 ms`).


*(Screenshot: Unmodified `POST /post HTTP/2` request in Burp Repeater returning a `200 OK` JSON baseline response)*

#### Step 3: Modifying Request Body Parameters & Verifying Response (`aftermodification.jpg`)

Directly inside Burp Repeater's **Request** pane, I bypassed the browser form completely and tampered with two URL-encoded body parameters before clicking **Send**:

| Parameter | Original Browser Value | Tampered Repeater Value | 
| ----- | ----- | ----- | 
| `custname` | `Sagar` | `Modified_In_Repeater` | 
| `comments` | `Original+Request` | `Intercepted_And_Tampered` | 
| `Content-Length` *(Auto-Updated)* | `146` bytes | `169` bytes | 

**Observed Result:**

* Burp Repeater automatically recalculated `Content-Length` from **`146`** to **`169`** so the modified HTTP/2 request remained structurally valid.

* The server accepted the tampered payload (`1,707 bytes` returned) and echoed both altered fields inside its JSON `"form"` object:

  ```
  "form": {
    "comments": "Intercepted_And_Tampered",
    "custemail": "abcd@gmail.com",
    "custname": "Modified_In_Repeater",
    "custtel": "1212121212",
    "delivery": "14:15",
    "size": "medium",
    "topping": [
      "onion",
      "mushroom"
    ]
  }
  
  ```


*(Screenshot: Tampering with `custname` and `comments` directly inside Burp Repeater, with `Content-Length` auto-updated to `169` and the server echoing the modified values in JSON)*

### :bulb: Conclusion & Security Takeaway

Successfully configured **Burp Suite Community Edition** on Windows, diagnosed an external TCP connection timeout using PowerShell (`Test-NetConnection`), intercepted live HTTPS traffic using Burp's built-in Chromium browser, and modified `POST` parameters directly inside **Burp Repeater**.

**Security Takeaway:** Client-side browser controls (HTML forms, dropdowns, and JavaScript checks) provide zero security on their own because any user with an intercepting proxy can alter parameters, headers, or cookies after the browser submits them. All input validation, authorization, and business logic checks must be strictly enforced on the server side.