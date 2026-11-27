# Cybersecurity Portfolio - Week 5, Day 30

## Topic: Broken Access Control — Horizontal Privilege Escalation & IDOR

**Objective:**
Practice identifying and understanding **Broken Access Control** vulnerabilities in authorized lab environments using **PortSwigger Web Security Academy** and **Burp Suite Community Edition**. Complete three Apprentice labs—*Unprotected admin functionality*, *Unprotected admin functionality with unpredictable URL*, and *User ID controlled by request parameter (IDOR)*—document **IDOR** clearly, and outline **server-side session ownership checks** as the primary remediation.

### :hammer_and_wrench: Tools & Environment

* **Intercepting Proxy & Repeater:** Burp Suite Community Edition (HTTP Proxy, HTTP History & Repeater)
* **Client Browser:** Burp Built-in Chromium Browser
* **Lab Platform:** PortSwigger Web Security Academy (Access Control — Apprentice Labs)
* **OWASP / Security Relevance:** **Broken Access Control** (OWASP Top 10), **Horizontal Privilege Escalation**, and **IDOR** across **Penetration Testing**, **Application Security (AppSec)**, **Security Engineering**, **Cloud Security**, **Vulnerability Management**, **GRC**, **DFIR**, and **Threat Intelligence**

### :shield: Part 1: What Is IDOR & Horizontal Privilege Escalation?

**IDOR (Insecure Direct Object Reference)** occurs when an application takes a user-supplied identifier (such as a query parameter like `?id=carlos` or object ID) and uses it directly to fetch, view, or modify a resource without verifying on the server whether the authenticated user owns or is authorized to access that object.

* **Direct Object Reference Without Authorization:** Modifying a request parameter (such as changing `id` from `wiener` to `carlos`) reaches another user's record because the backend trusts the client-supplied identifier instead of enforcing authorization.
* **Horizontal Privilege Escalation:** Allows a standard user to access another user's account details or sensitive data (such as an API key) at a similar privilege level, rather than escalating to an administrative role.
* **Security by Obscurity Is Not Access Control:** Hiding administrative paths in `robots.txt`, client-side code, or randomized URLs leaves endpoints exposed if the server does not enforce role and permission checks on every request.

| Access Control Concept | What Happens in a Flawed App | Security Impact |
| ----- | ----- | ----- |
| **IDOR (`?id=...`)** | Backend loads object data using the `id` parameter without checking session ownership. | Unauthorized read/write/delete of another user's resource or sensitive data (such as an API key). |
| **Horizontal Privilege Escalation** | User A accesses User B's account or data at the same privilege tier. | Cross-user data exposure and privacy breach. |
| **Unprotected / Obscure Admin Path** | Admin route (`/administrator-panel` or randomized URL) lacks server-side auth enforcement. | Unauthorized access to administrative actions (such as deleting users). |

### :mag: Part 2: Solved PortSwigger Apprentice Labs

#### Lab 1: Unprotected Admin Functionality

* **Discovery:** The navigation bar only displayed `Home` and `My account`, and inspecting the home page HTML source showed product listings (`product?productId=...`) and `/my-account` without an admin link. Checking `/robots.txt` revealed `/administrator-panel`.
* **Execution & Result:** Navigating directly to `/administrator-panel` allowed access without proper authorization enforcement, and deleting the target user marked the lab as **Solved**.

#### Lab 2: Unprotected Admin Functionality with Unpredictable URL

* **Discovery:** Instead of a standard or `robots.txt` path, the admin interface used an unpredictable URL (`/admin-7eo4g3`) exposed via page/script inspection.
* **Execution & Result:** Accessing `/admin-7eo4g3` and deleting the target user marked the lab as **Solved**, demonstrating that an unpredictable URL alone does not replace server-side access control.

#### Lab 3: User ID Controlled by Request Parameter (IDOR)

* **Discovery:** After logging into `/my-account` with a valid session, inspecting `/my-account` requests in Burp showed the `id` parameter controlling which user's account information was returned. *(Note: Testing with an unauthenticated/inactive session returned a `302 Found` redirect to `/login`, confirming an active authenticated session was required before testing cross-user parameter access.)*
* **Execution & Result:** Sending the authenticated `/my-account` request to **Burp Repeater**, changing `id` to `carlos`, retrieving `carlos`'s sensitive API key, and submitting it marked the lab as **Solved**. Both test users were also removed in the sandbox environment, which can be reset anytime via a fresh lab instance.

*(Optional Screenshot Placeholder: Add a screenshot of your Burp Repeater `id=carlos` request/response or lab completion here if you keep one in `Week-5-Access-Control-SSRF/`.)*

### :wrench: Part 3: How Developers Fix IDOR (Server-Side Session Ownership Checks)

| Remediation Control | Implementation Details |
| ----- | ----- |
| **Server-Side Session Ownership Checks** | Derive the acting user strictly from the verified server-side session—never from client-controlled parameters alone—and check on the backend that the authenticated user is authorized for the requested resource (`session_user == resource_owner` or explicit policy check). |
| **Fail-Closed Authorization on Every Route** | Enforce authentication, role, and object-level checks consistently across all endpoints and HTTP methods (`GET`, `POST`, `PUT`, `DELETE`), returning `401` or `403` on unauthorized requests. |
| **Scoped Queries & Non-Guessable References** | Scope database queries by the authorized user/tenant context and avoid relying on predictable identifiers or unauthenticated URL obscurity. |

### :bulb: Conclusion & Role Transferability

Completed all three PortSwigger Apprentice access control labs—identifying `/administrator-panel` via `/robots.txt`, locating `/admin-7eo4g3` as an unpredictable admin path, and exploiting an `id` parameter IDOR flaw to retrieve `carlos`'s API key—while reinforcing **server-side session ownership checks** as the fix.

* **Penetration Testing & AppSec:** Core workflow for spotting missing function-level access control, forced browsing, and IDOR/broken object-level authorization flaws in web apps and APIs.
* **Security Engineering & Cloud Security:** Essential when building least-privilege access, API authorization checks, and resource-level permissions across applications and cloud services.
* **Vulnerability Management, GRC, DFIR & Threat Intelligence:** Supports accurate impact/severity rating for broken access control, alignment with security controls, and HTTP log/request analysis when investigating unauthorized data access.