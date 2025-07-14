# 🔐 Web Security Academy Lab Notes – PortSwigger (Solved Labs)

This document contains customized notes from solved labs on [PortSwigger Web Security Academy](https://portswigger.net/web-security), categorized by vulnerability type. Each lab entry includes the bug, why it happened, how it was exploited, and the recommended fix.

---

## 🔐 Authentication

### Username Enumeration via Different Responses
- **Bug**: Different messages for valid vs. invalid usernames.
- **Why**: Revealed logic like “Invalid password” vs. “User not found”.
- **Exploit**: Tried usernames and analyzed responses.
- **Fix**: Use generic error messages like: `Invalid username or password`.

### 2FA Simple Bypass
- **Bug**: 2FA step could be skipped or bypassed.
- **Why**: Server failed to enforce the 2FA check properly.
- **Exploit**: Submitted random or no 2FA code after valid login.
- **Fix**: Validate 2FA server-side and bind it to the session.

### Password Reset Broken Logic
- **Bug**: Reset flow didn’t validate ownership.
- **Why**: Tokens or users weren’t properly checked.
- **Exploit**: Manipulated parameters to reset another user's password.
- **Fix**: Bind tokens tightly to specific users and validate every step.

### Username Enumeration via Subtle Differences
- **Bug**: Minor differences revealed valid usernames.
- **Why**: Response size, code, or timing varied slightly.
- **Exploit**: Used Burp Comparer or manual checks.
- **Fix**: Standardize all error messages and timings.

### Username Enumeration via Response Timing
- **Bug**: Slower response for valid usernames.
- **Why**: Extra logic (e.g., password hashing) only for valid ones.
- **Exploit**: Timed responses to detect valid usernames.
- **Fix**: Normalize response time regardless of username validity.

### Broken Brute-force Protection (IP-Based Only)
- **Bug**: Blocking only based on IP.
- **Why**: Failed attempts weren’t tracked per user.
- **Exploit**: Switched IP (e.g., X-Forwarded-For) to continue brute-force.
- **Fix**: Track attempts per user/IP combo and use CAPTCHA or lockouts.

### Username Enumeration via Account Lock
- **Bug**: Different messages for locked vs. non-existent users.
- **Why**: Lockout logic leaked username validity.
- **Exploit**: Triggered lockouts and watched the error changes.
- **Fix**: Show the same lockout message for all attempts.

### 2FA Broken Logic
- **Bug**: Tokens weren’t securely generated or validated.
- **Why**: Shared or reusable tokens allowed bypass.
- **Exploit**: Used valid token from another account/session.
- **Fix**: Use per-session, single-use codes with quick expiry.

### Brute-Forcing a “Remember Me” Cookie
- **Bug**: Token was predictable.
- **Why**: Weak generation like hashing user IDs.
- **Exploit**: Brute-forced the cookie to stay logged in.
- **Fix**: Use long, random tokens and store them securely server-side.

### Offline Password Cracking
- **Bug**: Password hashes were leaked.
- **Why**: Poor controls or data breach.
- **Exploit**: Downloaded hashes and cracked with wordlists offline.
- **Fix**: Use strong, salted hashes (bcrypt/scrypt) and slow hashing.

### Password Reset Poisoning via Middleware
- **Bug**: Host header wasn’t validated.
- **Why**: Used attacker-supplied Host in reset link.
- **Exploit**: User got a link pointing to attacker’s domain.
- **Fix**: Use fixed backend host or whitelist domains in reset links.

---

## 🐚 OS Command Injection

### OS Command Injection – Simple Case
- **Bug**: User input sent directly to shell commands.
- **Why**: No sanitization when calling system commands.
- **Exploit**: Injected payload like `127.0.0.1; whoami`.
- **Fix**: Avoid shell execution or sanitize strictly. Use safe APIs.

---

## 🗂️ Path Traversal

### File Path Traversal – Simple Case
- **Bug**: `../` sequences not sanitized.
- **Why**: Direct access to filesystem paths.
- **Exploit**: Requested `../../../../etc/passwd`.
- **Fix**: Normalize and validate paths, enforce whitelisting.

---
## 🔓 Access Control Vulnerabilities Labs

### Unprotected Admin Functionality
- **Bug**: No auth check on admin pages.
- **Why**: Backend didn’t restrict access.
- **Exploit**: Accessed `/admin` without login.
- **Fix**: Enforce role-based access on all sensitive routes.

### Unprotected Admin Functionality with Unpredictable URL
- **Bug**: Relied on security through obscurity.
- **Why**: Endpoint wasn’t protected properly.
- **Exploit**: Guessed or found hidden admin URLs.
- **Fix**: Apply proper authentication and authorization checks.

### User Role Controlled by Request Parameter
- **Bug**: Role value controlled by client input.
- **Why**: Server trusted user-supplied role parameters.
- **Exploit**: Modified role parameter to escalate privileges.
- **Fix**: Roles must be assigned and verified server-side only.

### User Role Can Be Modified in User Profile
- **Bug**: User can change their own role in profile settings.
- **Why**: Role data is modifiable by the user.
- **Exploit**: Elevated own privileges by editing role.
- **Fix**: Roles should not be editable by users.

### User ID Controlled by Request Parameter
- **Bug**: User ID sent in request to fetch or modify data.
- **Why**: No access control on user IDs.
- **Exploit**: Changed user ID to access/modify other accounts.
- **Fix**: Enforce strict access control per user ID.

### User ID Controlled by Request Parameter, with Unpredictable User IDs
- **Bug**: IDs are hard to guess but no auth checks.
- **Why**: Security through obscurity only.
- **Exploit**: Brute forced or enumerated IDs to access data.
- **Fix**: Enforce proper access control regardless of ID complexity.

### User ID Controlled by Request Parameter with Data Leakage in Redirect
- **Bug**: Sensitive data exposed in redirects using user IDs.
- **Why**: Redirect URLs leak info.
- **Exploit**: Captured sensitive data via redirects.
- **Fix**: Avoid leaking sensitive info in URLs or redirects.

### User ID Controlled by Request Parameter with Password Disclosure
- **Bug**: Access to other users’ passwords by modifying user ID.
- **Why**: Missing or insufficient access controls.
- **Exploit**: Retrieved passwords by changing user ID in request.
- **Fix**: Secure all sensitive endpoints with proper auth.

### Insecure Direct Object References (IDOR)
- **Bug**: Direct references to objects without authorization.
- **Why**: Server fails to verify user permissions.
- **Exploit**: Accessed unauthorized data by changing object IDs.
- **Fix**: Implement strict authorization checks on all object references.

### URL-based Access Control Can Be Circumvented
- **Bug**: Access control enforced by URL patterns.
- **Why**: URL manipulation or rewriting bypasses controls.
- **Exploit**: Altered URLs to access restricted functions.
- **Fix**: Apply robust access control independent of URLs.

### Method-based Access Control Can Be Circumvented
- **Bug**: Access control depends on HTTP method (e.g., POST only).
- **Why**: Server fails to check all methods properly.
- **Exploit**: Used alternative HTTP methods (GET, PUT) to bypass.
- **Fix**: Validate access rights for all HTTP methods.

### Multi-step Process with No Access Control on One Step
- **Bug**: One step in multi-step workflow lacks access control.
- **Why**: Server trusts user has completed prior steps.
- **Exploit**: Skipped steps and accessed unprotected step directly.
- **Fix**: Check access control on every step independently.

### Referer-based Access Control
- **Bug**: Access control based on Referer HTTP header.
- **Why**: Referer can be spoofed or controlled by attacker.
- **Exploit**: Forged Referer header to bypass restrictions.
- **Fix**: Do not rely on Referer for critical access decisions.

---

## 🌐 Server-Side Request Forgery (SSRF)

### Basic SSRF Against Localhost
- **Bug**: User-supplied URL fetched blindly.
- **Why**: No validation of internal targets.
- **Exploit**: Targeted `http://localhost:8080` to access internal services.
- **Fix**: Block internal IPs, use allowlist for safe domains.

### Basic SSRF Against Internal Services
- **Bug**: SSRF to internal networks.
- **Why**: No filtering of private IPs.
- **Exploit**: Accessed internal APIs like `192.168.x.x`.
- **Fix**: Block private ranges and validate target URLs carefully.

---

## 🧮 SQL Injection

### SQLi in WHERE Clause – Retrieve Hidden Data
- **Bug**: Unsanitized input in SQL WHERE.
- **Why**: Query built like: `...WHERE id = '$input'`
- **Exploit**: Used `' OR 1=1 --` to get all results.
- **Fix**: Use parameterized queries or ORM securely.

### SQLi in Login – Authentication Bypass
- **Bug**: Input injected directly in login query.
- **Why**: Query example: `SELECT * FROM users WHERE username='$user' AND password='$pass'`
- **Exploit**: Used `' OR '1'='1` to log in as any user.
- **Fix**: Use prepared statements for all database inputs.

---

## ✅ Summary

These labs provide essential insight into real-world vulnerabilities. Each lesson emphasizes the importance of:

- Validating input properly.
- Avoiding assumptions about client behavior.
- Implementing server-side checks at every stage.
- Following secure coding practices and principles like **least privilege**, **defense in depth**, and **fail-safe defaults**.

---

> _Keep practicing, stay sharp, and remember: the most secure code is the one you don't have to trust!_
