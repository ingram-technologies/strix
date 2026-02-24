---
name: owasp
description: OWASP ASVS Level 1 verification with Testing Guide methodology — structured checklist-driven assessment
---

# OWASP ASVS L1 Testing Mode

Structured security assessment mapped to OWASP Application Security Verification Standard (ASVS) Level 1 and the OWASP Testing Guide. Every finding maps to a specific ASVS control. The goal is pass/fail verification of each applicable control with evidence.

## Approach

Checklist-driven, not exploratory. Work through ASVS L1 controls systematically by category. Use OWASP Testing Guide techniques for each control. Report pass, fail, or not-applicable per control with evidence references.

ASVS Level 1 is the minimum assurance level — achievable through black-box testing alone. It targets the most critical controls that every application must satisfy.

## Phase 1: Scope & Architecture Mapping (ASVS V1)

Before testing controls, understand the application:

- Identify application type: traditional web, SPA, API, mobile backend, microservices
- Map technology stack and frameworks
- Identify trust boundaries and external integrations
- Document authentication and authorization architecture
- List all entry points: endpoints, forms, APIs, file upload, WebSockets
- Determine data sensitivity level and regulatory context

This phase informs which ASVS controls are applicable and which are N/A.

## Phase 2: Authentication Verification (ASVS V2)

Test all L1 controls in V2:

- **V2.1 — Password Security**
  - Passwords allow at least 12 characters (V2.1.1)
  - Passwords allow at least 64 characters (V2.1.2)
  - Password truncation is not performed (V2.1.3)
  - Any Unicode character is allowed in passwords (V2.1.4)
  - Users can change their password (V2.1.5)
  - Password change requires current and new password (V2.1.6)
  - Passwords are checked against breached password lists or sets (V2.1.7)
  - Password strength meter is provided (V2.1.8)
  - No password composition rules limiting character types (V2.1.9)
  - No periodic credential rotation requirement (V2.1.10)
  - Pasting into password fields is permitted (V2.1.11)
  - User can choose to view the password temporarily (V2.1.12)

- **V2.2 — General Authenticator Security**
  - Anti-automation controls for credential stuffing and brute force (V2.2.1)
  - Email as authentication factor uses only weak verifiers like OTP (V2.2.2)
  - Notification after credential updates (V2.2.3)
  - Resistance to phishing: allow integration with hardware tokens or passkeys (V2.2.4)

- **V2.5 — Credential Recovery**
  - Initial or recovery secrets are randomly generated (V2.5.1)
  - Password hints or knowledge-based recovery absent (V2.5.2)
  - Credential recovery does not reveal the current password (V2.5.3)
  - Shared or default accounts absent (V2.5.4)
  - Recovery tokens are time-limited and single-use (V2.5.6)

- **V2.7 — Out-of-Band Verifier** (if applicable)
  - OTP is time-limited and single-use (V2.7.1)
  - OOB verifier expires after a reasonable period (V2.7.2)
  - OOB verifier requests are only sent to the authenticated channel (V2.7.3)

- **V2.8 — Single/Multi-Factor Authenticator** (if applicable)
  - Time-based OTP has a defined lifetime (V2.8.1)

- **V2.10 — Service Authentication**
  - No static API keys or shared secrets in source code (V2.10.3)

## Phase 3: Session Management Verification (ASVS V3)

- **V3.1 — Session Management**
  - URLs do not expose session tokens (V3.1.1)

- **V3.2 — Session Binding**
  - Session created on login (V3.2.1)
  - Sufficient session token entropy (≥64 bits) (V3.2.2)
  - Application stores session tokens in the browser using secure methods (V3.2.3)
  - Session tokens are generated using approved cryptographic algorithms (V3.2.4)

- **V3.3 — Session Termination**
  - Logout invalidates session token server-side (V3.3.1)
  - Session expires after a period of inactivity (V3.3.2)
  - Session expires after an absolute maximum lifetime (V3.3.3)
  - Users can terminate all active sessions (V3.3.4)

- **V3.4 — Cookie-Based Session Management** (if applicable)
  - Secure attribute set on cookies (V3.4.1)
  - HttpOnly attribute set on cookies (V3.4.2)
  - SameSite attribute set on cookies (V3.4.3)
  - Cookie path set to the most precise path (V3.4.4)

- **V3.5 — Token-Based Session Management** (if applicable — JWT, OAuth)
  - Token validation does not rely solely on static secrets (V3.5.2)
  - Stateless session tokens use digital signatures (V3.5.3)

## Phase 4: Access Control Verification (ASVS V4)

- **V4.1 — General Access Control**
  - Least privilege: users can only access authorized functions and data (V4.1.1)
  - Access controls enforced server-side, not solely client-side (V4.1.2)
  - Principle of deny by default: access is denied unless explicitly permitted (V4.1.3)

- **V4.2 — Operation-Level Access Control**
  - Sensitive data and APIs protected against IDOR (V4.2.1)
  - Application does not rely on hidden or obscured URLs for access control (V4.2.2)

- **V4.3 — Administrative Access Control** (if applicable)
  - Administrative interfaces use appropriate multi-factor authentication (V4.3.1)
  - Directory listing disabled unless deliberately intended (V4.3.2)

## Phase 5: Input Validation & Encoding (ASVS V5)

- **V5.1 — Input Validation**
  - HTTP parameter pollution is defended against (V5.1.1)
  - Frameworks protect against mass assignment (V5.1.2)
  - All input is validated: type, length, range (V5.1.3)
  - Structured data is validated against a defined schema (V5.1.4)
  - URL redirects use allowlists or show a warning (V5.1.5)

- **V5.2 — Sanitization and Sandboxing**
  - All untrusted HTML is sanitized using a safe library (V5.2.1)
  - Unstructured data is sanitized with expected characters/length (V5.2.2)
  - Input is sanitized before passing to mail systems (SMTP injection) (V5.2.3)
  - Eval() or dynamic code execution features are not used with user input (V5.2.4)
  - Template injection is prevented through input sanitization or sandboxing (V5.2.5)
  - Application protects against SSRF by validating untrusted data in URLs (V5.2.6)
  - Application protects against XSS with SVG scriptable content and other relevant formats (V5.2.7)
  - Application protects against XPath/XML injection (V5.2.8)

- **V5.3 — Output Encoding**
  - Output encoding is relevant to the interpreter/context (V5.3.1)
  - Output encoding preserves the user's chosen character set (V5.3.2)
  - Context-aware output escaping to protect against reflected, stored, and DOM XSS (V5.3.3)
  - Data selection or database queries use parameterized queries or stored procedures (V5.3.4)
  - OS command injection is prevented (V5.3.5)
  - LDAP injection is prevented (V5.3.6)
  - Application protects against XPath injection (V5.3.7)
  - Application protects against injection including SQL injection, NoSQL injection, and LDAP injection (V5.3.8)

- **V5.5 — Deserialization Prevention**
  - Serialized objects use integrity checks or encryption (V5.5.1)
  - XML parsers are configured to prevent XXE (V5.5.2)
  - Deserialization of untrusted data is avoided or protected (V5.5.3)

## Phase 6: Cryptography (ASVS V6)

- **V6.2 — Algorithms**
  - All cryptographic modules fail securely (V6.2.1)
  - Industry-proven cryptographic algorithms are used (V6.2.2)

- **V6.4 — Secret Management**
  - Secrets are created/stored securely and not in source code (V6.4.1)
  - Key material is not exposed to the application directly (V6.4.2)

## Phase 7: Error Handling & Logging (ASVS V7)

- **V7.1 — Log Content**
  - Sensitive data (credentials, payment, PII) is not logged (V7.1.1)
  - All authentication decisions are logged (V7.1.2)

- **V7.4 — Error Handling**
  - A generic error message is shown on unexpected errors (V7.4.1)
  - Exception handling covers the entire codebase (V7.4.2)
  - Security-relevant error messages don't leak sensitive info (stack traces, session IDs) (V7.4.3)

## Phase 8: Data Protection (ASVS V8)

- **V8.1 — General Data Protection**
  - Application protects sensitive data from being cached in server components (V8.1.1)
  - Server-side temp files are stored securely/cleaned up (V8.1.2)
  - Sensitive data in the HTTP response body or headers is minimized (V8.1.6)

- **V8.2 — Client-Side Data Protection**
  - Sensitive data is not stored in browser storage (localStorage, sessionStorage) permanently (V8.2.1)
  - Autocomplete is disabled on fields with sensitive data (V8.2.2)
  - Sensitive data removed from the DOM when hidden (V8.2.3)

- **V8.3 — Sensitive Private Data**
  - Sensitive data is sent in the HTTP body or headers, not URL parameters (V8.3.1)
  - Users can export/delete their data (V8.3.5)
  - Users are informed about collection and use of personal information (V8.3.6)
  - Sensitive data created and processed is identified and protected (V8.3.7)
  - Sensitive data backed up securely (V8.3.8)

## Phase 9: Communication Security (ASVS V9)

- **V9.1 — Client Communication Security**
  - TLS is used for all client connections (V9.1.1)
  - TLS configuration uses current, strong cipher suites (V9.1.2)
  - Only the latest recommended TLS versions are enabled (V9.1.3)

## Phase 10: Business Logic (ASVS V11)

- **V11.1 — Business Logic Security**
  - Application processes business logic flows in sequential step order (V11.1.1)
  - Application processes business logic flows with realistic human timing (V11.1.2)
  - Application has limits on specific business actions to prevent abuse (V11.1.3)
  - Application has anti-automation controls to prevent data exfiltration or excessive requests (V11.1.4)
  - Application has integrity checks to detect tampering (V11.1.5)
  - Application does not process unsolicited high-value transactions (V11.1.6)

## Phase 11: Files & Resources (ASVS V12)

- **V12.1 — File Upload**
  - Application does not accept large files that could cause DoS (V12.1.1)
  - Compressed file contents validated before decompression (V12.1.2)

- **V12.3 — File Execution**
  - User-submitted filenames are sanitized for path traversal (V12.3.1)
  - User-submitted filenames are validated or ignored in favor of server-generated names (V12.3.2)
  - Direct exposure of user-uploaded file metadata (original path) is prevented (V12.3.6)

- **V12.4 — File Storage**
  - Files from untrusted sources are stored outside the web root (V12.4.1)
  - Files from untrusted sources are scanned by antivirus or served from a separate domain (V12.4.2)

- **V12.5 — File Download**
  - Application does not serve content types other than intended (MIME type validation) (V12.5.1)
  - Direct requests to uploaded files are not executed as HTML/JavaScript (V12.5.2)

## Phase 12: API & Web Services (ASVS V13)

- **V13.1 — Generic Web Service Security**
  - All application components use the same encoding (V13.1.1)
  - Access to admin and management functions is limited to authorized administrators (V13.1.3)

- **V13.2 — RESTful Web Service** (if applicable)
  - Enabled HTTP methods are validated (V13.2.1)
  - JSON schema validation is enabled (V13.2.2)
  - RESTful web services using cookies are protected against CSRF (V13.2.3)
  - REST services have anti-automation controls (V13.2.5)

- **V13.3 — SOAP Web Service** (if applicable)
  - XSD schema validation before processing (V13.3.1)

- **V13.4 — GraphQL** (if applicable)
  - Query allowlist or depth/amount limiting is used (V13.4.1)
  - Authorization logic is implemented at the business logic layer (V13.4.2)

## Phase 13: Configuration (ASVS V14)

- **V14.2 — Dependency**
  - All components are up to date with security patches (V14.2.1)
  - Unnecessary features, documentation, samples, and configurations are removed (V14.2.2)
  - Exposed assets (JavaScript libraries, CSS, fonts) are hosted locally, not from CDNs or external sources without SRI (V14.2.3)

- **V14.3 — Unintended Security Disclosure**
  - Server and framework error messages are configured to deliver actionable, customized responses (V14.3.2)
  - HTTP security headers are present: X-Content-Type-Options, Content-Security-Policy, etc. (V14.3.3)

- **V14.4 — HTTP Security Headers**
  - Every HTTP response includes a Content-Type header with a safe character set (V14.4.1)
  - All API responses include Content-Disposition: attachment (where applicable) (V14.4.2)
  - CSP response header is present and restrictive (V14.4.3)
  - All responses contain X-Content-Type-Options: nosniff (V14.4.4)
  - Strict-Transport-Security header is included on all responses (V14.4.5)
  - Referrer-Policy header is included (V14.4.6)
  - Content-Type and Content-Security-Policy prevent embedding in third-party sites where not intended (V14.4.7)

- **V14.5 — HTTP Request Header Validation**
  - Application server only accepts HTTP methods in use (V14.5.1)
  - Origin header is validated against an allowlist (V14.5.3)

## Chaining

L1 is primarily about individual control verification, but when a control failure is found, immediately assess impact:

- Failed auth control → attempt access control bypass
- Missing input validation → attempt injection to demonstrate impact
- Weak session management → demonstrate session hijacking scenario
- Missing CSRF protection → demonstrate state-changing cross-origin request

Chain only to establish severity. The primary deliverable is per-control pass/fail status.

## Agent Strategy

Organize subagents by ASVS category:

1. **Auth Agent** — V2 (Authentication) + V3 (Session Management)
2. **Access Control Agent** — V4 (Access Control)
3. **Input/Output Agent** — V5 (Validation, Sanitization, Encoding)
4. **Config & Crypto Agent** — V6 (Cryptography) + V9 (Communication) + V14 (Configuration)
5. **Business Logic Agent** — V11 (Business Logic) + V12 (Files) + V13 (API)
6. **Data Protection Agent** — V7 (Error Handling) + V8 (Data Protection)

Each agent reports per-control: PASS / FAIL / N/A with evidence.

## Output Format

For each tested control, report:

- **Control ID** (e.g., V2.1.1)
- **Control description**
- **Status**: PASS | FAIL | N/A
- **Evidence**: what was tested, request/response, PoC if FAIL
- **Severity** (if FAIL): Critical / High / Medium / Low
- **Remediation**: specific fix guidance

Group results by ASVS category in the final report. Include a summary table with pass/fail counts per category.

## Mindset

Compliance-oriented but adversarial. Verify each control through actual testing, not assumption. A control is PASS only with positive evidence. When in doubt, mark as requiring further investigation. Prioritize breadth of coverage — every L1 control must be assessed.
