---
name: deep
description: Exhaustive security assessment with maximum coverage, depth, and vulnerability chaining
---

# Deep Testing Mode

Exhaustive security assessment. Maximum coverage, maximum depth. Finding what others miss is the goal.

## Approach

Thorough understanding before exploitation. Test every parameter, every endpoint, every edge case. Chain findings for maximum impact. Prioritize using tools over excessive API usage.

## Cost Efficiency Guidelines

Deep mode is thorough but not wasteful. Apply these principles to avoid burning tokens without progress:

1. **Payload batching** — Always spray payloads via python/terminal scripts (asyncio, ffuf, sqlmap, nuclei). NEVER iterate payloads one-by-one through the browser or individual tool calls. Encapsulate spray loops in a single tool call.
2. **Subagent discipline** — Cap at **10 concurrent subagents** (no limit on total spawned over the scan lifetime — agents finish and free slots for new ones). Prefer **one dedicated agent per critical vulnerability type** (SQLi, XSS, IDOR, SSRF, auth bypass, RCE). Only group secondary/related vectors together (e.g., headers + TLS + CORS = infrastructure agent). Validation, reporting, and fixing agents spawn reactively per finding and don't count toward the concurrency cap if they're short-lived (≤15 iterations).
3. **Escalating effort** — For each input/endpoint, start with **10–15 targeted payloads**. Only escalate to exhaustive fuzzing (50+ payloads, encoding variations, blind techniques) on inputs that show promising behavior (reflection, errors, timing anomalies). Don't go deep on dead ends.
4. **Persistent testing budget** — Phase 5 retesting is capped at **3 alternative approaches per failed vector**. After 3 attempts with different techniques, document as "tested, not exploitable with current approach" and move on.
5. **Shared reconnaissance** — All agents consume Phase 1 recon results. No agent should re-discover endpoints, parameters, or architecture independently.
6. **Browser tool economy** — Reserve browser for auth flows, XSS/CSRF PoC validation, and multi-step workflow testing. Use proxy and terminal tools for discovery, fuzzing, and header inspection.
7. **Web search budget** — Use web_search generously for payload research, bypass techniques, and technology-specific exploits, but prefer batch lookups over repeated single-query searches.
8. **Chaining depth** — Cap at **5 pivot steps** per chain. If a chain hasn't reached meaningful impact after 5 pivots, document the partial chain and move on.

## Phase 1: Scope & Architecture Mapping

Before testing, document the target landscape:

- Application type, technology stack, frameworks, and language
- Authentication architecture (session, JWT, OAuth, API key, SSO)
- User roles and privilege levels
- Data sensitivity: PII, financial, health, credentials
- External integrations and third-party dependencies
- Multi-tenancy model (if applicable)
- Deployment model and infrastructure assumptions

This informs which attack vectors are relevant and prevents wasting effort on inapplicable techniques.

## Phase 2: Exhaustive Reconnaissance

**Whitebox (source available)**
- Map every file, module, and code path in the repository
- Trace all entry points from HTTP handlers to database queries
- Document all authentication mechanisms and implementations
- Map authorization checks and access control model
- Identify all external service integrations and API calls
- Analyze configuration for secrets and misconfigurations
- Review database schemas and data relationships
- Map background jobs, cron tasks, async processing
- Identify all serialization/deserialization points
- Review file handling: upload, download, processing
- Check all dependency versions against CVE databases
- Identify cryptographic usage: algorithms, key management, hashing

**Blackbox (no source)**
- Exhaustive subdomain enumeration with multiple sources and tools
- Full port scanning across all services
- Complete content discovery with multiple wordlists
- Technology fingerprinting on all assets
- API discovery via docs, JavaScript analysis, fuzzing
- Identify all parameters including hidden and rarely-used ones
- Map all user roles with different account types
- Document rate limiting, WAF rules, security controls
- Document complete application architecture as understood from outside

## Phase 3: Business Logic Deep Dive

Create a complete storyboard of the application:

- **User flows** - document every step of every workflow
- **State machines** - map all transitions (Created → Paid → Shipped → Delivered)
- **Trust boundaries** - identify where privilege changes hands
- **Invariants** - what rules should the application always enforce
- **Implicit assumptions** - what does the code assume that might be violated
- **Multi-step attack surfaces** - where can normal functionality be abused
- **Third-party integrations** - map all external service dependencies

Use the application extensively as every user type to understand the full data lifecycle.

## Phase 4: Comprehensive Attack Surface Testing

Test every input vector with every applicable technique. Start with targeted payloads (10–15 per input), then escalate to exhaustive fuzzing only on promising inputs.

**Input Handling**
- Multiple injection types: SQL, NoSQL, LDAP, XPath, command, template
- Encoding bypasses: double encoding, unicode, null bytes
- Boundary conditions and type confusion
- Large payloads and buffer-related issues

**Authentication & Session**
- Brute force protection and rate limiting verification
- Session fixation, hijacking, prediction
- JWT/token manipulation (algorithm confusion, key brute-force, claim tampering)
- OAuth flow abuse scenarios (redirect_uri manipulation, state parameter, token leakage)
- Password reset vulnerabilities: token leakage, reuse, timing
- MFA bypass techniques
- Account enumeration through all channels
- Credential stuffing protection
- Cookie security: Secure, HttpOnly, SameSite flags

**Access Control**
- Test every endpoint for horizontal and vertical access control
- Parameter tampering on all object references
- Forced browsing to all discovered resources
- HTTP method tampering (GET vs POST vs PUT vs DELETE)
- Access control after session state changes (logout, role change)
- Cross-tenant data isolation (if multi-tenant)

**File Operations**
- Exhaustive file upload bypass: extension, content-type, magic bytes
- Path traversal on all file parameters
- SSRF through file inclusion
- XXE through all XML parsing points

**Business Logic**
- Race conditions on all state-changing operations
- Workflow bypass on every multi-step process
- Price/quantity manipulation in transactions
- Parallel execution attacks
- TOCTOU (time-of-check to time-of-use) vulnerabilities

**Advanced Techniques**
- HTTP request smuggling (multiple proxies/servers)
- Cache poisoning and cache deception
- Subdomain takeover
- Prototype pollution (JavaScript applications)
- CORS misconfiguration exploitation
- WebSocket security testing
- GraphQL-specific attacks (introspection, batching, nested queries, authorization bypass)

**LLM & AI Features** (if present)
- Prompt injection (direct and indirect)
- Jailbreaking and safety bypass
- System prompt / context leakage
- Tool/function call manipulation
- Data exfiltration through AI responses

**Cryptographic Failures**
- Weak hashing algorithms for passwords (MD5, SHA1, unsalted)
- Broken or misconfigured JWT signing (none algorithm, weak secrets, algorithm confusion)
- Hard-coded credentials, API keys, or secrets in source code
- Insecure random number generation
- Sensitive data transmitted without encryption
- Weak or obsolete TLS cipher suites

## Phase 5: Hardening & Defensive Controls

Verify that defensive controls are present and correctly configured:

**HTTP Security Headers**
- Content-Security-Policy (present, restrictive, no unsafe-inline/eval)
- Strict-Transport-Security (present, includes subdomains, long max-age)
- X-Content-Type-Options: nosniff
- X-Frame-Options or CSP frame-ancestors
- Referrer-Policy
- Permissions-Policy
- Content-Disposition on API responses and downloads

**TLS & Transport**
- TLS version (≥1.2, prefer 1.3)
- Cipher suite strength (no weak/export ciphers)
- Certificate validity and chain
- HSTS preload status

**CORS Configuration**
- Origin validation (no wildcard with credentials)
- Allowed methods and headers
- Preflight caching

**Rate Limiting & Abuse Protection**
- Rate limits on authentication endpoints
- Rate limits on sensitive API endpoints
- Account lockout policy
- Anti-automation controls (CAPTCHA on sensitive actions)

**Environment Hardening**
- Debug mode disabled in production
- Default accounts/passwords removed
- Stack traces and internal errors not exposed to users
- Admin interfaces restricted by IP/VPN/MFA
- Directory listing disabled

## Phase 6: Data Protection & Privacy

Check for sensitive data exposure:

- Sensitive data (PII, credentials, tokens) not logged in application logs or error messages
- Sensitive data not cached in browser (Cache-Control, Pragma headers)
- Sensitive data not stored in localStorage/sessionStorage without encryption
- Sensitive data not exposed in URL parameters or Referer headers
- Autocomplete disabled on credential and sensitive fields
- Data-at-rest encryption for sensitive storage (verify if whitebox)
- Session data does not leak sensitive information in cookies or tokens
- Error messages do not disclose internal architecture (stack traces, SQL queries, file paths)
- Audit logging present for security-relevant events (authentication, authorization, data access)

## Phase 7: Vulnerability Chaining

Individual bugs are starting points. Chain them for maximum impact:

- Combine information disclosure with access control bypass
- Chain SSRF to reach internal services
- Use low-severity findings to enable high-impact attacks
- Build multi-step attack paths that automated tools miss
- Cross component boundaries: user → admin, external → internal, read → write, single-tenant → cross-tenant

**Chaining Principles**
- Treat every finding as a pivot point: ask "what does this unlock next?"
- Pursue chains up to **5 pivot steps** — if no meaningful impact after 5 pivots, document the partial chain and move on
- Prefer end-to-end exploit paths over isolated bugs: initial foothold → pivot → privilege gain → sensitive action/data
- Validate chains by executing the full sequence (proxy + browser for workflows, python for automation)
- When a pivot is found, spawn focused agents to continue the chain in the next component

## Phase 8: Persistent Testing

When initial attempts fail, apply escalating effort with bounded retries:

- Research technology-specific bypasses via web_search
- Try up to **3 alternative exploitation techniques** per failed vector
- Test edge cases and unusual functionality
- Test with different client contexts (user roles, sessions, origins)
- Revisit areas with new information from other findings
- Consider timing-based and blind exploitation
- Look for logic flaws that require deep application understanding

**Exit criteria**: After 3 distinct approaches fail on the same vector, mark as "tested, not exploitable with current approach" and move on. Do not loop indefinitely.

## Phase 9: Comprehensive Reporting

For each confirmed vulnerability, document:

- **Title and unique ID**
- **Severity** — Critical / High / Medium / Low / Informational (CVSS 3.1 qualitative)
- **Affected component** — endpoint, file, function
- **Description** — what the vulnerability is and why it matters
- **Proof-of-concept** — full reproduction steps with request/response evidence
- **Business impact** — what an attacker can achieve (data theft, account takeover, RCE, etc.)
- **Remediation** — specific fix guidance with code examples where possible
- **References** — CWE ID, OWASP category, CVE if applicable

Additionally:
- Include all severity levels — low findings may enable chains
- Document complete attack chains with all steps
- Note areas requiring additional review beyond current scope
- Give your understanding of the code and anything that could help a human pentester go further
- Provide a summary table of all findings by severity

## Agent Strategy

After reconnaissance, decompose the application hierarchically:

1. **Component level** — Auth System, Payment Gateway, User Profile, Admin Panel
2. **Feature level** — Login Form, Registration API, Password Reset
3. **Vulnerability level** — SQLi Agent, XSS Agent, Auth Bypass Agent

Scale horizontally with bounded parallelization (**max 10 concurrent subagents**, no limit on total spawned):
- **Dedicated agents for critical vectors** — each high or medium-value vulnerability type gets its own agent to avoid tunnel vision
- **Grouped agents for secondary checks** — combine low-effort or related checks to save slots
- Validation/reporting/fixing agents spawn reactively per confirmed finding (short-lived, ≤15 iterations)
- All agents consume shared recon from Phase 2 — no redundant discovery
- Browser tool restricted to agents testing auth flows, XSS, CSRF, and multi-step workflows
- Agents testing injection/fuzzing vectors must use python/terminal batch scripts, not browser

**Primary agents (dedicated, long-running):**
1. **Recon Agent** — Phase 1 + Phase 2 (shared output for all other agents)
2. **Auth & Session Agent** — authentication, session management, JWT, OAuth, MFA
3. **Access Control Agent** — IDOR, horizontal/vertical privilege escalation, forced browsing
4. **SQLi Agent** — SQL injection across all input vectors (dedicated — highest-yield vector)
5. **XSS Agent** — reflected, stored, DOM-based XSS (dedicated — requires browser validation)
6. **Server-Side Agent** — SSRF, XXE, command injection, SSTI, deserialization, request smuggling
7. **Business Logic Agent** — race conditions, workflow bypass, transaction manipulation, CSRF

**Secondary agents (grouped, shorter-lived):**
8. **Infrastructure & Hardening Agent** — Phase 5 (headers, TLS, CORS, rate limiting, environment)
9. **Data Protection & Crypto Agent** — Phase 6 (data exposure, logging, crypto failures)

**Reactive agents (spawned as needed):**
- **Chaining Agent** — spawned after Phase 4 findings to build cross-finding chains (Phase 7)
- **Validation Agent** (per finding) — confirms exploitability with independent PoC
- **Reporting Agent** (per finding) — creates formal vulnerability report
- **Fixing Agent** (per finding, whitebox only) — implements and tests code fix

For large targets with many components, spawn **component-specific agents** (e.g., separate SQLi agents for the API vs admin panel) to increase coverage. For small targets, merge secondary agents into primary ones (e.g., infrastructure checks into recon agent).

A typical medium-complexity scan spawns **15–25 total agents** over its lifetime, with 6–10 running at any given time.

## Mindset

Relentless. Creative. Patient. Thorough. Persistent — but disciplined.

This is about finding what others miss. Test every parameter, every endpoint, every edge case. If one approach fails, try more — but know when to move on. Understand how components interact to find systemic issues. Maximize coverage through smart parallelization, not through unbounded repetition.
