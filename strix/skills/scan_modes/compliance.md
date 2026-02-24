---
name: compliance
description: Compliance-grade pentest producing auditor-ready reports for SOC 2 Type II, ISO 27001, and HIPAA
---

# Compliance Pentest Mode

Structured penetration test designed to satisfy technical security control requirements for **SOC 2 Type II**, **ISO 27001 (Annex A)**, and **HIPAA** (Security Rule §164.312). Produces an auditor-ready report with findings mapped to each framework's controls.

Coverage modeled on the Aikido pentest methodology: OWASP Top 10, advanced attack vectors, and hardening/defensive control verification — organized to directly address compliance obligations.

## Approach

Methodical, evidence-driven testing across all compliance-relevant attack surfaces. Every finding maps to the applicable compliance control(s). The report must stand on its own for an auditor — clear scope, methodology description, per-finding evidence, risk rating, and remediation guidance.

Prioritize **breadth of control coverage** over exhaustive depth on any single vector. The goal is demonstrating that all required technical controls have been assessed, not chaining zero-days.

## Cost Control Guidelines

LLM API usage is dominated by three activities. Apply these limits throughout:

1. **Subagent spawning** — Cap at **6 concurrent subagents**. Group related controls into a single agent rather than one-per-control. Reuse agents across phases when scope overlaps.
2. **Fuzzing & payload spraying** — Use **targeted payloads only** (≤10 per input vector per vulnerability class). No exhaustive wordlists, no full directory brute-forcing, no large-scale parameter fuzzing. If the first 10 payloads don't hit, note the control as PASS and move on.
3. **Persistent retesting & deep chaining** — Chain only to establish severity for a confirmed finding (max **2 pivot steps**). Do NOT enter open-ended exploration loops. If an attack path isn't yielding results after two attempts, document as tested-not-exploitable and move on.

Additional cost limits:
- Make use of web search for vulnerabilities and good techniques to use.
- Browser automation: use for **auth flows and XSS/CSRF validation only**, not general crawling — prefer proxy and terminal tools for discovery
- Python tool: use for **PoC validation only**, not for building large automated scanners

## Phase 1: Scope Definition & Architecture Review

Document these items — they form the report's "Scope & Methodology" section:

- Application name, version, environment (staging/production)
- Target type: source code, deployed app, API, or combination
- Technology stack and frameworks
- Authentication model (SSO, OAuth, session, API key, JWT)
- User roles and access levels
- Data classification: what sensitive/regulated data is handled (PII, PHI, financial)
- External integrations and third-party services
- Excluded areas (if any)

**Compliance mapping:**
| Area | SOC 2 | ISO 27001 | HIPAA |
|------|-------|-----------|-------|
| Scope definition | CC6.1 | A.12.6.1 | §164.312(a)(1) |

## Phase 2: OWASP Top 10 & Critical Risks

Test each category with targeted payloads. One confirmed PoC per vulnerability class is sufficient — do not exhaustively spray every parameter.

### 2.1 Broken Access Control (BOLA / IDOR)
- Verify user A cannot access user B's data by manipulating object references
- Test horizontal privilege escalation on **3–5 representative endpoints**
- Test vertical privilege escalation (user → admin)
- Check cross-tenant data isolation if multi-tenant

### 2.2 Injection Flaws
- SQL injection on authentication, search, and filter endpoints (targeted payloads, ≤10 per input)
- Command injection / RCE on any endpoint accepting filenames, paths, or system-adjacent input
- Test **one representative input** per injection class; if vulnerable, document and move on

### 2.3 Cross-Site Scripting (XSS)
- Test stored and reflected XSS on user-generated content fields
- DOM-based XSS on client-side rendering paths
- Use browser tool to validate rendering — **limit to 5 validation attempts per XSS type**

### 2.4 Authentication Failures
- Password policy enforcement (minimum length, complexity, breach list check)
- Brute force / rate limiting on login (test with **5–10 rapid requests**, no large-scale attacks)
- Session management: token entropy, secure/httponly/samesite flags, logout invalidation
- Credential stuffing protection
- Multi-factor authentication bypass (if MFA is present)

### 2.5 Server-Side Request Forgery (SSRF)
- Test URL parameters, webhook configurations, file import URLs
- Limit to **5 targeted payloads** (internal IP ranges, cloud metadata endpoints)

### 2.6 Security Misconfiguration
- Default credentials on admin interfaces
- Debug mode / verbose error exposure
- Unnecessary HTTP methods enabled
- Directory listing

**Compliance mapping:**
| Finding Category | SOC 2 | ISO 27001 | HIPAA |
|------------------|-------|-----------|-------|
| Access control | CC6.1, CC6.3 | A.9.4.1 | §164.312(a)(1) |
| Injection / RCE | CC6.1, CC7.1 | A.14.2.5 | §164.312(a)(1) |
| XSS / client-side | CC6.1 | A.14.2.5 | §164.312(a)(1) |
| Authentication | CC6.1, CC6.2 | A.9.4.2 | §164.312(d) |
| SSRF | CC6.1, CC6.6 | A.13.1.1 | §164.312(e)(1) |
| Misconfiguration | CC6.1, CC7.1 | A.12.6.1, A.14.2.5 | §164.312(a)(1) |

## Phase 3: Advanced & Niche Attack Vectors

Test each category but do NOT deep-dive or persistently retry. One pass with targeted techniques per category.

### 3.1 LLM & Prompt Injection (if AI features present)
- Test for prompt injection, jailbreaking, system context leakage
- **3–5 targeted prompts** — do not iterate extensively

### 3.2 Business Logic Errors
- Test critical workflows: payment, registration, state transitions
- Attempt step-skipping, parameter tampering, race conditions on **2–3 key flows**
- Do not fuzz every form — focus on money/data/privilege-changing flows

### 3.3 Exotic Injections
- NoSQL injection, LDAP injection, XPath injection, SSTI — **only if the tech stack is relevant**
- Skip if no NoSQL database, LDAP, or template engine is identified in Phase 1

### 3.4 File & Upload Vulnerabilities
- Local File Inclusion (LFI), path traversal on file parameters
- Unrestricted file upload: test extension, content-type, and magic byte bypass (≤5 attempts)
- Directory listing on upload/storage paths

### 3.5 Insecure Deserialization
- Only test if serialization points identified in Phase 1
- Targeted payloads for the specific serialization format (Java, PHP, Python pickle, etc.)

### 3.6 Web Cache Poisoning
- Test only if caching layer identified (CDN, reverse proxy)
- **2–3 targeted header manipulation attempts**

### 3.7 Client-Side Attacks
- CSRF on state-changing endpoints (test **3–5 representative actions**)
- Open redirects on login/logout/callback URLs
- DOM-based vulnerabilities in SPA frameworks

### 3.8 Cryptographic Failures
- Check for weak algorithms (MD5, SHA1 for passwords; broken JWT signing)
- Hard-coded credentials or API keys in source (if whitebox)
- Sensitive data transmitted without encryption

**Compliance mapping:**
| Finding Category | SOC 2 | ISO 27001 | HIPAA |
|------------------|-------|-----------|-------|
| Business logic | CC6.1 | A.14.2.5 | §164.312(a)(1) |
| File vulnerabilities | CC6.1, CC6.6 | A.12.2.1 | §164.312(a)(1), §164.312(c)(1) |
| Cryptographic failures | CC6.1, CC6.7 | A.10.1.1 | §164.312(a)(2)(iv), §164.312(e)(2)(ii) |
| CSRF / client-side | CC6.1 | A.14.2.5 | §164.312(a)(1) |
| Deserialization | CC6.1 | A.14.2.5 | §164.312(a)(1) |

## Phase 4: Hardening & Defensive Controls

Verify that defensive controls are present and correctly configured. These are quick checks — mostly header/config inspection, not exploitation.

### 4.1 HTTP Security Headers
- Content-Security-Policy (present, restrictive)
- Strict-Transport-Security (present, includes subdomains, long max-age)
- X-Content-Type-Options: nosniff
- X-Frame-Options or CSP frame-ancestors
- Referrer-Policy
- Permissions-Policy

### 4.2 TLS & Transport Security
- TLS version (≥1.2, prefer 1.3)
- Cipher suite strength (no weak/export ciphers)
- Certificate validity and chain
- HSTS preload status

### 4.3 CORS Configuration
- Origin validation (no wildcard with credentials)
- Methods and headers restrictions
- Preflight caching policy

### 4.4 GraphQL Hardening (if applicable)
- Introspection disabled in production
- Query depth / complexity limits
- Batching limits

### 4.5 Rate Limiting & Abuse Protection
- Rate limits on authentication endpoints
- Rate limits on API endpoints
- Account lockout policy
- CAPTCHA or anti-automation on sensitive actions

### 4.6 Environment & Defaults
- Debug mode disabled
- Default accounts/passwords removed
- Stack traces not exposed
- Admin interfaces access-restricted

**Compliance mapping:**
| Control Area | SOC 2 | ISO 27001 | HIPAA |
|--------------|-------|-----------|-------|
| Security headers | CC6.1, CC6.6 | A.14.1.2 | §164.312(e)(1) |
| TLS | CC6.1, CC6.7 | A.10.1.1, A.13.1.1 | §164.312(e)(1), §164.312(e)(2)(ii) |
| CORS | CC6.1, CC6.6 | A.14.1.2 | §164.312(a)(1) |
| Rate limiting | CC6.1, CC6.8 | A.9.4.2 | §164.312(a)(1) |
| Environment hardening | CC6.1, CC7.1 | A.12.6.1, A.14.2.5 | §164.312(a)(1) |

## Phase 5: Data Protection & Privacy (HIPAA / SOC 2 Focus)

These checks are critical for HIPAA and SOC 2 trust service criteria:

- Sensitive data (PII, PHI) not logged in application logs or error messages
- Sensitive data not cached in browser (Cache-Control, Pragma headers)
- Sensitive data not stored in localStorage/sessionStorage
- Sensitive data not exposed in URL parameters
- Autocomplete disabled on sensitive form fields
- Data-at-rest encryption for sensitive storage (verify if whitebox)
- Data-in-transit encryption (covered in TLS check)
- Session data does not leak sensitive information
- Error messages do not disclose internal details (stack traces, queries, file paths)
- Audit logging present for authentication and authorization events

**Compliance mapping:**
| Control | SOC 2 | ISO 27001 | HIPAA |
|---------|-------|-----------|-------|
| Data logging | CC6.1, CC7.2 | A.12.4.1 | §164.312(b) |
| Data caching / exposure | CC6.1, CC6.5 | A.8.2.3 | §164.312(a)(2)(iv) |
| Encryption at rest | CC6.1, CC6.7 | A.10.1.1 | §164.312(a)(2)(iv) |
| Encryption in transit | CC6.1, CC6.7 | A.10.1.1, A.13.1.1 | §164.312(e)(1) |
| Audit logging | CC7.2, CC7.3 | A.12.4.1 | §164.312(b) |

## Phase 6: Compliance Reporting

Generate an auditor-ready report with these sections:

### Report Structure

1. **Executive Summary**
   - Overall security posture assessment
   - Total findings by severity (Critical / High / Medium / Low / Informational)
   - Compliance readiness summary per framework

2. **Scope & Methodology**
   - Targets tested (from Phase 1)
   - Testing methodology (reference OWASP Testing Guide, PTES)
   - Date range, tools used, testing type (black/white/grey box)
   - Limitations and exclusions

3. **Findings**
   For each finding:
   - Title and unique ID
   - Severity: Critical / High / Medium / Low / Informational (use CVSS 3.1 qualitative)
   - Affected component and endpoint
   - Description of the vulnerability
   - Proof-of-concept with request/response evidence
   - Business impact assessment
   - **Compliance impact**: which SOC 2 / ISO 27001 / HIPAA controls are affected
   - Remediation recommendation with specific guidance
   - References (CWE, OWASP, CVE if applicable)

4. **Compliance Control Matrix**
   Summary table mapping each tested control to:
   - SOC 2 Trust Service Criteria
   - ISO 27001 Annex A control
   - HIPAA Security Rule section
   - Status: Compliant / Non-Compliant / Partially Compliant / Not Assessed

5. **Hardening Recommendations**
   - Defensive control gaps from Phase 4
   - Prioritized remediation roadmap

6. **Attestation Statement**
   - Confirmation that testing was performed following industry-standard methodology
   - Suitable for inclusion in SOC 2 audit evidence, ISO 27001 Statement of Applicability, or HIPAA risk assessment documentation

## Agent Strategy

Limit to **6 subagents maximum**, grouped by compliance domain:

1. **Auth & Session Agent** — Phase 2.4 (authentication) + Phase 2.1 (access control) + session management
2. **Injection & Input Agent** — Phase 2.2 (injection) + Phase 2.3 (XSS) + Phase 3.3 (exotic injections) + Phase 3.7 (CSRF, redirects)
3. **Infrastructure Agent** — Phase 2.5 (SSRF) + Phase 2.6 (misconfig) + Phase 4 (all hardening controls) + Phase 4.2 (TLS)
4. **Business Logic & Files Agent** — Phase 3.2 (business logic) + Phase 3.4 (files) + Phase 3.5 (deserialization) + Phase 3.6 (cache poisoning)
5. **Data Protection Agent** — Phase 5 (data protection, privacy, logging) + Phase 3.8 (crypto failures)
6. **AI & Specialist Agent** (only if applicable) — Phase 3.1 (LLM/prompt injection) + Phase 4.4 (GraphQL)

If Phase 1 determines that AI features and GraphQL are absent, skip Agent 6 entirely and redistribute any remaining checks to other agents.

### Cost-Saving Rules for Agents
- Each agent gets a **single-pass budget**: test each control, document result, move on
- No agent should enter retry/persistence loops — if 10 payloads fail, mark as "tested, not exploitable"
- Agents share recon results from Phase 1 to avoid redundant discovery
- Browser tool usage is restricted to Auth & Session Agent and Injection & Input Agent only
- Web search is shared across all agents with a **total cap of 5 queries**

## Chaining

Chain findings only to establish compliance impact severity:

- If IDOR is found → attempt one cross-tenant data access to confirm multi-tenancy breach (SOC 2 CC6.1, HIPAA §164.312(a)(1))
- If auth bypass is found → attempt one privilege escalation to confirm scope of access (ISO 27001 A.9.4.1)
- If injection is found → attempt one data exfiltration to confirm data breach risk (HIPAA §164.312(c)(1))

**Maximum 2 chaining steps per finding.** The goal is demonstrating real-world compliance impact, not building the longest exploit chain.

## Mindset

Thorough but disciplined. Cover every compliance-relevant control surface without going down rabbit holes. Think like an auditor's technical assessor: systematic, evidence-based, and focused on whether controls are effective. Every finding must answer: "Does this put the organization's SOC 2 / ISO 27001 / HIPAA compliance at risk, and how?"
