# Information Risk Management (IRM) — ESI Lookup

**Application:** ESI Lookup
**URL:** https://esilookup.com
**Owner:** Shell Energy (internal tooling)
**Document version:** 1.0
**Last updated:** 2026-04-14

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Asset Inventory and Classification](#2-asset-inventory-and-classification)
3. [Threat Landscape](#3-threat-landscape)
4. [Risk Register](#4-risk-register)
5. [Controls Inventory](#5-controls-inventory)
6. [Residual Risk Summary](#6-residual-risk-summary)
7. [Risk Acceptance](#7-risk-acceptance)
8. [Document Control](#8-document-control)

---

## 1. Purpose and Scope

This document identifies, assesses, and tracks information risks for the ESI Lookup application. It covers the application runtime, hosting infrastructure, authentication mechanisms, data in scope, and third-party integrations.

**In scope:**
- ESI Lookup Node.js application (`/home/ubuntu/esi-lookup/server.js`)
- AWS EC2 host (Ubuntu) and Nginx reverse proxy
- In-memory local database (ESI IDs and service addresses)
- SmartMeterTexas.com and ERCOT MIS integrations (when configured)

**Out of scope:**
- SmartMeterTexas.com and ERCOT MIS internal security posture
- AWS account-level controls (IAM, VPC, GuardDuty)
- End-user devices

**Risk scoring methodology:**

Risks are scored as **Likelihood × Impact**, each rated 1–3:

| Score | Rating |
|---|---|
| 1–2 | Low |
| 3–4 | Medium |
| 6–9 | High |

---

## 2. Asset Inventory and Classification

### Application Assets

| Asset | Description | Sensitivity |
|---|---|---|
| `server.js` | Application source code | Internal |
| `LOOKUP_PASSWORD` | Shared application password | **Confidential** |
| `SMT_USERNAME` / `SMT_PASSWORD` | SmartMeterTexas.com credentials | **Confidential** |
| `ERCOT_CERT` / `ERCOT_KEY` | ERCOT MIS client certificate and key | **Confidential** |
| In-memory `localDB` | ESI IDs mapped to service addresses | **Restricted** |
| Bearer tokens (active sessions) | In-memory session tokens | **Confidential** |

### Infrastructure Assets

| Asset | Detail | Sensitivity |
|---|---|---|
| EC2 instance | AWS Ubuntu host running the application | Internal |
| Nginx config | Reverse proxy configuration and TLS termination | Internal |
| TLS private key | `/etc/letsencrypt/live/esilookup.com/privkey.pem` | **Confidential** |
| PM2 logs | Application stdout/stderr | Internal — contain credentials when `LOOKUP_PASSWORD` is not set |
| Nginx access logs | Inbound request log | Internal |

### Data Classification

| Data type | Classification | Notes |
|---|---|---|
| ESI IDs | Restricted | Texas PUC-regulated energy metering identifiers |
| Service addresses | Restricted | Customer location data tied to energy accounts |
| Session tokens | Confidential | 32-byte random hex; loss enables full API access |
| Application password | Confidential | Single credential gates all application access |

---

## 3. Threat Landscape

### Trust Boundaries

```
Internet
   │
   ▼
Nginx (443 / 80) — TLS termination, HSTS
   │
   │ proxy_pass (localhost only)
   ▼
Node.js :3001
   │
   ├── In-memory localDB (imported ESI / address records)
   ├── SmartMeterTexas.com API (outbound, optional)
   └── ERCOT MIS API (outbound, optional)
```

### Threat Actors

| Actor | Motivation | Likely vector |
|---|---|---|
| External opportunist | Credential theft, data scraping | Brute-force login, public exploit |
| Malicious insider | Unauthorized data access or sabotage | Abuse of shared credential |
| Automated scanner | Vulnerability discovery | Public internet exposure |
| Compromised dependency | Supply chain | Malicious npm package |

### Key Risk Drivers

- Internet-facing application with a single shared password and no MFA
- ESI IDs and service addresses are regulated utility customer data
- In-memory architecture means a crash or restart destroys all imported data with no recovery path
- All authenticated users have equivalent privilege — no role separation

---

## 4. Risk Register

### Scoring key: L = Likelihood (1–3), I = Impact (1–3), Score = L × I

| ID | Risk | L | I | Score | Rating | Treatment | Status |
|---|---|---|---|---|---|---|---|
| R-01 | `LOOKUP_PASSWORD` printed in plaintext to PM2 stderr log on every restart without persistent env var set | 3 | 3 | **9** | High | Mitigate | Open |
| R-02 | Single shared password with no MFA — credential compromise grants full access with no per-user audit trail | 2 | 3 | **6** | High | Mitigate | Open |
| R-03 | Full stack traces (file paths, line numbers) returned in HTTP 5xx responses | 3 | 2 | **6** | High | Mitigate | Open |
| R-04 | No Content-Security-Policy header on application responses — XSS payloads execute with full page privilege | 2 | 3 | **6** | High | Mitigate | Open |
| R-05 | Imported `address` / `source` fields stored without sanitization — authenticated user can inject stored XSS | 2 | 3 | **6** | High | Mitigate | Open |
| R-06 | IPv4/IPv6 dual-stack allows brute-force lockout bypass (`req.ip` differs between `1.2.3.4` and `::ffff:1.2.3.4`) | 2 | 2 | **4** | Medium | Mitigate | Open |
| R-07 | Password comparison uses `!==` rather than `crypto.timingSafeEqual()` — timing oracle possible | 1 | 3 | **3** | Medium | Mitigate | Open |
| R-08 | In-memory database only — all imported records lost on process restart or crash; no backup or recovery path | 3 | 2 | **6** | High | Accept (by design) | Accepted |
| R-09 | No per-field string length limit on import — oversized strings accepted, potential memory exhaustion | 2 | 2 | **4** | Medium | Mitigate | Open |
| R-10 | Nginx discloses exact version in `Server:` response header | 3 | 1 | **3** | Medium | Mitigate | Open |
| R-11 | Session tokens stored in-memory — all sessions invalidated on restart (denial of service for active users) | 2 | 1 | **2** | Low | Accept | Accepted |
| R-12 | No IP allowlist — application is accessible from the public internet | 2 | 2 | **4** | Medium | Accept | Accepted |
| R-13 | TLS certificate auto-renewal failure would expose users to certificate warnings or downgrade | 1 | 2 | **2** | Low | Mitigate | Open |
| R-14 | Third-party npm dependencies may contain unpatched CVEs | 1 | 2 | **2** | Low | Mitigate | Open |
| R-15 | EC2 host compromise would expose all secrets, logs, and source code | 1 | 3 | **3** | Medium | Mitigate | Open |

---

## 5. Controls Inventory

### Controls in place

| Control | Type | Addresses | Effectiveness |
|---|---|---|---|
| TLS (Let's Encrypt, auto-renew) | Preventive | Transit interception | High |
| Nginx HSTS header | Preventive | Protocol downgrade | High |
| Nginx `X-Frame-Options`, `X-Content-Type-Options` headers | Preventive | Clickjacking, MIME sniffing | Medium |
| Bearer token authentication on all `/api/*` routes | Preventive | Unauthorized API access | Medium |
| Token TTL (8-hour inactivity expiry) | Preventive | Stale session abuse | Medium |
| Login brute-force lockout (5 attempts → 15-min lockout) | Preventive | Credential stuffing | Medium — bypassed via IPv4/IPv6 (R-06) |
| In-memory rate limiting (sliding window, per IP) | Preventive | DoS, scraping | Medium |
| PM2 process management with auto-restart | Recovery | Application crash | High |
| Node.js `crypto.randomBytes` for token and password generation | Preventive | Predictable tokens | High |

### Controls not yet in place

| Control | Addresses | Priority |
|---|---|---|
| Persistent `LOOKUP_PASSWORD` env var | R-01 | High |
| Global Express error handler suppressing stack traces | R-03 | High |
| `Content-Security-Policy` header | R-04 | High |
| Input sanitization on import (strip HTML) | R-05 | High |
| `crypto.timingSafeEqual()` for password check | R-07 | Medium |
| IPv4/IPv6 normalization in `req.ip` | R-06 | Medium |
| Per-field string length limits on import | R-09 | Medium |
| `server_tokens off` in Nginx config | R-10 | Low |
| Certbot renewal monitoring / alerting | R-13 | Low |
| `npm audit` in CI or periodic schedule | R-14 | Low |

---

## 6. Residual Risk Summary

| Rating | Count | Risk IDs |
|---|---|---|
| High (open) | 4 | R-01, R-02, R-03, R-04, R-05 |
| Medium (open) | 4 | R-06, R-07, R-09, R-15 |
| Low (open) | 3 | R-10, R-13, R-14 |
| Accepted | 3 | R-08, R-11, R-12 |

The dominant residual risk is **credential and session exposure** (R-01, R-02) combined with **missing output security controls** (R-03, R-04, R-05). These should be remediated before the application handles production-volume regulated data.

---

## 7. Risk Acceptance

| Risk ID | Rationale for acceptance |
|---|---|
| R-08 (in-memory DB only) | In-memory architecture is intentional — data is re-imported from source systems on demand. Acceptable given that source data is retained externally. |
| R-11 (session loss on restart) | Restart events are rare and brief. Re-authentication is a minor inconvenience. Acceptable for an internal tool. |
| R-12 (no IP allowlist) | Users access the application from variable locations. An allowlist is not operationally feasible without a VPN. Risk partially mitigated by authentication requirement. |

All other open risks require mitigation before next quarterly review.

---

## 8. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-04-14 | Security review | Initial document |

This document must be reviewed:
- After any SEV-1 or SEV-2 security incident
- After significant changes to the application or infrastructure
- Quarterly at minimum
