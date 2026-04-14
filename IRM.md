# Incident Response Management (IRM) — ESI Lookup

**Application:** ESI Lookup  
**URL:** https://esilookup.com  
**Owner:** Shell Energy (internal tooling)  
**Document version:** 1.0  
**Last updated:** 2026-04-14  

---

## Table of Contents

1. [Asset Inventory](#1-asset-inventory)
2. [Threat Model](#2-threat-model)
3. [Incident Severity Levels](#3-incident-severity-levels)
4. [Roles and Responsibilities](#4-roles-and-responsibilities)
5. [General Incident Response Procedure](#5-general-incident-response-procedure)
6. [Playbooks](#6-playbooks)
   - [PB-01: Credential Compromise / Unauthorized Access](#pb-01-credential-compromise--unauthorized-access)
   - [PB-02: Brute-Force or Credential Stuffing Attack](#pb-02-brute-force-or-credential-stuffing-attack)
   - [PB-03: Stored XSS / Data Poisoning via Import](#pb-03-stored-xss--data-poisoning-via-import)
   - [PB-04: Denial of Service / Rate Limit Exhaustion](#pb-04-denial-of-service--rate-limit-exhaustion)
   - [PB-05: Server Crash / Application Unavailability](#pb-05-server-crash--application-unavailability)
   - [PB-06: Secret / Credential Exposure in Logs](#pb-06-secret--credential-exposure-in-logs)
   - [PB-07: TLS Certificate Expiry or Compromise](#pb-07-tls-certificate-expiry-or-compromise)
   - [PB-08: EC2 Host Compromise](#pb-08-ec2-host-compromise)
7. [Known Vulnerabilities and Mitigations](#7-known-vulnerabilities-and-mitigations)
8. [Runbook: Operational Commands](#8-runbook-operational-commands)
9. [Post-Incident Review](#9-post-incident-review)
10. [Document Control](#10-document-control)

---

## 1. Asset Inventory

### Application

| Component | Detail |
|---|---|
| Application name | ESI Lookup |
| Public URL | https://esilookup.com |
| Internal URL | http://127.0.0.1:3001 |
| Purpose | ESI ID → service address lookup for Texas energy market (Oncor, CenterPoint, AEP, TNMP, Lubbock P&L) |
| Runtime | Node.js 20.20.1, Express 5.x |
| Process manager | PM2 (process ID 0, fork mode) |
| Source path | `/home/ubuntu/esi-lookup/server.js` |

### Infrastructure

| Component | Detail |
|---|---|
| Host | AWS EC2, Ubuntu |
| Reverse proxy | Nginx 1.24.0 |
| TLS | Let's Encrypt — `/etc/letsencrypt/live/esilookup.com/` |
| Cert renewal | Certbot (auto-renewal via cron/systemd timer) |

### Logs

| Log | Path |
|---|---|
| Application stdout | `/home/ubuntu/.pm2/logs/esi-lookup-out.log` |
| Application stderr | `/home/ubuntu/.pm2/logs/esi-lookup-error.log` |
| Nginx access | `/var/log/nginx/access.log` |
| Nginx error | `/var/log/nginx/error.log` |

### External Integrations (optional, credential-gated)

| Integration | Env vars | Status |
|---|---|---|
| SmartMeterTexas.com | `SMT_USERNAME`, `SMT_PASSWORD` | Not configured |
| ERCOT MIS | `ERCOT_CERT`, `ERCOT_KEY` | Not configured |

### Data

- **All lookup data is in-memory only.** No persistent database. The in-memory `localDB` Map is lost on process restart.
- Maximum 200,000 local records; 50,000 per import batch.
- Data types stored: ESI IDs (digits only), service addresses (free-text strings), source labels.

---

## 2. Threat Model

### Trust Boundaries

```
Internet
   │
   ▼
Nginx (443/80) ──TLS─→ esilookup.com
   │
   │ proxy_pass (internal only)
   ▼
Node.js :3001 (localhost)
   │
   ├── In-memory localDB (imported ESI/address records)
   ├── SmartMeterTexas.com API (outbound, optional)
   └── ERCOT MIS API (outbound, optional)
```

### Actors

| Actor | Trust level | Access |
|---|---|---|
| Unauthenticated public | None | `GET /` static files, `POST /api/login` only |
| Authenticated user | Low — single shared password | All `/api/*` endpoints |
| EC2 OS user (`ubuntu`) | High | Full filesystem, PM2, logs, secrets |
| AWS IAM / console | High | EC2 control plane |

### Key Risks

1. Single shared password — no per-user identity or audit trail
2. All authenticated users can import data, clear the database, and trigger outbound lookups
3. No persistent audit log of who looked up what
4. Session tokens are in-memory; lost on server restart
5. No IP allowlist — the application is internet-facing

---

## 3. Incident Severity Levels

| Level | Name | Definition | Target response time |
|---|---|---|---|
| **SEV-1** | Critical | Active exploitation confirmed; data exfiltration; complete service unavailability | 30 min |
| **SEV-2** | High | Suspected compromise; credential leak; service degraded for all users | 2 hours |
| **SEV-3** | Medium | Suspicious activity; partial service impact; single-user impact | 8 hours (business day) |
| **SEV-4** | Low | Configuration drift; minor anomaly; informational finding | Next sprint |

---

## 4. Roles and Responsibilities

| Role | Responsibilities |
|---|---|
| **Incident Commander (IC)** | Declares severity, coordinates response, owns communications, calls all-clear |
| **Application Owner** | Source code decisions, hotfix deployment, credential rotation |
| **Infrastructure Owner** | EC2/Nginx/PM2 actions, firewall changes, log collection |
| **Security Analyst** | Evidence preservation, forensics, root-cause analysis |
| **Stakeholder / User comms** | Notifies affected users, tracks regulatory obligations |

> For a small team, one person may hold multiple roles. Designate backups in advance.

---

## 5. General Incident Response Procedure

```
DETECT → TRIAGE → CONTAIN → ERADICATE → RECOVER → REVIEW
```

### Step 1 — Detect
Incidents may be detected via:
- User-reported anomaly (unexpected logouts, unknown data in results)
- Nginx access log spike (automated alerting or manual review)
- PM2 crash alert or unexpected restarts
- External vulnerability scanner report
- AWS GuardDuty / CloudTrail alert

### Step 2 — Triage
Answer these questions within 15 minutes of detection:

- [ ] Is the service currently up? (`curl -s -o /dev/null -w "%{http_code}" https://esilookup.com/`)
- [ ] Are there active sessions that may belong to an attacker? (check `activeTokens` — no direct API for this; requires server restart to clear all)
- [ ] Is data being exfiltrated? (review Nginx access log for `/api/lookup` or `/api/db-status` bursts)
- [ ] Are credentials confirmed compromised?
- [ ] Is this an active vs. historical incident?

Assign a severity level and page the IC.

### Step 3 — Contain

**Fastest containment options (in order of impact):**

| Action | Effect | Command |
|---|---|---|
| Rotate `LOOKUP_PASSWORD` + restart | Invalidates all existing tokens | See [PB-01](#pb-01-credential-compromise--unauthorized-access) |
| Block IP at Nginx | Stops specific attacker | `deny <ip>;` in nginx.conf |
| Take app offline | Full containment | `pm2 stop esi-lookup` |
| Block at security group | Network-level block | AWS console → EC2 → Security Groups |

### Step 4 — Eradicate
- Remove malicious imported records if data was poisoned: `POST /api/clear` or process restart
- Patch the underlying vulnerability before bringing the service back up
- Rotate all secrets (see relevant playbook)

### Step 5 — Recover
- Bring service back with new credentials
- Verify no attacker persistence (cron jobs, SSH keys, backdoors)
- Monitor for 24 hours post-recovery

### Step 6 — Review
Complete a [Post-Incident Review](#9-post-incident-review) within 5 business days.

---

## 6. Playbooks

---

### PB-01: Credential Compromise / Unauthorized Access

**Indicators:**
- Successful login from unexpected IP in Nginx access log
- Unfamiliar records in `/api/db-status` count
- User reports they were logged out unexpectedly (attacker cleared DB or rotated password)

**Response:**

1. **Preserve evidence before taking action:**
   ```bash
   cp /var/log/nginx/access.log /tmp/incident-$(date +%Y%m%d%H%M%S)-nginx.log
   cp /home/ubuntu/.pm2/logs/esi-lookup-error.log /tmp/incident-$(date +%Y%m%d%H%M%S)-pm2.log
   ```

2. **Invalidate all active sessions** (only option is to restart the process):
   ```bash
   pm2 restart esi-lookup
   ```
   This clears the in-memory `activeTokens` Map and generates a new random password (until `LOOKUP_PASSWORD` is set permanently — see step 3).

3. **Set a strong, persistent password:**
   ```bash
   # Generate a new password
   NEW_PASS=$(openssl rand -hex 32)
   echo "New password: $NEW_PASS"  # Record securely before proceeding

   # Set it in PM2's environment so it survives restarts
   pm2 stop esi-lookup
   pm2 delete esi-lookup
   LOOKUP_PASSWORD="$NEW_PASS" pm2 start /home/ubuntu/esi-lookup/server.js --name esi-lookup
   pm2 save
   ```

4. **Audit what the attacker accessed:**
   ```bash
   # Find all requests using a specific token — note tokens are not logged by default
   grep "POST /api/" /var/log/nginx/access.log | grep -v "127.0.0.1"
   # Look for /api/lookup, /api/import, /api/clear, /api/db-status
   ```

5. **Assess data impact:**
   - Was `/api/import` called? Attacker could have poisoned the local DB.
   - Was `/api/clear` called? All local lookup data is gone.
   - Was `/api/lookup` called with real customer ESI IDs? This is a data access event.
   - If SMT or ERCOT credentials were configured, were they exposed via `sourceDetails` responses?

6. **Determine if regulatory notification is required** (energy sector data access may trigger obligations).

---

### PB-02: Brute-Force or Credential Stuffing Attack

**Indicators:**
- High volume of `POST /api/login` with HTTP 401 responses in Nginx access log
- HTTP 429 responses from the lockout mechanism
- Repeated requests from one or many IPs

**Response:**

1. **Check if the attack is ongoing:**
   ```bash
   tail -f /var/log/nginx/access.log | grep "POST /api/login"
   ```

2. **Count attack volume and identify source IPs:**
   ```bash
   grep "POST /api/login" /var/log/nginx/access.log | \
     awk '{print $1}' | sort | uniq -c | sort -rn | head -20
   ```

3. **Block top attacker IPs at Nginx** (add inside the main `server` block in the esilookup nginx config):
   ```nginx
   deny 1.2.3.4;
   deny 5.6.7.8;
   ```
   Then: `nginx -t && systemctl reload nginx`

4. **Block at AWS Security Group** for persistent protection (survives Nginx config changes).

5. **Check if the lockout was bypassed** (IPv4 vs IPv6 — known vulnerability M1):
   - If attacker appears to be switching IPs rapidly from the same subnet, or alternating IPv4/IPv6, the in-memory rate limiter may have been partially bypassed.
   - If bypass is suspected, rotate the password immediately (see PB-01 step 3).

6. **If attack was successful** (any 200 response on `/api/login`), treat as PB-01.

---

### PB-03: Stored XSS / Data Poisoning via Import

**Indicators:**
- User reports unexpected JavaScript execution in their browser when viewing lookup results
- Imported records contain HTML/script tags when reviewing raw API responses
- Unfamiliar records with suspicious address values (e.g., `<script>`, `javascript:`, `=CMD|...`)

**Background:** The `/api/import` endpoint stores `address` and `source` values without sanitization. These are returned verbatim from `/api/lookup`. If the frontend renders them with `innerHTML`, XSS triggers for any user who looks up a poisoned ESI ID.

**Response:**

1. **Confirm the poisoned records:**
   ```bash
   # Get a fresh token and check db-status
   TOKEN=$(curl -s -X POST http://127.0.0.1:3001/api/login \
     -H "Content-Type: application/json" \
     -d '{"password":"YOUR_PASSWORD"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
   curl -s http://127.0.0.1:3001/api/db-status -H "Authorization: Bearer $TOKEN"
   ```

2. **Clear all in-memory data immediately** (this is destructive — all imported records are lost):
   ```bash
   curl -s -X POST http://127.0.0.1:3001/api/clear -H "Authorization: Bearer $TOKEN"
   ```
   Or restart the process (same effect, also rotates the password):
   ```bash
   pm2 restart esi-lookup
   ```

3. **Assess who was affected:**
   - Check Nginx access logs for `/api/lookup` requests that hit the poisoned ESI ID.
   - If `Content-Security-Policy` headers are not set (currently absent from the direct Node.js responses), the XSS payload executed with full page privileges.

4. **Patch before re-enabling imports:**
   - Sanitize all imported string fields server-side (strip HTML tags).
   - Add `Content-Security-Policy` header.
   - See [Known Vulnerabilities M2](#7-known-vulnerabilities-and-mitigations).

5. **Determine whether the attack originated from an authorized or unauthorized session** — if the latter, also follow PB-01.

---

### PB-04: Denial of Service / Rate Limit Exhaustion

**Indicators:**
- All users receiving HTTP 429 on `/api/lookup` (20 req/min limit per IP)
- Application unresponsive or slow
- PM2 showing high CPU/memory

**Response:**

1. **Check current server health:**
   ```bash
   pm2 monit
   # or
   pm2 show esi-lookup
   ```

2. **Check memory usage** (localDB exhaustion — 200k record limit):
   ```bash
   TOKEN=...
   curl -s http://127.0.0.1:3001/api/db-status -H "Authorization: Bearer $TOKEN"
   # If localRecords is near 200,000, the DB is full
   ```

3. **For rate limit exhaustion:** The sliding-window rate limiter resets after 60 seconds. If a single attacker IP is exhausting the shared 20 req/min lookup limit for all users:
   - Block the attacker IP at Nginx (see PB-02 step 3).
   - Note: rate limiting is per-IP but currently all users share the same limits — there is no per-user quota.

4. **For memory-based DoS** (large import payloads filling localDB):
   - Clear the DB: `POST /api/clear`
   - Restart the process to reclaim memory: `pm2 restart esi-lookup`

5. **For application crash / OOM:**
   ```bash
   pm2 restart esi-lookup
   # PM2 will auto-restart on crash, but verify:
   pm2 list
   pm2 logs esi-lookup --lines 50
   ```

---

### PB-05: Server Crash / Application Unavailability

**Indicators:**
- https://esilookup.com returns 502 Bad Gateway
- `pm2 list` shows esi-lookup as `errored` or `stopped`
- PM2 restart count increasing rapidly (crash loop)

**Response:**

1. **Check PM2 status and last error:**
   ```bash
   pm2 list
   pm2 logs esi-lookup --lines 100 --nostream
   ```

2. **If in a crash loop**, check the error log for the root cause before restarting:
   ```bash
   tail -50 /home/ubuntu/.pm2/logs/esi-lookup-error.log
   ```

3. **Common crash causes and fixes:**

   | Error | Cause | Fix |
   |---|---|---|
   | `EADDRINUSE :3001` | Port already in use | `fuser -k 3001/tcp && pm2 start esi-lookup` |
   | `Cannot find module` | Corrupted node_modules | `cd /home/ubuntu/esi-lookup && npm ci && pm2 restart esi-lookup` |
   | `Out of memory` | localDB filled with large strings | Clear DB, then restart |
   | Unhandled promise rejection | Bug in server code | Check logs, apply hotfix |

4. **Restart the application:**
   ```bash
   pm2 restart esi-lookup
   # Wait 5 seconds, then verify
   curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3001/
   ```

5. **If Nginx is also down:**
   ```bash
   systemctl status nginx
   nginx -t
   systemctl restart nginx
   ```

6. **Verify end-to-end:**
   ```bash
   curl -s -o /dev/null -w "%{http_code}" https://esilookup.com/
   # Expected: 200
   ```

---

### PB-06: Secret / Credential Exposure in Logs

**Indicators:**
- `LOOKUP_PASSWORD` visible in PM2 error log (current known condition)
- `SMT_USERNAME` / `SMT_PASSWORD` or `ERCOT_CERT` / `ERCOT_KEY` visible in logs
- Log files accessed by unauthorized party

**Background:** When `LOOKUP_PASSWORD` is not set as an env var, the server prints the generated password to stderr on every restart. PM2 writes this to `/home/ubuntu/.pm2/logs/esi-lookup-error.log`.

**Immediate actions:**

1. **Rotate the exposed credential immediately** — assume it has been read:
   ```bash
   NEW_PASS=$(openssl rand -hex 32)
   pm2 stop esi-lookup
   pm2 delete esi-lookup
   LOOKUP_PASSWORD="$NEW_PASS" pm2 start /home/ubuntu/esi-lookup/server.js --name esi-lookup
   pm2 save
   echo "New password set. Store it in your password manager."
   ```

2. **Prevent future exposure** — write an ecosystem config file so PM2 always injects the env var:
   ```bash
   cat > /home/ubuntu/esi-lookup/ecosystem.config.js << 'EOF'
   module.exports = {
     apps: [{
       name: 'esi-lookup',
       script: './server.js',
       env: {
         LOOKUP_PASSWORD: process.env.LOOKUP_PASSWORD_PROD
       }
     }]
   };
   EOF
   # Then set LOOKUP_PASSWORD_PROD in /etc/environment or a secrets manager
   ```

3. **Truncate or rotate the log file** containing the exposed secret:
   ```bash
   > /home/ubuntu/.pm2/logs/esi-lookup-error.log
   ```

4. **Restrict log file permissions:**
   ```bash
   chmod 600 /home/ubuntu/.pm2/logs/esi-lookup-*.log
   ```

5. **If `SMT_PASSWORD` or ERCOT keys were exposed:** rotate those credentials with the respective third-party providers (SmartMeterTexas.com, ERCOT).

---

### PB-07: TLS Certificate Expiry or Compromise

**Indicators:**
- Browser shows certificate warning on https://esilookup.com
- Certbot renewal failure alerts
- Certificate validity check fails

**Check certificate status:**
```bash
openssl s_client -connect esilookup.com:443 -servername esilookup.com 2>/dev/null \
  | openssl x509 -noout -dates

# Or via certbot:
certbot certificates
```

**Manual renewal:**
```bash
certbot renew --dry-run   # test first
certbot renew
systemctl reload nginx
```

**If the certificate's private key is compromised** (e.g., key material exposed on disk or in a breach):

1. Revoke the certificate:
   ```bash
   certbot revoke --cert-path /etc/letsencrypt/live/esilookup.com/fullchain.pem
   ```
2. Issue a new certificate:
   ```bash
   certbot certonly --nginx -d esilookup.com -d www.esilookup.com
   systemctl reload nginx
   ```

---

### PB-08: EC2 Host Compromise

**Indicators:**
- Unknown SSH keys in `/home/ubuntu/.ssh/authorized_keys`
- Unknown processes in `ps aux` or `pm2 list`
- Unexpected outbound connections
- AWS CloudTrail shows unexpected API calls from this instance's IAM role
- New cron jobs in `crontab -l` or `/etc/cron*`

**Response:**

1. **Isolate the instance** — modify the EC2 Security Group to block all inbound/outbound except from your IP.

2. **Preserve a forensic snapshot** — take an EBS snapshot from the AWS console before making any changes.

3. **Check for persistence mechanisms:**
   ```bash
   # SSH keys
   cat /home/ubuntu/.ssh/authorized_keys
   cat /root/.ssh/authorized_keys 2>/dev/null

   # Cron jobs
   crontab -l -u ubuntu
   ls /etc/cron* /var/spool/cron/

   # New listening ports
   ss -tlnp

   # Outbound connections
   ss -tnp state established

   # Recently modified files
   find /home /etc /tmp /var/tmp -newer /etc/passwd -type f 2>/dev/null | head -40
   ```

4. **Rotate all credentials** stored on the host:
   - `LOOKUP_PASSWORD` (see PB-06)
   - `SMT_USERNAME` / `SMT_PASSWORD`
   - ERCOT certificate/key
   - Any SSH keys stored on the instance
   - AWS IAM role credentials (rotate via IAM console)

5. **Consider full instance replacement** — if compromise is confirmed, rebuilding from a known-good AMI is safer than forensic cleanup.

---

## 7. Known Vulnerabilities and Mitigations

The following findings are from the internal penetration test conducted 2026-04-14. They represent the current known risk surface.

| ID | Severity | Finding | Status | Mitigation |
|---|---|---|---|---|
| C1 | Critical | `LOOKUP_PASSWORD` logged in plaintext to PM2 stderr on every restart | Open | Set `LOOKUP_PASSWORD` env var persistently via ecosystem config; restrict log permissions |
| H1 | High | Full stack traces (file paths, line numbers) returned in HTTP error responses | Open | Add global Express error handler; suppress stack traces in production |
| H2 | High | Node.js process has no `Content-Security-Policy` header (Nginx has HSTS, X-Frame, X-Content-Type-Options) | Open | Add `helmet` middleware or add `add_header Content-Security-Policy` to Nginx config |
| M1 | Medium | IPv4 vs IPv6 allows brute-force lockout bypass (different `req.ip` for same host) | Open | Normalize `req.ip` by stripping `::ffff:` prefix; or block IPv6 at the security group if not needed |
| M2 | Medium | Imported `address`/`source` fields stored without HTML sanitization — Stored XSS if frontend uses `innerHTML` | Open | Sanitize strings on import; audit frontend rendering |
| M3 | Medium | Password comparison uses `!==` (not timing-safe) | Open | Replace with `crypto.timingSafeEqual()` |
| L1 | Low | Nginx discloses exact version (`Server: nginx/1.24.0 (Ubuntu)`) | Open | Add `server_tokens off;` to nginx.conf |
| L2 | Low | No per-field string length limit on import — large strings accepted without truncation | Open | Add `Math.min(addr.length, 500)` truncation or validation on import |
| L3 | Low | `req.body` not guarded against `undefined` when `Content-Type` is wrong — 500 with stack trace | Open | Guard with `if (!req.body)` check; covered by H1 fix |

---

## 8. Runbook: Operational Commands

### Health check
```bash
# Is the app responding?
curl -s -o /dev/null -w "%{http_code}" https://esilookup.com/

# Is the Node.js process alive?
pm2 list

# How much memory is in use?
pm2 show esi-lookup | grep mem
```

### Rotate the application password
```bash
pm2 stop esi-lookup
pm2 delete esi-lookup
LOOKUP_PASSWORD="$(openssl rand -hex 32)" pm2 start /home/ubuntu/esi-lookup/server.js --name esi-lookup
pm2 save
pm2 logs esi-lookup --lines 5 --nostream   # verify no password warning in output
```

### View live logs
```bash
pm2 logs esi-lookup          # tail both stdout and stderr
tail -f /var/log/nginx/access.log | grep -v "127.0.0.1"
```

### Clear the in-memory database
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:3001/api/login \
  -H "Content-Type: application/json" \
  -d '{"password":"YOUR_PASSWORD"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
curl -s -X POST http://127.0.0.1:3001/api/clear -H "Authorization: Bearer $TOKEN"
```

### Block an IP at Nginx
```bash
# Add inside the esilookup 'server' block in /etc/nginx/sites-enabled/esilookup
# deny 1.2.3.4;
nginx -t && systemctl reload nginx
```

### Restart all services
```bash
pm2 restart esi-lookup
systemctl reload nginx
```

### Check TLS certificate expiry
```bash
certbot certificates
openssl s_client -connect esilookup.com:443 -servername esilookup.com 2>/dev/null \
  | openssl x509 -noout -enddate
```

### Archive logs before an incident action
```bash
STAMP=$(date +%Y%m%d%H%M%S)
cp /var/log/nginx/access.log /tmp/incident-${STAMP}-nginx-access.log
cp /home/ubuntu/.pm2/logs/esi-lookup-error.log /tmp/incident-${STAMP}-pm2-error.log
cp /home/ubuntu/.pm2/logs/esi-lookup-out.log /tmp/incident-${STAMP}-pm2-out.log
```

---

## 9. Post-Incident Review

Complete within **5 business days** of incident resolution.

### Review template

**Incident summary**

| Field | Value |
|---|---|
| Date / time detected | |
| Date / time resolved | |
| Severity | |
| Duration | |
| Playbook(s) used | |

**Timeline** *(key events with timestamps)*

| Time | Event |
|---|---|
| | |

**Root cause**

> What was the underlying technical cause?

**Impact**

> What data, users, or services were affected? Was any data exfiltrated or modified?

**What went well**

> What detection or response actions were effective?

**What went poorly**

> What slowed the response? What was unclear?

**Action items**

| # | Action | Owner | Due date |
|---|---|---|---|
| 1 | | | |

---

## 10. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-04-14 | Security review | Initial document — based on penetration test findings |

This document should be reviewed after every SEV-1 or SEV-2 incident, and at minimum once per quarter.
