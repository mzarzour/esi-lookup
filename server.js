'use strict';

const crypto = require('crypto');
const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3001;

// ── Auth config ────────────────────────────────────────────────────────────
const LOOKUP_PASSWORD = process.env.LOOKUP_PASSWORD || (() => {
  const generated = crypto.randomBytes(16).toString('hex');
  console.warn(`\nWARNING: LOOKUP_PASSWORD not set — using generated password for this session:\n  ${generated}\n  Set LOOKUP_PASSWORD env var to make this permanent.\n`);
  return generated;
})();

// Active tokens: token -> lastUsedAt (ms). Tokens expire after 8 hours of inactivity.
const activeTokens = new Map();
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000;

setInterval(() => {
  const cutoff = Date.now() - TOKEN_TTL_MS;
  for (const [token, lastUsed] of activeTokens) {
    if (lastUsed < cutoff) activeTokens.delete(token);
  }
}, 30 * 60 * 1000).unref();

// ── Rate limiting (in-memory sliding window, no extra deps) ────────────────
const RATE_WINDOW_MS = 60_000;
const LOOKUP_RATE_LIMIT = 20;   // /api/lookup requests per minute per IP
const GENERAL_RATE_LIMIT = 100; // all other /api/* requests per minute per IP

const rateLimitStore = new Map(); // `${ip}:${key}` -> timestamps[]

function isRateLimited(ip, key, limit) {
  const storeKey = `${ip}:${key}`;
  const now = Date.now();
  const recent = (rateLimitStore.get(storeKey) || []).filter(t => t > now - RATE_WINDOW_MS);
  recent.push(now);
  rateLimitStore.set(storeKey, recent);
  return recent.length > limit;
}

setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  for (const [key, timestamps] of rateLimitStore) {
    const recent = timestamps.filter(t => t > cutoff);
    if (recent.length === 0) rateLimitStore.delete(key);
    else rateLimitStore.set(key, recent);
  }
}, 5 * 60 * 1000).unref();

// ── Login brute-force protection ───────────────────────────────────────────
const loginAttempts = new Map(); // ip -> { count, lockedUntil }
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function isLoginLocked(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || !entry.lockedUntil) return false;
  if (Date.now() < entry.lockedUntil) return true;
  loginAttempts.delete(ip); // lock expired
  return false;
}

function recordLoginFailure(ip) {
  const entry = loginAttempts.get(ip) || { count: 0, lockedUntil: null };
  entry.count += 1;
  if (entry.count >= MAX_LOGIN_ATTEMPTS) {
    entry.lockedUntil = Date.now() + LOCKOUT_MS;
    entry.count = 0;
  }
  loginAttempts.set(ip, entry);
}

// ── CORS (restricted — only enabled if CORS_ORIGIN is explicitly set) ──────
const corsOrigin = process.env.CORS_ORIGIN;
if (corsOrigin) {
  app.use(cors({ origin: corsOrigin, credentials: true }));
  console.log(`CORS enabled for origin: ${corsOrigin}`);
}

// ── Body parsing & static files ────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token || !activeTokens.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  activeTokens.set(token, Date.now()); // refresh last-used
  next();
}

// ── Rate limit middleware factories ────────────────────────────────────────
function rateLimit(key, limit) {
  return (req, res, next) => {
    if (isRateLimited(req.ip, key, limit)) {
      return res.status(429).json({ error: 'Too many requests — please slow down.' });
    }
    next();
  };
}

// ── Login endpoint (unauthenticated, brute-force protected) ────────────────
app.post('/api/login', rateLimit('login', 20), (req, res) => {
  if (isLoginLocked(req.ip)) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
  }
  const { password } = req.body || {};
  if (typeof password !== 'string' || password !== LOOKUP_PASSWORD) {
    recordLoginFailure(req.ip);
    return res.status(401).json({ error: 'Invalid password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  activeTokens.set(token, Date.now());
  res.json({ token });
});

// ── All remaining /api/* routes require authentication ─────────────────────
app.use('/api', requireAuth);

// ── Logout ─────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  const token = req.headers['authorization'].slice(7);
  activeTokens.delete(token);
  res.json({ ok: true });
});

// ── In-memory local lookup table ───────────────────────────────────────────
let localDB = new Map();
const MAX_DB_RECORDS = 200_000;
const MAX_IMPORT_RECORDS = 50_000;

// ── TDSP detection from ESI ID prefix ──────────────────────────────────────
function detectTDSP(esiId) {
  if (esiId.startsWith('1008')) return 'Oncor';
  if (esiId.startsWith('1044')) return 'CenterPoint Energy';
  if (esiId.startsWith('1007')) return 'AEP Texas Central';
  if (esiId.startsWith('1002')) return 'AEP Texas';
  if (esiId.startsWith('1040')) return 'TNMP';
  if (esiId.startsWith('1041')) return 'Lubbock Power & Light';
  return 'Unknown TDSP';
}

function cleanESIId(raw) {
  return String(raw).replace(/\D/g, '');
}

// ── Source: Local database ─────────────────────────────────────────────────
function lookupLocal(esiId) {
  const entry = localDB.get(esiId);
  if (entry) {
    return { source: entry.source || 'Local Database', status: 'found', address: entry.address };
  }
  return { source: 'Local Database', status: 'not_found', address: null };
}

// ── Source: SmartMeterTexas.com ────────────────────────────────────────────
async function lookupSmartMeterTexas(esiId) {
  const username = process.env.SMT_USERNAME;
  const password = process.env.SMT_PASSWORD;

  if (!username || !password) {
    return {
      source: 'SmartMeterTexas.com',
      status: 'auth_required',
      address: null,
      note: 'Set SMT_USERNAME and SMT_PASSWORD env vars to enable.',
    };
  }

  try {
    const authRes = await fetch('https://www.smartmetertexas.com/commonapi/user/authenticate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ userName: username, password, rememberMe: 'false' }),
      timeout: 12000,
    });

    if (!authRes.ok) {
      return { source: 'SmartMeterTexas.com', status: 'auth_failed', address: null, note: `Auth HTTP ${authRes.status}` };
    }

    const authData = await authRes.json();
    const token = authData.token || authData.authToken || authData.TokenID;

    if (!token) {
      return { source: 'SmartMeterTexas.com', status: 'auth_failed', address: null, note: 'No token in auth response' };
    }

    const detailRes = await fetch(`https://www.smartmetertexas.com/smartmeters/?esiId=${encodeURIComponent(esiId)}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0',
      },
      timeout: 12000,
    });

    const data = await detailRes.json();
    const address = (
      data.serviceAddress ||
      data.address ||
      data.premiseAddress ||
      data.ServiceAddress ||
      (data.data && (data.data.serviceAddress || data.data.address)) ||
      (Array.isArray(data) && data[0] && data[0].serviceAddress)
    );

    if (address) {
      return { source: 'SmartMeterTexas.com', status: 'found', address };
    }
    return { source: 'SmartMeterTexas.com', status: 'not_found', address: null };
  } catch (err) {
    return { source: 'SmartMeterTexas.com', status: 'error', address: null, note: err.message };
  }
}

// ── Source: ERCOT MIS ──────────────────────────────────────────────────────
function lookupERCOT(esiId) {
  const hasCert = !!(process.env.ERCOT_CERT && process.env.ERCOT_KEY);
  return Promise.resolve({
    source: 'ERCOT MIS',
    status: 'auth_required',
    address: null,
    note: hasCert
      ? 'ERCOT cert configured but integration not yet implemented.'
      : 'Set ERCOT_CERT and ERCOT_KEY env vars (market participant certificate).',
  });
}

// ── CSV import endpoint ────────────────────────────────────────────────────
app.post('/api/import', rateLimit('import', GENERAL_RATE_LIMIT), (req, res) => {
  const { rows, csv, source } = req.body;
  let imported = 0;
  let skipped = 0;
  const importSource = source || 'Imported Data';

  if (localDB.size >= MAX_DB_RECORDS) {
    return res.status(400).json({ error: `Database is full (${MAX_DB_RECORDS.toLocaleString()} record limit). Clear existing data first.` });
  }

  if (Array.isArray(rows)) {
    if (rows.length > MAX_IMPORT_RECORDS) {
      return res.status(400).json({ error: `Too many rows — maximum ${MAX_IMPORT_RECORDS.toLocaleString()} per import.` });
    }
    for (const row of rows) {
      if (localDB.size >= MAX_DB_RECORDS) break;
      const id = cleanESIId(row.esiId || row.esi_id || row.ESI_ID || row.ESIID || '');
      const addr = String(row.address || row.Address || row.service_address || row.ServiceAddress || '').trim();
      if (id.length >= 5 && addr) {
        localDB.set(id, { address: addr, source: row.source || importSource });
        imported++;
      } else {
        skipped++;
      }
    }
  }

  if (csv) {
    const lines = String(csv).split(/\r?\n/).filter(l => l.trim());
    if (lines.length - 1 > MAX_IMPORT_RECORDS) {
      return res.status(400).json({ error: `Too many rows — maximum ${MAX_IMPORT_RECORDS.toLocaleString()} per import.` });
    }
    if (lines.length > 1) {
      const headers = lines[0].split(',').map(h => h.replace(/^["']|["']$/g, '').trim().toLowerCase());
      const esiCol = headers.findIndex(h => h.includes('esi'));
      const addrCol = headers.findIndex(h => h.includes('address') || h.includes('addr'));
      const srcCol = headers.findIndex(h => h.includes('source') || h.includes('src'));

      if (esiCol !== -1 && addrCol !== -1) {
        for (let i = 1; i < lines.length; i++) {
          if (localDB.size >= MAX_DB_RECORDS) break;
          const cols = lines[i].split(',').map(c => c.replace(/^["']|["']$/g, '').trim());
          const id = cleanESIId(cols[esiCol] || '');
          const addr = cols[addrCol] || '';
          if (id.length >= 5 && addr) {
            localDB.set(id, { address: addr, source: (srcCol !== -1 ? cols[srcCol] : null) || importSource });
            imported++;
          } else {
            skipped++;
          }
        }
      } else {
        return res.status(400).json({ error: 'CSV must have columns containing "esi" and "address" in the headers.' });
      }
    }
  }

  res.json({ imported, skipped, total: localDB.size });
});

// ── Database status endpoint ───────────────────────────────────────────────
app.get('/api/db-status', rateLimit('general', GENERAL_RATE_LIMIT), (req, res) => {
  const smtConfigured = !!(process.env.SMT_USERNAME && process.env.SMT_PASSWORD);
  const ercotConfigured = !!(process.env.ERCOT_CERT && process.env.ERCOT_KEY);
  res.json({ localRecords: localDB.size, smtConfigured, ercotConfigured });
});

// ── Clear local database ───────────────────────────────────────────────────
app.post('/api/clear', rateLimit('general', GENERAL_RATE_LIMIT), (req, res) => {
  localDB.clear();
  res.json({ ok: true });
});

// ── Main lookup endpoint ───────────────────────────────────────────────────
app.post('/api/lookup', rateLimit('lookup', LOOKUP_RATE_LIMIT), async (req, res) => {
  const { esiIds } = req.body;

  if (!Array.isArray(esiIds) || esiIds.length === 0) {
    return res.status(400).json({ error: 'Provide an array of ESI IDs' });
  }

  if (esiIds.length > 500) {
    return res.status(400).json({ error: 'Maximum 500 ESI IDs per request' });
  }

  const results = await Promise.all(
    esiIds.map(async (rawId) => {
      const esiId = cleanESIId(rawId);

      if (!esiId || esiId.length < 5) {
        return { esiId: rawId, esiIdClean: esiId, tdsp: 'Unknown', address: null, source: null, status: 'invalid' };
      }

      const tdsp = detectTDSP(esiId);

      const local = lookupLocal(esiId);
      if (local.status === 'found') {
        return {
          esiId: rawId, esiIdClean: esiId, tdsp,
          address: local.address, source: local.source, status: 'found',
          sourceDetails: [{ source: local.source, status: 'found', note: null }],
        };
      }

      const [smt, ercot] = await Promise.all([
        lookupSmartMeterTexas(esiId),
        lookupERCOT(esiId),
      ]);

      const remoteSources = [smt, ercot];
      const found = remoteSources.find(s => s.status === 'found');

      return {
        esiId: rawId,
        esiIdClean: esiId,
        tdsp,
        address: found ? found.address : null,
        source: found ? found.source : null,
        status: found ? 'found' : 'not_found',
        sourceDetails: [
          { source: 'Local Database', status: local.status, note: null },
          ...remoteSources.map(s => ({ source: s.source, status: s.status, note: s.note || null })),
        ],
      };
    })
  );

  res.json({ results });
});

app.listen(PORT, () => {
  console.log(`ESI Lookup server running on port ${PORT}`);
});
