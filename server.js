'use strict';

const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory local lookup table — loaded from CSV upload or env-configured file
// Maps esiId (string, digits only) -> { address, source }
let localDB = new Map();

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

// ── Source: Local database (CSV upload or env-seeded) ──────────────────────
function lookupLocal(esiId) {
  const entry = localDB.get(esiId);
  if (entry) {
    return { source: entry.source || 'Local Database', status: 'found', address: entry.address };
  }
  return { source: 'Local Database', status: 'not_found', address: null };
}

// ── Source: SmartMeterTexas.com ────────────────────────────────────────────
// Requires SMT_USERNAME + SMT_PASSWORD env vars.
// SMT is the official ERCOT/TDU customer portal — the authoritative source for
// meter-level data including service addresses.
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

    // Fetch meter/premise details
    const detailRes = await fetch(`https://www.smartmetertexas.com/smartmeters/?esiId=${encodeURIComponent(esiId)}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0',
      },
      timeout: 12000,
    });

    const data = await detailRes.json();
    // Response shape varies — try common field names
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
// Requires ERCOT market participant digital certificate.
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

// ── CSV import endpoint ─────────────────────────────────────────────────────
// POST /api/import  { rows: [ { esiId, address, source? }, ... ] }
// OR pass raw CSV text as body.address field
app.post('/api/import', (req, res) => {
  const { rows, csv, source } = req.body;
  let imported = 0;
  let skipped = 0;
  const importSource = source || 'Imported Data';

  if (Array.isArray(rows)) {
    for (const row of rows) {
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
    // Parse raw CSV text: first row is headers
    const lines = String(csv).split(/\r?\n/).filter(l => l.trim());
    if (lines.length > 1) {
      const headers = lines[0].split(',').map(h => h.replace(/^["']|["']$/g, '').trim().toLowerCase());
      const esiCol = headers.findIndex(h => h.includes('esi'));
      const addrCol = headers.findIndex(h => h.includes('address') || h.includes('addr'));
      const srcCol = headers.findIndex(h => h.includes('source') || h.includes('src'));

      if (esiCol !== -1 && addrCol !== -1) {
        for (let i = 1; i < lines.length; i++) {
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

// ── Database status endpoint ────────────────────────────────────────────────
app.get('/api/db-status', (req, res) => {
  const smtConfigured = !!(process.env.SMT_USERNAME && process.env.SMT_PASSWORD);
  const ercotConfigured = !!(process.env.ERCOT_CERT && process.env.ERCOT_KEY);
  res.json({
    localRecords: localDB.size,
    smtConfigured,
    ercotConfigured,
  });
});

// ── Clear local database ────────────────────────────────────────────────────
app.post('/api/clear', (req, res) => {
  localDB.clear();
  res.json({ ok: true });
});

// ── Main lookup endpoint ────────────────────────────────────────────────────
app.post('/api/lookup', async (req, res) => {
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

      // Check local DB first (fast, no network)
      const local = lookupLocal(esiId);
      if (local.status === 'found') {
        return {
          esiId: rawId, esiIdClean: esiId, tdsp,
          address: local.address, source: local.source, status: 'found',
          sourceDetails: [{ source: local.source, status: 'found', note: null }],
        };
      }

      // Fall back to remote sources in parallel
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
