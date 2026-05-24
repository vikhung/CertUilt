'use strict';

const { X509Certificate } = require('crypto');
const fs = require('fs');
const path = require('path');
const { parseCertMeta } = require('./cert-parser');

const CCADB_INTERMEDIATES_URL =
  'https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV';
const CCADB_ROOTS_URL =
  'https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV';

const CACHE_FILE = path.join(process.cwd(), '.ccadb-cache.json');
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

function normalizeHex(raw) {
  if (!raw) return '';
  return raw.replace(/[:\s]/g, '').toLowerCase();
}

// RFC 4180 CSV parser — supports multi-line quoted fields (needed for PEM data)
function parseCsvWithHeaders(text) {
  const rows = [];
  let i = 0;
  const len = text.length;

  while (i < len) {
    const row = [];

    while (true) {
      let field;

      if (i < len && text[i] === '"') {
        i++;
        field = '';
        while (i < len) {
          if (text[i] === '"') {
            if (i + 1 < len && text[i + 1] === '"') { field += '"'; i += 2; }
            else { i++; break; }
          } else { field += text[i++]; }
        }
      } else {
        field = '';
        while (i < len && text[i] !== ',' && text[i] !== '\r' && text[i] !== '\n') {
          field += text[i++];
        }
      }

      row.push(field);
      if (i < len && text[i] === ',') { i++; } else { break; }
    }

    if (i < len && text[i] === '\r') i++;
    if (i < len && text[i] === '\n') i++;
    if (row.length > 1 || (row.length === 1 && row[0] !== '')) rows.push(row);
  }

  if (rows.length === 0) return [];
  const headers = rows[0];
  return rows.slice(1).map(row => {
    const obj = Object.create(null);
    headers.forEach((h, idx) => { obj[h] = row[idx] ?? ''; });
    return obj;
  });
}

function parsePemFromCsv(pemField) {
  try {
    const cleaned = pemField.replace(/^'|'$/g, '').trim();
    if (!cleaned.startsWith('-----BEGIN CERTIFICATE-----')) return null;
    return new X509Certificate(cleaned);
  } catch { return null; }
}

function buildEntryFromCsv(row, ski, aki, isRoot) {
  const certName =
    row['Certificate Name'] ?? row['Common Name or Certificate Name'] ??
    row['Cert Name'] ?? row['Common Name'] ?? '';
  const caOwner = row['CA Owner'] ?? row['Owner'] ?? '';
  const subject = row['Subject'] ?? row['Certificate Subject'] ?? '';
  const issuer  = row['Issuer']  ?? row['Certificate Issuer']  ?? '';
  const status  =
    row['Status'] ?? row['Cert Status'] ?? row['Certificate Status'] ??
    row['Trust Bits'] ?? '';
  const validFromStr = row['Valid From [GMT]'] ?? row['Valid From'] ?? '';
  const validToStr   = row['Valid To [GMT]']   ?? row['Valid To']   ?? '';

  return {
    caOwner, certName, subject, issuer, ski, aki,
    fingerprint: '',
    pem: '',
    validFrom: validFromStr ? new Date(validFromStr) : new Date(0),
    validTo:   validToStr   ? new Date(validToStr)   : new Date(0),
    serialNumber: row['Certificate Serial Number'] ?? row['Serial Number'] ?? '',
    status, isRoot,
  };
}

async function fetchAndParseCsv(url, label, isRoot) {
  console.log(`[ccadb] 下載 ${label}...`);
  let text;
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 cert-util/1.0' },
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    text = await res.text();
  } catch (err) {
    console.warn(`[ccadb] 警告：無法下載 ${label}: ${err.message}`);
    return [];
  }

  const records = parseCsvWithHeaders(text);
  const entries = [];
  let parsed = 0;

  for (const row of records) {
    const pemField = row['PEM Info'] ?? row['PEM'] ?? row['Certificate PEM'] ?? '';
    const cleanedPem = pemField.replace(/^'|'$/g, '').trim();
    const cert = parsePemFromCsv(pemField);
    const csvEntry = buildEntryFromCsv(row, '', '', isRoot);

    if (cert) {
      const meta = parseCertMeta(cert);
      csvEntry.ski = meta.ski;
      csvEntry.aki = meta.aki;
      csvEntry.fingerprint = meta.fingerprint;
      if (meta.subject) csvEntry.subject = meta.subject;
      if (meta.issuer)  csvEntry.issuer  = meta.issuer;
      csvEntry.pem = cleanedPem;
      parsed++;
    } else {
      const fp =
        row['SHA-256 Fingerprint'] ?? row['SHA256 Fingerprint'] ??
        row['Fingerprint (SHA256)'] ?? '';
      csvEntry.fingerprint = normalizeHex(fp);
    }

    entries.push(csvEntry);
  }

  console.log(`[ccadb] ${label}：${entries.length} 筆（${parsed} 筆含 PEM）`);
  return entries;
}

async function downloadAllCcadbData() {
  const [intermediates, roots] = await Promise.all([
    fetchAndParseCsv(CCADB_INTERMEDIATES_URL, 'Intermediate CA CSV', false),
    fetchAndParseCsv(CCADB_ROOTS_URL, 'Root CA CSV', true),
  ]);

  const seen = new Set();
  const merged = [];
  for (const entry of [...roots, ...intermediates]) {
    const key = entry.fingerprint || `${entry.certName}|${entry.validFrom}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(entry);
  }

  console.log(`[ccadb] 合計 ${merged.length} 筆（根 CA ${roots.length} + 中繼 ${intermediates.length}，去重後）`);
  return merged;
}

// ─── 快取 ────────────────────────────────────────────────────────────────────

// 每筆 downloadHistory 格式：
// { downloadedAt, totalCount, prevCount?, addedCount?, added?: [{certName,isRoot,fingerprint}],
//                                          removedCount?, removed?: [{certName,isRoot,fingerprint}] }
// added/removed 完整保留所有項目，無數量限制

function loadCacheRaw() {
  if (!fs.existsSync(CACHE_FILE)) return null;
  try { return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')); } catch { return null; }
}

function convertDates(e) {
  return { ...e, validFrom: new Date(e.validFrom), validTo: new Date(e.validTo) };
}

function toGmt8(isoStr) {
  return new Date(new Date(isoStr).getTime() + 8 * 60 * 60 * 1000)
    .toISOString().slice(0, 19).replace('T', ' ');
}

// Returns yyyyMMdd in GMT+8 (used as directory name for new-cert exports)
function toGmt8Date(isoStr) {
  return new Date(new Date(isoStr).getTime() + 8 * 60 * 60 * 1000)
    .toISOString().slice(0, 10).replace(/-/g, '');
}

// Scans full downloadHistory to build diff info:
//   - latestAdded  : most recent record that has additions (for 00.new dir naming)
//   - removedFingerprints : ALL removed fps across ALL history records (for 02.notExist moving)
// Returns { date, fingerprints, addedCount, removedFingerprints } or null.
function getLatestDiffFromHistory(history) {
  let latestAddedDate  = null;
  let latestAddedFps   = new Set();
  let latestAddedCount = 0;
  const removedFingerprints = new Set();

  for (let i = history.length - 1; i >= 0; i--) {
    const rec = history[i];
    // Aggregate ALL removed fps from every history record
    if (rec.removed?.length > 0) {
      for (const e of rec.removed) {
        if (e.fingerprint) removedFingerprints.add(e.fingerprint);
      }
    }
    // Find the most recent record that has added entries
    if (latestAddedDate === null && rec.addedCount > 0 && rec.added?.length > 0) {
      latestAddedDate  = toGmt8Date(rec.downloadedAt);
      latestAddedFps   = new Set(rec.added.map(e => e.fingerprint).filter(Boolean));
      latestAddedCount = rec.addedCount;
    }
  }

  if (latestAddedDate === null && removedFingerprints.size === 0) return null;
  return {
    date:               latestAddedDate,
    fingerprints:       latestAddedFps,
    addedCount:         latestAddedCount,
    removedFingerprints,
  };
}

// 顯示某筆 history 的差異（不論是剛下載還是從快取讀取，皆可呼叫）
function printDiff(record, prefix) {
  const ts   = toGmt8(record.downloadedAt);
  const cur  = record.totalCount?.toLocaleString() ?? '?';
  const prev = record.prevCount != null ? `，前次 ${record.prevCount.toLocaleString()} 筆` : '';
  console.log(`${prefix}下載時間：${ts}　共 ${cur} 筆${prev}`);

  if (record.addedCount == null) return; // 第一次下載，無前次可比較

  const addedCnt   = record.addedCount   ?? 0;
  const removedCnt = record.removedCount ?? 0;

  if (addedCnt === 0 && removedCnt === 0) {
    console.log(`${prefix}與前次相比：無異動。`);
    return;
  }

  if (addedCnt > 0) {
    console.log(`${prefix}新增 ${addedCnt} 筆：`);
    (record.added ?? []).forEach(e => {
      const tag = e.isRoot ? 'Root' : 'ICA ';
      console.log(`${prefix}  + [${tag}] ${e.certName || e.fingerprint || '(unknown)'}`);
    });
  }

  if (removedCnt > 0) {
    console.log(`${prefix}移除 ${removedCnt} 筆：`);
    (record.removed ?? []).forEach(e => {
      const tag = e.isRoot ? 'Root' : 'ICA ';
      console.log(`${prefix}  - [${tag}] ${e.certName || e.fingerprint || '(unknown)'}`);
    });
  }
}

// Returns { date, fingerprints, addedCount, removedFingerprints } or null.
function saveCache(newEntries, oldRaw) {
  try {
    const hasPrev = oldRaw?.entries?.length > 0;

    // 計算 diff（新增 + 移除），完整保留所有項目
    let addedCount, addedRecord, removedCount, removedRecord;
    if (hasPrev) {
      const oldFps = new Set(oldRaw.entries.map(e => e.fingerprint).filter(Boolean));
      const newFps = new Set(newEntries.map(e => e.fingerprint).filter(Boolean));

      const added    = newEntries.filter(e => e.fingerprint && !oldFps.has(e.fingerprint));
      addedCount     = added.length;
      addedRecord    = added.map(e => ({
        certName: e.certName || '', isRoot: e.isRoot, fingerprint: e.fingerprint,
      }));

      const removed  = oldRaw.entries.filter(e => e.fingerprint && !newFps.has(e.fingerprint));
      removedCount   = removed.length;
      removedRecord  = removed.map(e => ({
        certName: e.certName || '', isRoot: !!e.isRoot, fingerprint: e.fingerprint,
      }));
    }

    const now = new Date().toISOString();
    const prevHistory = Array.isArray(oldRaw?.downloadHistory) ? oldRaw.downloadHistory : [];

    // 新的 history 紀錄，包含新增與移除 diff
    const newRecord = {
      downloadedAt: now,
      totalCount:   newEntries.length,
      ...(hasPrev && {
        prevCount:    oldRaw.entries.length,
        addedCount,   added:   addedRecord,
        removedCount, removed: removedRecord,
      }),
    };

    // 顯示 diff（下載當下立即顯示）
    printDiff(newRecord, '[ccadb] ');

    const data = {
      fetchedAt:       Date.now(),
      downloadHistory: [...prevHistory, newRecord],
      entries:         newEntries.map(e => ({
        ...e,
        validFrom: e.validFrom.toISOString(),
        validTo:   e.validTo.toISOString(),
      })),
    };
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2), 'utf8');

    if (hasPrev && (addedCount > 0 || removedCount > 0)) {
      return {
        date:               toGmt8Date(now),
        fingerprints:       new Set((addedRecord  ?? []).map(e => e.fingerprint).filter(Boolean)),
        addedCount:         addedCount ?? 0,
        removedFingerprints: new Set((removedRecord ?? []).map(e => e.fingerprint).filter(Boolean)),
      };
    }
    return null;
  } catch (err) {
    console.warn('[ccadb] 無法寫入快取：', err);
    return null;
  }
}

// Returns { entries: Entry[], latestDiff: { date, fingerprints, addedCount, removedFingerprints } | null }
async function fetchCcadbEntries() {
  const raw = loadCacheRaw();

  if (raw && (Date.now() - raw.fetchedAt <= CACHE_TTL_MS)) {
    // 使用快取：仍顯示上次下載的 diff，避免使用者錯過
    const history = Array.isArray(raw.downloadHistory) ? raw.downloadHistory : [];
    const last    = history[history.length - 1];
    console.log('[ccadb] 使用本機快取（24 小時內）。');
    if (last) printDiff(last, '[ccadb] ');
    const latestDiff = getLatestDiffFromHistory(history);
    return { entries: raw.entries.map(convertDates), latestDiff };
  }

  if (raw) console.log('[ccadb] 快取已過期，重新下載...');
  const entries    = await downloadAllCcadbData();
  const latestDiff = saveCache(entries, raw);
  return { entries, latestDiff };
}

// ─── 索引 ────────────────────────────────────────────────────────────────────

function buildAkiIndex(entries) {
  const index = new Map();
  for (const entry of entries) {
    if (entry.isRoot) continue;
    const key = normalizeHex(entry.aki);
    if (!key) continue;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(entry);
  }
  return index;
}

function buildSkiIndex(entries) {
  const index = new Map();
  for (const entry of entries) {
    const key = normalizeHex(entry.ski);
    if (!key || index.has(key)) continue;
    index.set(key, entry);
  }
  return index;
}

module.exports = { fetchCcadbEntries, buildAkiIndex, buildSkiIndex };
