'use strict';

const { X509Certificate } = require('crypto');
const fs = require('fs');
const path = require('path');
const { parseCertMeta } = require('./cert-parser');
const { loadConfig } = require('./config-loader');

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
    const obj = {};
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
    const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 cert-util/1.0' } });
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
// { downloadedAt, totalCount, prevCount?, addedCount?, added?: [{certName,isRoot,fingerprint}] }
// added 最多保留 diffStoreLimit 筆，以控制快取檔案大小（設定於 config.json ccadb.diffStoreLimit）

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

// 顯示某筆 history 的差異（不論是剛下載還是從快取讀取，皆可呼叫）
function printDiff(record, prefix) {
  const { ccadb: { diffDisplayLimit } } = loadConfig();
  const ts   = toGmt8(record.downloadedAt);
  const cur  = record.totalCount?.toLocaleString() ?? '?';
  const prev = record.prevCount != null ? `，前次 ${record.prevCount.toLocaleString()} 筆` : '';
  console.log(`${prefix}下載時間：${ts}　共 ${cur} 筆${prev}`);

  if (record.addedCount == null) return; // 第一次下載，無前次可比較

  if (record.addedCount === 0) {
    console.log(`${prefix}與前次相比：無新增項目。`);
    return;
  }

  const stored  = record.added ?? [];
  const display = stored.slice(0, diffDisplayLimit);
  console.log(`${prefix}與前次相比：新增 ${record.addedCount} 筆`);
  display.forEach(e => {
    const tag   = e.isRoot ? 'Root' : 'ICA ';
    const label = e.certName || e.fingerprint || '(unknown)';
    console.log(`${prefix}  + [${tag}] ${label}`);
  });
  const remaining = record.addedCount - diffDisplayLimit;
  if (remaining > 0) console.log(`${prefix}  … 及其他 ${remaining} 筆`);
}

function saveCache(newEntries, oldRaw) {
  try {
    const { ccadb: { diffStoreLimit, diffDisplayLimit } } = loadConfig();
    const hasPrev = oldRaw?.entries?.length > 0;

    // 計算 diff
    let addedCount, addedRecord;
    if (hasPrev) {
      const oldFps = new Set(oldRaw.entries.map(e => e.fingerprint).filter(Boolean));
      const added  = newEntries.filter(e => e.fingerprint && !oldFps.has(e.fingerprint));
      addedCount   = added.length;
      addedRecord  = added.slice(0, diffStoreLimit).map(e => ({
        certName:    e.certName || '',
        isRoot:      e.isRoot,
        fingerprint: e.fingerprint,
      }));
    }

    const now = new Date().toISOString();
    const prevHistory = Array.isArray(oldRaw?.downloadHistory) ? oldRaw.downloadHistory : [];

    // 新的 history 紀錄，包含 diff 資訊
    const newRecord = {
      downloadedAt: now,
      totalCount:   newEntries.length,
      ...(hasPrev && {
        prevCount:   oldRaw.entries.length,
        addedCount,
        added:       addedRecord,
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
  } catch (err) {
    console.warn('[ccadb] 無法寫入快取：', err);
  }
}

async function fetchCcadbEntries() {
  const raw = loadCacheRaw();

  if (raw && (Date.now() - raw.fetchedAt <= CACHE_TTL_MS)) {
    // 使用快取：仍顯示上次下載的 diff，避免使用者錯過
    const history = Array.isArray(raw.downloadHistory) ? raw.downloadHistory : [];
    const last    = history[history.length - 1];
    console.log('[ccadb] 使用本機快取（24 小時內）。');
    if (last) printDiff(last, '[ccadb] ');
    return raw.entries.map(convertDates);
  }

  if (raw) console.log('[ccadb] 快取已過期，重新下載...');
  const entries = await downloadAllCcadbData();
  saveCache(entries, raw);
  return entries;
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
