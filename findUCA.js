'use strict';

const path = require('path');
const fs = require('fs');
const { parseCertMeta, parsePemChain } = require('./lib/cert-parser');
const { fetchCcadbEntries, buildAkiIndex, buildSkiIndex } = require('./lib/ccadb-client');
const { buildTree, printTree } = require('./lib/ca-tree');
const { loadConfig } = require('./lib/config-loader');
const { generateReports } = require('./lib/report-generator');
const { initLogger } = require('./lib/logger');

function normalizeHex(raw) {
  if (!raw) return '';
  return raw.replace(/[:\s]/g, '').toLowerCase();
}

function sanitizeFilename(name) {
  return (name ?? '').replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').trim().slice(0, 120) || 'unknown';
}

// Format a raw hex SKI/AKI string as colon-separated pairs (e.g. "1A:2B:3C...")
function formatSki(hex) {
  if (!hex) return '';
  const h = normalizeHex(hex);
  return h.match(/.{1,2}/g)?.join(':').toUpperCase() ?? h;
}

function isActualRoot(cert, meta) {
  if (cert.subject === cert.issuer) return true;
  if (!meta.aki) return true;
  if (meta.aki === meta.ski) return true;
  return false;
}

function isCAcert(cert) {
  return cert.ca === true;
}

function extractLabel(dn) {
  if (!dn) return '';
  const cn = dn.match(/CN\s*=\s*([^,\n]+)/i)?.[1]?.trim();
  if (cn) return cn;
  const o = dn.match(/O\s*=\s*([^,\n]+)/i)?.[1]?.trim();
  if (o) return o;
  return dn.slice(0, 80);
}

function traceToRootSki(startAki, skiIndex) {
  let currentAki = startAki;
  const visited = new Set();
  const chainNodes = [];
  let lastEntry = null;

  while (currentAki) {
    if (visited.has(currentAki)) break;
    visited.add(currentAki);

    const entry = skiIndex.get(currentAki);
    if (!entry) {
      return { rootSki: currentAki, lastIntermediate: lastEntry, chainNodes };
    }

    lastEntry = entry;
    chainNodes.push({ name: entry.certName || extractLabel(entry.subject), ski: entry.ski, aki: entry.aki ?? '' });

    const entryAki = entry.aki ?? '';
    if (!entryAki || entryAki === entry.ski) {
      return { rootSki: entry.ski, lastIntermediate: entry, chainNodes };
    }

    currentAki = entryAki;
  }

  return { rootSki: currentAki, lastIntermediate: lastEntry, chainNodes };
}

function findTopmostCA(certs) {
  const skiSet = new Set(certs.map(c => parseCertMeta(c).ski).filter(Boolean));
  const caCerts = certs.filter(isCAcert);
  if (caCerts.length === 0) return null;

  const top = caCerts.find(c => {
    const meta = parseCertMeta(c);
    return !meta.aki || !skiSet.has(meta.aki) || meta.aki === meta.ski;
  });

  return top ?? caCerts[0];
}

// ─── 匯出 UCA PEM 檔 ─────────────────────────────────────────────────────────

function exportUcaPems(rootLabel, nodes) {
  const now        = new Date();
  const dirName    = sanitizeFilename(rootLabel);
  const activeDir  = path.join(process.cwd(), 'pem',          dirName);
  const expireDir  = path.join(process.cwd(), 'pem', 'expire', dirName);

  let total = 0, writtenActive = 0, writtenExpire = 0;
  const seenActive  = new Map();
  const seenExpire  = new Map();

  function writeFile(outDir, seenMap, entry) {
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    const base  = sanitizeFilename(entry.certName || entry.fingerprint || `cert_${total}`);
    const count = seenMap.get(base) ?? 0;
    seenMap.set(base, count + 1);
    const fileName = count === 0
      ? `${base}.crt`
      : `${base}_${(entry.fingerprint || '').slice(0, 8) || count}.crt`;
    fs.writeFileSync(path.join(outDir, fileName), entry.pem + '\n', 'utf8');
  }

  function walk(nodeList) {
    for (const node of nodeList) {
      total++;
      if (node.info.pem) {
        const expired = node.info.validTo instanceof Date && node.info.validTo < now;
        if (expired) {
          writeFile(expireDir, seenExpire, node.info);
          writtenExpire++;
        } else {
          writeFile(activeDir, seenActive, node.info);
          writtenActive++;
        }
      }
      walk(node.children);
    }
  }

  walk(nodes);
  if (total > 0) {
    console.log(`[pem] 有效：${writtenActive} 個 → pem/${dirName}/`);
    if (writtenExpire > 0) {
      console.log(`[pem] 已過期：${writtenExpire} 個 → pem/expire/${dirName}/`);
    }
  }
}

// ─── 處理單一憑證檔 ───────────────────────────────────────────────────────────

function processCertFile(certPath, akiIndex, skiIndex) {
  const resolvedPath = path.resolve(certPath);
  console.log(`\n[info] 解析憑證：${resolvedPath}`);

  const certs = parsePemChain(resolvedPath);
  console.log(`[info] 找到 ${certs.length} 張憑證`);

  const allMetas = certs.map(c => ({ cert: c, meta: parseCertMeta(c) }));
  const providedSkis = new Set(allMetas.map(m => m.meta.ski).filter(Boolean));

  const leafEntry =
    allMetas.find(({ cert }) => !isCAcert(cert)) ??
    allMetas.find(({ meta }) => meta.aki && !providedSkis.has(meta.aki)) ??
    allMetas[0];
  const targetSki = leafEntry.meta.aki;

  const bottomEntry =
    allMetas.find(({ meta }) => meta.aki && !providedSkis.has(meta.aki)) ??
    allMetas[0];

  let rootSki, rootLabel, rootFingerprint;

  const selfSigned = certs.find(c => isActualRoot(c, parseCertMeta(c)));

  if (selfSigned) {
    const meta = parseCertMeta(selfSigned);
    rootSki = meta.ski;
    rootLabel = extractLabel(selfSigned.subject);
    rootFingerprint = meta.fingerprint;
    console.log(`[info] 鏈中發現自簽 Root CA：${rootLabel}`);

  } else {
    const topmostCA = findTopmostCA(certs);

    if (topmostCA) {
      const meta = parseCertMeta(topmostCA);
      rootSki = meta.ski;
      rootLabel = extractLabel(topmostCA.subject);
      rootFingerprint = meta.fingerprint;
      console.log(`[info] 鏈中最上層 CA（錨點）：${rootLabel}`);

    } else {
      console.log('[info] 未找到 CA 憑證，透過 CCADB 向上追溯...');

      const bottomMeta = bottomEntry.meta;
      if (!bottomMeta.aki) {
        throw new Error('憑證無 Authority Key Identifier，無法向上追溯。請提供完整憑證鏈。');
      }

      const leafName = extractLabel(bottomEntry.cert.subject);
      const trace = traceToRootSki(bottomMeta.aki, skiIndex);

      const pathNames = [leafName, ...trace.chainNodes.map(n => n.name)];
      console.log(`[info] 從此節點開始追溯及路徑：${pathNames.join(' → ')}`);
      console.log(`[info] ${leafName} (SKI：${formatSki(bottomMeta.ski)} → AKI：${formatSki(bottomMeta.aki)})`);
      for (const node of trace.chainNodes) {
        if (node.aki && node.aki !== node.ski) {
          console.log(`[info] ${node.name} (SKI：${formatSki(node.ski)} → AKI：${formatSki(node.aki)})`);
        } else {
          console.log(`[info] ${node.name} (SKI：${formatSki(node.ski)})`);
        }
      }

      rootSki = trace.rootSki;
      rootFingerprint = '';
      rootLabel = trace.lastIntermediate
        ? (extractLabel(trace.lastIntermediate.issuer) || `(Root CA — SKI: ${rootSki.slice(0, 16)}...)`)
        : `(Root CA — SKI: ${rootSki.slice(0, 16)}...)`;
    }
  }

  console.log(`[info] Root CA：${rootLabel}  SKI：${rootSki}`);
  if (targetSki) console.log(`[info] 標的 UCA SKI：${targetSki}`);

  const nodes = buildTree(rootSki, akiIndex);
  return { source: certPath, rootLabel, rootSki, rootFingerprint, nodes, targetSki };
}

// ─── 處理白名單項目 ───────────────────────────────────────────────────────────

function processWhitelistEntry(entry, entries, akiIndex) {
  const displayName = entry.label || entry.name || entry.ski || '(未命名)';
  console.log(`\n[whitelist] 處理：${displayName}`);

  let rootEntry = null;

  if (entry.ski) {
    const norm = normalizeHex(entry.ski);
    rootEntry = entries.find(e => e.isRoot && normalizeHex(e.ski) === norm)
              ?? entries.find(e => normalizeHex(e.ski) === norm);
  }

  if (!rootEntry && entry.name) {
    const kw = entry.name.toLowerCase();
    rootEntry = entries.find(e =>
      e.isRoot && (
        (e.certName && e.certName.toLowerCase().includes(kw)) ||
        (e.subject  && e.subject.toLowerCase().includes(kw))
      )
    );
  }

  if (!rootEntry && entry.label) {
    const keywords = entry.label.toLowerCase().split(/\s+/).filter(w => w.length > 2);
    rootEntry = entries.find(e =>
      e.isRoot && keywords.every(kw =>
        (e.certName && e.certName.toLowerCase().includes(kw)) ||
        (e.subject  && e.subject.toLowerCase().includes(kw))
      )
    );
    if (rootEntry) console.log(`[whitelist] 以 label 關鍵字找到 Root CA：${rootEntry.certName || rootEntry.subject}`);
  }

  if (!rootEntry) {
    console.warn(`[whitelist] 警告：找不到符合的 Root CA（ski: ${entry.ski || '無'}, name: ${entry.name || '無'}）`);
    const label = entry.label || entry.name || '';
    if (label) {
      const kw = label.split(/\s+/).find(w => w.length > 3)?.toLowerCase() ?? '';
      if (kw) {
        const suggestions = entries
          .filter(e => e.isRoot && (
            (e.certName && e.certName.toLowerCase().includes(kw)) ||
            (e.subject  && e.subject.toLowerCase().includes(kw))
          ))
          .slice(0, 5);
        if (suggestions.length > 0) {
          console.warn('[whitelist] CCADB 中相近的 Root CA（可複製 SKI 填入 config.json）：');
          suggestions.forEach(s =>
            console.warn(`  "${s.certName || s.subject}"  ski: ${normalizeHex(s.ski)}`)
          );
        }
      }
    }
    return null;
  }

  const rootSki = normalizeHex(rootEntry.ski);
  const rootLabel = rootEntry.certName || extractLabel(rootEntry.subject);
  console.log(`[whitelist] 找到 Root CA：${rootLabel}  SKI：${rootSki}`);

  const nodes = buildTree(rootSki, akiIndex);
  return {
    source: 'whitelist',
    rootLabel,
    rootSki,
    rootFingerprint: rootEntry.fingerprint || '',
    nodes,
    targetSki: '',
  };
}

// ─── 掃描 certs/ 目錄 ────────────────────────────────────────────────────────

function scanCertsDir() {
  const certsDir = path.join(process.cwd(), 'certs');
  if (!fs.existsSync(certsDir)) return [];
  return fs.readdirSync(certsDir)
    .filter(f => /\.(pem|crt|cer|p7b)$/i.test(f))
    .map(f => path.join(certsDir, f));
}

// ─── 主程式 ──────────────────────────────────────────────────────────────────

async function main() {
  initLogger(path.join(process.cwd(), 'logs'));
  const args = process.argv.slice(2);

  if (args[0] === '--help' || args[0] === '-h') {
    console.log('用法：node findUCA.js [--no-cache] [<憑證檔.pem>]');
    console.log('');
    console.log('  不指定憑證檔時（無引數模式）：');
    console.log('    1. 自動掃描 certs/ 目錄中的憑證，識別 Root CA 並查詢中繼 CA');
    console.log('    2. 讀取 config.json 的 rootCAWhitelist，查詢白名單中每個 Root CA 的中繼 CA');
    console.log('');
    console.log('  指定憑證檔時：只處理該檔案（行為與舊版相同）');
    console.log('');
    console.log('  結果均輸出至 output/report.html 與 output/result.json');
    console.log('');
    console.log('選項：');
    console.log('  --no-cache   略過本機快取，強制重新下載 CCADB 資料');
    process.exit(0);
  }

  const noCache = args.includes('--no-cache');
  if (noCache) {
    const cachePath = path.join(process.cwd(), '.ccadb-cache.json');
    if (fs.existsSync(cachePath)) {
      fs.unlinkSync(cachePath);
      console.log('[info] 快取已清除。');
    }
  }

  const certArg = args.find(a => !a.startsWith('--'));

  const entries = await fetchCcadbEntries();
  const akiIndex = buildAkiIndex(entries);
  const skiIndex = buildSkiIndex(entries);

  const results = [];
  const seenRootSkis = new Set();

  function addResult(result) {
    if (!result) return;
    if (seenRootSkis.has(result.rootSki)) {
      console.log(`[info] Root CA 已存在結果中，略過重複：${result.rootLabel}`);
      return;
    }
    seenRootSkis.add(result.rootSki);
    results.push(result);
    printTree(result.rootLabel, result.rootSki, result.rootFingerprint, result.nodes, result.targetSki);
    exportUcaPems(result.rootLabel, result.nodes);
  }

  if (certArg) {
    // ── 單一檔案模式 ──
    addResult(processCertFile(certArg, akiIndex, skiIndex));

  } else {
    // ── 無引數模式：掃描 certs/ + 白名單 ──
    const certFiles = scanCertsDir();

    if (certFiles.length === 0) {
      console.log('[info] certs/ 目錄中未找到憑證檔案（.pem / .crt / .cer）。');
    } else {
      console.log(`[info] 在 certs/ 目錄找到 ${certFiles.length} 個憑證檔案。`);
    }

    for (const certPath of certFiles) {
      try {
        addResult(processCertFile(certPath, akiIndex, skiIndex));
      } catch (err) {
        console.error(`[error] ${path.basename(certPath)}: ${err.message}`);
      }
    }

    const config = loadConfig();

    if (config.rootCAWhitelist.length === 0 && certFiles.length === 0) {
      console.log('[info] 提示：可在 config.json 的 rootCAWhitelist 中設定 Root CA 白名單。');
    }

    for (const entry of config.rootCAWhitelist) {
      addResult(processWhitelistEntry(entry, entries, akiIndex));
    }
  }

  if (results.length > 0) {
    console.log('\n[output] 產生報表中...');
    generateReports(results);
  } else {
    console.log('\n[info] 無結果可輸出。');
  }
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
