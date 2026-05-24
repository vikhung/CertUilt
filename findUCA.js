'use strict';

const path = require('path');
const fs = require('fs');
const { parseCertMeta, parsePemChain } = require('./lib/cert-parser');
const { fetchCcadbEntries, buildAkiIndex, buildSkiIndex } = require('./lib/ccadb-client');
const { buildTree, printTree } = require('./lib/ca-tree');
const { loadConfig } = require('./lib/config-loader');
const { generateReports } = require('./lib/report-generator');
const { initLogger } = require('./lib/logger');
const { generateLogSummary } = require('./lib/log-summary-generator');

function normalizeHex(raw) {
  if (!raw) return '';
  return raw.replace(/[:\s]/g, '').toLowerCase();
}

function sanitizeFilename(name) {
  const cleaned = (name ?? '').replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').trim().slice(0, 120);
  return cleaned.replace(/^\.+$/, '') || 'unknown';
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

// ─── 共用寫檔工具 ────────────────────────────────────────────────────────────

function writeEntryFile(outDir, seenMap, entry, idx) {
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const base  = sanitizeFilename(entry.certName || entry.fingerprint || `cert_${idx}`);
  const count = seenMap.get(base) ?? 0;
  seenMap.set(base, count + 1);
  const fileName = count === 0
    ? `${base}.crt`
    : `${base}_${(entry.fingerprint || '').slice(0, 8) || count}.crt`;
  fs.writeFileSync(path.join(outDir, fileName), entry.pem + '\n', 'utf8');
  return fileName;
}

// ─── Manifest helpers ────────────────────────────────────────────────────────
// Manifest 格式：{ updatedAt, entries: { fingerprint: 'relative/path.crt' } }
// 路徑相對於 manifest 所在目錄的上一層 baseDir。

function loadManifest(manifestPath) {
  try {
    if (fs.existsSync(manifestPath)) {
      const data = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      return { entries: (data.entries && typeof data.entries === 'object') ? data.entries : {} };
    }
  } catch { /* ignore corrupt manifest */ }
  return { entries: {} };
}

function saveManifest(manifestPath, manifest) {
  try {
    const dir = path.dirname(manifestPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(manifestPath, JSON.stringify({
      updatedAt: new Date().toISOString(),
      entries:   manifest.entries,
    }, null, 2), 'utf8');
  } catch (err) {
    console.warn(`[manifest] 無法儲存：${err.message}`);
  }
}

// 根據 manifest 找出 removedFps 對應的檔案，搬移至 notExistSubdir/。
// baseDir      : manifest 中相對路徑的根目錄（如 pem/ 或 pem/ccadb/）
// notExistSubdir: 目標子目錄名稱（如 '02.notExist'），相對於 baseDir
function moveRemovedFiles(baseDir, manifestPath, removedFps, notExistSubdir) {
  if (!removedFps || removedFps.size === 0) return;

  const manifest   = loadManifest(manifestPath);
  const SKIP_FIRST = new Set([notExistSubdir, '00.new']); // 已在特殊目錄的跳過
  const SPECIAL    = new Set(['myCert', '01.expire', '00.new', notExistSubdir]);
  let moved = 0, changed = false;

  for (const fp of removedFps) {
    const relPath = manifest.entries[fp];
    if (!relPath) continue;

    const normRel = relPath.replace(/\\/g, '/');
    // 若已在 notExistSubdir 或 00.new 則清理 manifest entry 後跳過
    if (SKIP_FIRST.has(normRel.split('/')[0])) {
      delete manifest.entries[fp];
      changed = true;
      continue;
    }

    const srcPath = path.join(baseDir, relPath);
    if (!fs.existsSync(srcPath)) {
      // 來源不存在（已手動刪除）→ 清理 manifest
      delete manifest.entries[fp];
      changed = true;
      continue;
    }

    // 從路徑中取得 Root CA 目錄名稱（跳過所有 SPECIAL 前綴段）
    const parts     = normRel.split('/');
    const rootCaDir = parts.find(p => !SPECIAL.has(p)) ?? 'unknown';
    const fileName  = parts[parts.length - 1];
    const destDir   = path.join(baseDir, notExistSubdir, rootCaDir);
    const destPath  = path.join(destDir, fileName);

    fs.mkdirSync(destDir, { recursive: true });
    fs.renameSync(srcPath, destPath);
    delete manifest.entries[fp];
    changed = true;
    moved++;
  }

  if (changed) saveManifest(manifestPath, manifest);
  if (moved > 0)
    console.log(`[pem] 已從 CCADB 移除：共移動 ${moved} 個憑證 → ${path.relative(process.cwd(), path.join(baseDir, notExistSubdir))}/`);
}

// ─── 匯出 myCert UCA PEM 檔 ──────────────────────────────────────────────────
// newFpSet : Set<fingerprint> | null — 本次 CCADB 下載新增的憑證指紋集合
// newDate  : 'yyyyMMdd' | null      — 新增日期（GMT+8），用作 pem/00.new/<date>/ 目錄名稱

function exportUcaPems(rootLabel, nodes, newFpSet, newDate) {
  const now      = new Date();
  const dirName  = sanitizeFilename(rootLabel);
  const pemBase  = path.join(process.cwd(), 'pem');
  const myCertBase = path.join(pemBase, 'myCert');
  const activeDir  = path.join(myCertBase, dirName);
  const expireDir  = path.join(myCertBase, '01.expire', dirName);
  const newDir     = (newFpSet?.size > 0 && newDate)
    ? path.join(myCertBase, '00.new', newDate, dirName)
    : null;

  const manifestPath = path.join(pemBase, '.myCert-manifest.json');
  const manifest     = loadManifest(manifestPath);

  let total = 0, writtenActive = 0, writtenExpire = 0, writtenNew = 0;
  const seenActive = new Map();
  const seenExpire = new Map();
  const seenNew    = new Map();

  function walk(nodeList) {
    for (const node of nodeList) {
      total++;
      if (node.info.pem) {
        const fp      = node.info.fingerprint;
        const expired = node.info.validTo instanceof Date && node.info.validTo < now;
        if (expired) {
          const fileName = writeEntryFile(expireDir, seenExpire, node.info, total);
          writtenExpire++;
          if (fp) manifest.entries[fp] = `01.expire/${dirName}/${fileName}`;
        } else {
          const fileName = writeEntryFile(activeDir, seenActive, node.info, total);
          writtenActive++;
          if (fp) manifest.entries[fp] = `${dirName}/${fileName}`;
        }
        if (newDir && fp && newFpSet.has(fp)) {
          writeEntryFile(newDir, seenNew, node.info, total);
          writtenNew++;
        }
      }
      walk(node.children);
    }
  }

  walk(nodes);
  if (total > 0) {
    saveManifest(manifestPath, manifest);
    console.log(`[pem] myCert 有效：${writtenActive} 個 → pem/myCert/${dirName}/`);
    if (writtenExpire > 0)
      console.log(`[pem] myCert 已過期：${writtenExpire} 個 → pem/myCert/01.expire/${dirName}/`);
    if (writtenNew > 0)
      console.log(`[pem] 新增：${writtenNew} 個 → pem/myCert/00.new/${newDate}/${dirName}/`);
  }
}

// ─── 匯出全部 CCADB 憑證（downloadFromCCADB 模式）────────────────────────────

function exportAllCcadbPems(entries, akiIndex, latestDiff) {
  const now      = new Date();
  const roots    = entries.filter(e => e.isRoot);
  const newFpSet = latestDiff ? latestDiff.fingerprints : new Set();
  const newDate  = (latestDiff && latestDiff.fingerprints.size > 0) ? latestDiff.date : null;
  const baseDir  = path.join(process.cwd(), 'pem', 'ccadb');

  const manifestPath  = path.join(process.cwd(), 'pem', '.ccadb-manifest.json');
  const ccadbManifest = loadManifest(manifestPath);
  let   manifestChanged = false;

  let totalActive = 0, totalExpire = 0, totalNew = 0, totalSkipped = 0;
  console.log(`\n[ccadb] downloadFromCCADB 模式：匯出全部 CCADB 憑證（${roots.length} 個 Root CA）...`);

  for (const root of roots) {
    const rootSki   = normalizeHex(root.ski);
    const rootLabel = root.certName || extractLabel(root.subject);
    const dirName   = sanitizeFilename(rootLabel);
    const nodes     = buildTree(rootSki, akiIndex);
    if (nodes.length === 0) continue;

    const activeDir = path.join(baseDir, dirName);
    const expireDir = path.join(baseDir, '01.expire', dirName);
    const newDir    = newDate ? path.join(baseDir, '00.new', newDate, dirName) : null;

    const seenActive = new Map();
    const seenExpire = new Map();
    const seenNew    = new Map();
    let idx = 0;

    const walkCcadb = (nodeList) => {
      for (const node of nodeList) {
        idx++;
        if (!node.info.pem) { walkCcadb(node.children); continue; }

        const fp      = node.info.fingerprint;
        const expired = node.info.validTo instanceof Date && node.info.validTo < now;
        const seenMap = expired ? seenExpire : seenActive;
        const outDir  = expired ? expireDir  : activeDir;

        // 計算檔名（無論是否略過，seenMap 計數器都要更新，確保跨執行命名一致）
        const base     = sanitizeFilename(node.info.certName || fp || `cert_${idx}`);
        const count    = seenMap.get(base) ?? 0;
        seenMap.set(base, count + 1);
        const fileName = count === 0
          ? `${base}.crt`
          : `${base}_${(fp || '').slice(0, 8) || count}.crt`;
        const relPath  = expired ? `01.expire/${dirName}/${fileName}` : `${dirName}/${fileName}`;

        // 增量寫入：檔案已存在則略過，但仍修復 manifest
        const filePath = path.join(outDir, fileName);
        if (!fs.existsSync(filePath)) {
          fs.mkdirSync(outDir, { recursive: true });
          fs.writeFileSync(filePath, node.info.pem + '\n', 'utf8');
          if (expired) totalExpire++; else totalActive++;
          if (fp) { ccadbManifest.entries[fp] = relPath; manifestChanged = true; }
        } else {
          totalSkipped++;
          // 自我修復：補上 manifest 遺失項目
          if (fp && !ccadbManifest.entries[fp]) {
            ccadbManifest.entries[fp] = relPath;
            manifestChanged = true;
          }
        }

        // 新增憑證無論如何都寫入 00.new
        if (newDir && fp && newFpSet.has(fp)) {
          writeEntryFile(newDir, seenNew, node.info, idx);
          totalNew++;
        }

        walkCcadb(node.children);
      }
    };

    walkCcadb(nodes);
  }

  if (manifestChanged) saveManifest(manifestPath, ccadbManifest);

  const written = totalActive + totalExpire;
  if (written > 0) {
    console.log(`[pem/ccadb] 新寫入：有效 ${totalActive}，已過期 ${totalExpire}；略過（已存在）：${totalSkipped}`);
  } else {
    console.log(`[pem/ccadb] 無新增，略過已存在 ${totalSkipped} 個憑證。`);
  }
  if (totalNew > 0)
    console.log(`[pem/ccadb] CCADB 新增：${totalNew} 個 → pem/ccadb/00.new/${newDate}/`);
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
    console.log('  結果均輸出至 pem/.myCert-report.html 與 pem/.myCert.json');
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
  const config  = loadConfig();

  const { entries, latestDiff } = await fetchCcadbEntries();
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
    exportUcaPems(result.rootLabel, result.nodes, latestDiff?.fingerprints, latestDiff?.date);
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

  if (config.downloadFromCCADB) {
    exportAllCcadbPems(entries, akiIndex, latestDiff);
  }

  // 搬移已從 CCADB 移除的憑證至 02.notExist/
  const pemBase    = path.join(process.cwd(), 'pem');
  const removedFps = latestDiff?.removedFingerprints ?? new Set();
  if (removedFps.size > 0) {
    // myCert：永遠嘗試（只要 manifest 存在）
    moveRemovedFiles(path.join(pemBase, 'myCert'), path.join(pemBase, '.myCert-manifest.json'), removedFps, '02.notExist');
    // ccadb：僅在 manifest 存在時（代表曾執行過 downloadFromCCADB 模式）
    const ccadbManifestPath = path.join(pemBase, '.ccadb-manifest.json');
    if (fs.existsSync(ccadbManifestPath)) {
      moveRemovedFiles(path.join(pemBase, 'ccadb'), ccadbManifestPath, removedFps, '02.notExist');
    }
  }

  generateLogSummary(path.join(process.cwd(), 'logs'));
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
