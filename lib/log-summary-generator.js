'use strict';

const fs   = require('fs');
const path = require('path');

function nowGmt8() {
  return new Date(Date.now() + 8 * 60 * 60 * 1000);
}

function dateStr(d) {
  return d.toISOString().slice(0, 10).replace(/-/g, '');
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// 去掉 log 行首的 [yyyy/MM/dd hh:mm:ss.SSS] 時間戳
function stripTs(line) {
  return line.replace(/^\[\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\]\s*/, '');
}

// 依行內容決定著色 class
function lineClass(line) {
  if (/\[ERROR\]/.test(line)) return 'c-error';
  if (/\[WARN\]/.test(line))  return 'c-warn';
  const b = stripTs(line);
  if (/^\[pem[\s/\]]|^\[pem\/|^\[output\]/.test(b)) return 'c-output';
  if (/^\[ccadb\]/.test(b)) return 'c-ccadb';
  if (/^\[info\]/.test(b))  return 'c-info';
  if (/^\[pc\]/.test(b))    return 'c-pc';
  return '';
}

function shortCommand(argv) {
  return argv.replace(/^.*[/\\]/, '');
}

// ─── 解析 log 成 sessions ────────────────────────────────────────────────────

function parseSessions(text) {
  const SEP   = '='.repeat(72);
  const lines = text.split('\n');
  const sessions = [];
  let i = 0;

  while (i < lines.length) {
    if (lines[i] !== SEP) { i++; continue; }

    const cmdLine = lines[i + 1] ?? '';
    const m = cmdLine.match(/^\[(.+? GMT\+8)\]\s{2}(.+)$/);
    if (m && lines[i + 2] === SEP) {
      const timestamp = m[1];
      const command   = shortCommand(m[2]);
      i += 3;
      const logLines = [];
      while (i < lines.length && lines[i] !== SEP) {
        logLines.push(lines[i]);
        i++;
      }
      while (logLines.length > 0 && logLines[logLines.length - 1] === '') logLines.pop();
      sessions.push({ timestamp, command, logLines });
    } else {
      i++;
    }
  }

  return sessions.reverse();
}

// ─── 從 log 行萃取結構化指標 ─────────────────────────────────────────────────

function extractMetrics(logLines) {
  const m = {
    ccadbTotal: null, ccadbAdded: null, ccadbRemoved: null,
    cacheHit: false,
    certFiles: null,
    roots: [],          // { label, valid, expire, newCount }
    outputFiles: [],
    hostname: null, pcTotal: null,
    errors: [], warnings: [],
  };

  // 暫存目前正在累積的 root CA
  let curRoot = null;

  for (const line of logLines) {
    const b = stripTs(line);
    let r;

    // CCADB 統計
    if ((r = b.match(/^\[ccadb\] 合計 ([\d,]+) 筆/)))        m.ccadbTotal   = r[1];
    if ((r = b.match(/^\[ccadb\] 新增 (\d+) 筆/)))            m.ccadbAdded   = +r[1];
    if ((r = b.match(/^\[ccadb\] 移除 (\d+) 筆/)))            m.ccadbRemoved = +r[1];
    if (/^\[ccadb\] 使用本機快取/.test(b))                    m.cacheHit     = true;

    // 憑證檔掃描
    if ((r = b.match(/^\[info\] 在 certs\/ 目錄找到 (\d+) 個/))) m.certFiles = +r[1];

    // Root CA 開始（樹狀列印第一行，格式如「Root CA：DigiCert...」或樹狀開頭「── DigiCert」）
    if ((r = b.match(/^(?:Root CA|─+)\s*[：:]\s*(.+)/))) {
      curRoot = { label: r[1].trim(), valid: 0, expire: 0, newCount: 0 };
      m.roots.push(curRoot);
    }

    // 匯出計數（歸入最後一個 root）
    if ((r = b.match(/^\[pem\] myCert 有效：(\d+) 個/))) {
      if (curRoot) curRoot.valid += +r[1]; else m.roots.push({ label: '—', valid: +r[1], expire: 0, newCount: 0 });
    }
    if ((r = b.match(/^\[pem\] myCert 已過期：(\d+) 個/))) {
      if (curRoot) curRoot.expire += +r[1];
    }
    if ((r = b.match(/^\[pem\] 新增：(\d+) 個/))) {
      if (curRoot) curRoot.newCount += +r[1];
    }

    // 輸出檔案
    if ((r = b.match(/^\[output\]\s+(.+)/)))  m.outputFiles.push(r[1].trim());

    // listPCCA
    if ((r = b.match(/^\[pc\] 主機名稱：(.+)/)))         m.hostname = r[1].trim();
    if ((r = b.match(/^\[pc\] 掃描完成，共 (\d+) 張/)))  m.pcTotal  = +r[1];

    // 錯誤 / 警告
    if (/\[ERROR\]/.test(line)) m.errors.push(b);
    if (/\[WARN\]/.test(line))  m.warnings.push(b);
  }

  return m;
}

// ─── HTML 組件 ───────────────────────────────────────────────────────────────

function chip(label, value, cls) {
  return `<span class="chip ${cls ?? ''}">${esc(label)}<strong>${esc(String(value))}</strong></span>`;
}

function renderMetrics(metrics) {
  const chips = [];

  if (metrics.hostname)
    chips.push(chip('主機', metrics.hostname, 'chip-blue'));
  if (metrics.pcTotal !== null)
    chips.push(chip('本機 CA 憑證', `${metrics.pcTotal} 張`, 'chip-blue'));
  if (metrics.cacheHit)
    chips.push(`<span class="chip chip-gray">CCADB 快取</span>`);
  if (metrics.ccadbTotal !== null)
    chips.push(chip('CCADB', `${metrics.ccadbTotal} 筆`, 'chip-purple'));
  if (metrics.ccadbAdded !== null && metrics.ccadbAdded > 0)
    chips.push(chip('新增', `+${metrics.ccadbAdded}`, 'chip-green'));
  if (metrics.ccadbRemoved !== null && metrics.ccadbRemoved > 0)
    chips.push(chip('移除', `-${metrics.ccadbRemoved}`, 'chip-red'));
  if (metrics.certFiles !== null)
    chips.push(chip('掃描憑證', `${metrics.certFiles} 個`, 'chip-blue'));

  // root CA 匯出統計
  for (const root of metrics.roots) {
    const parts = [];
    if (root.valid)    parts.push(`有效 ${root.valid}`);
    if (root.expire)   parts.push(`過期 ${root.expire}`);
    if (root.newCount) parts.push(`新增 ${root.newCount}`);
    if (parts.length)
      chips.push(chip(root.label.slice(0, 30) + (root.label.length > 30 ? '…' : '') + '　', parts.join(' / '), 'chip-teal'));
  }

  if (chips.length === 0) return '';
  return `<div class="metrics">${chips.join('')}</div>`;
}

function renderOutputFiles(files) {
  if (files.length === 0) return '';
  const items = files.map(f => `<li class="file-item">${esc(f)}</li>`).join('');
  return `<div class="output-files"><div class="section-label">輸出檔案</div><ul>${items}</ul></div>`;
}

function renderAlerts(errors, warnings) {
  if (errors.length === 0 && warnings.length === 0) return '';
  const rows = [
    ...errors.map(e   => `<div class="alert alert-err">${esc(e)}</div>`),
    ...warnings.map(w => `<div class="alert alert-warn">${esc(w)}</div>`),
  ];
  return `<div class="alerts">${rows.join('')}</div>`;
}

function renderLogLines(logLines) {
  if (logLines.length === 0)
    return '<div class="log-empty">（無輸出）</div>';
  return logLines.map(line =>
    line === ''
      ? '<div class="log-blank"></div>'
      : `<div class="log-line ${lineClass(line)}">${esc(line)}</div>`
  ).join('');
}

// ─── 主 HTML ─────────────────────────────────────────────────────────────────

function buildHtml(sessions, dateLabel) {
  // 頁首統計
  const totalErr  = sessions.reduce((n, s) => n + s.logLines.filter(l => /\[ERROR\]/.test(l)).length, 0);
  const totalWarn = sessions.reduce((n, s) => n + s.logLines.filter(l => /\[WARN\]/.test(l)).length, 0);

  const genTime = (() => {
    const n = nowGmt8();
    return n.toISOString().slice(0, 19).replace('T', ' ') + ' GMT+8';
  })();

  const sessionsHtml = sessions.map((s, idx) => {
    const metrics = extractMetrics(s.logLines);
    const errCnt  = metrics.errors.length;
    const warnCnt = metrics.warnings.length;

    const statusBadge = errCnt  > 0
      ? `<span class="status-badge badge-err">${errCnt} 錯誤</span>`
      : warnCnt > 0
        ? `<span class="status-badge badge-warn">${warnCnt} 警告</span>`
        : `<span class="status-badge badge-ok">正常</span>`;

    const metricsHtml     = renderMetrics(metrics);
    const outputFilesHtml = renderOutputFiles(metrics.outputFiles);
    const alertsHtml      = renderAlerts(metrics.errors, metrics.warnings);
    const logHtml         = renderLogLines(s.logLines);

    return `<section class="session${idx === 0 ? ' session-first' : ''}">
  <div class="session-head">
    <div class="session-time">${esc(s.timestamp)}</div>
    <div class="session-cmd">${esc(s.command)}</div>
    ${statusBadge}
  </div>
  ${metricsHtml}
  ${outputFilesHtml}
  ${alertsHtml}
  <details class="log-details">
    <summary>完整執行記錄</summary>
    <div class="log-body">${logHtml}</div>
  </details>
</section>`;
  }).join('\n');

  const headerBadges = [
    totalErr  > 0 ? `<span class="h-badge badge-err">${totalErr} 錯誤</span>`   : '',
    totalWarn > 0 ? `<span class="h-badge badge-warn">${totalWarn} 警告</span>` : '',
  ].filter(Boolean).join('');

  return `<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CertUilt 執行彙總 ${esc(dateLabel)}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;font-size:14px;color:#222;background:#f0f2f5}
a{color:inherit;text-decoration:none}

/* ── 頁首 ── */
header{background:#1a3a5c;color:#fff;padding:18px 32px;display:flex;align-items:baseline;gap:16px;flex-wrap:wrap}
header h1{font-size:20px;font-weight:600}
.header-meta{font-size:12px;opacity:.7;flex:1}
.h-badge{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:600}

/* ── 主體 ── */
main{max-width:1100px;margin:20px auto;padding:0 20px 40px}

/* ── 頁首統計列 ── */
.day-summary{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:14px 20px;margin-bottom:14px;display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.day-stat{text-align:center}
.day-stat .val{font-size:24px;font-weight:700;color:#1a3a5c;line-height:1.2}
.day-stat .lbl{font-size:11px;color:#888;margin-top:2px}

/* ── Session 卡片 ── */
.session{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:12px;overflow:hidden}
.session-first{border-left:4px solid #1a3a5c}
.session-head{padding:12px 18px;display:flex;align-items:center;gap:12px;background:#f8f9fb;border-bottom:1px solid #e8edf2;flex-wrap:wrap}
.session-time{font-size:12px;color:#1a3a5c;font-weight:600;white-space:nowrap}
.session-cmd{font-family:Consolas,'Courier New',monospace;font-size:13px;color:#333;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.status-badge{font-size:11px;padding:2px 8px;border-radius:10px;font-weight:600;white-space:nowrap}

/* ── 指標 chips ── */
.metrics{padding:10px 18px;display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid #f0f2f5}
.chip{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:12px;font-size:12px;border:1px solid transparent}
.chip strong{font-weight:600}
.chip-blue  {background:#e8f0fe;border-color:#c5d4f5;color:#1a3a5c}
.chip-purple{background:#f3e8fd;border-color:#d9b8f5;color:#6b21a8}
.chip-teal  {background:#e8faf5;border-color:#a7e8d8;color:#065f46}
.chip-green {background:#ecfdf5;border-color:#6ee7b7;color:#065f46}
.chip-red   {background:#fef2f2;border-color:#fca5a5;color:#991b1b}
.chip-gray  {background:#f3f4f6;border-color:#d1d5db;color:#374151}

/* ── 輸出檔案 ── */
.output-files{padding:8px 18px 10px;border-bottom:1px solid #f0f2f5}
.section-label{font-size:11px;color:#888;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
.output-files ul{list-style:none;display:flex;flex-direction:column;gap:3px}
.file-item{font-family:Consolas,'Courier New',monospace;font-size:12px;color:#0e7a62;padding:2px 0 2px 14px;position:relative}
.file-item::before{content:'▸';position:absolute;left:0;color:#4ec9b0}

/* ── 警告 / 錯誤 ── */
.alerts{padding:8px 18px 10px;border-bottom:1px solid #f0f2f5;display:flex;flex-direction:column;gap:4px}
.alert{font-family:Consolas,'Courier New',monospace;font-size:12px;padding:4px 10px;border-radius:4px;word-break:break-all}
.alert-err {background:#fef2f2;color:#b91c1c;border-left:3px solid #f87171}
.alert-warn{background:#fffbeb;color:#92400e;border-left:3px solid #fcd34d}

/* ── 完整記錄 ── */
.log-details{border-top:1px solid #f0f2f5}
.log-details>summary{padding:7px 18px;font-size:12px;color:#888;cursor:pointer;user-select:none;list-style:none;display:flex;align-items:center;gap:6px}
.log-details>summary::-webkit-details-marker{display:none}
.log-details>summary::before{content:'▶';font-size:10px;transition:transform .15s}
.log-details[open]>summary::before{transform:rotate(90deg)}
.log-details>summary:hover{color:#333;background:#fafafa}
.log-body{padding:8px 18px 14px;background:#1e1e1e;border-top:1px solid #333;font-family:Consolas,'Courier New',monospace;font-size:12px;line-height:1.65;overflow-x:auto}
.log-line{white-space:pre-wrap;word-break:break-all}
.log-blank{height:5px}
.log-empty{color:#666;font-style:italic}
.log-line.c-error {color:#f48771}
.log-line.c-warn  {color:#cca700}
.log-line.c-output{color:#4ec9b0}
.log-line.c-ccadb {color:#c586c0}
.log-line.c-info  {color:#9cdcfe}
.log-line.c-pc    {color:#b5cea8}
.log-line         {color:#d4d4d4}

/* ── badge 顏色 ── */
.badge-ok  {background:#ecfdf5;color:#065f46}
.badge-warn{background:#fffbeb;color:#92400e}
.badge-err {background:#fef2f2;color:#b91c1c}

footer{text-align:center;color:#bbb;font-size:11px;padding:16px 0 24px}
</style>
</head>
<body>
<header>
  <h1>CertUilt — 執行彙總</h1>
  <span class="header-meta">${esc(dateLabel)} &nbsp;|&nbsp; 產生時間：${esc(genTime)}</span>
  ${headerBadges}
</header>
<main>
  <div class="day-summary">
    <div class="day-stat"><div class="val">${sessions.length}</div><div class="lbl">執行次數</div></div>
    <div class="day-stat"><div class="val" style="color:${totalErr > 0 ? '#b91c1c' : '#065f46'}">${totalErr}</div><div class="lbl">錯誤</div></div>
    <div class="day-stat"><div class="val" style="color:${totalWarn > 0 ? '#92400e' : '#065f46'}">${totalWarn}</div><div class="lbl">警告</div></div>
  </div>
${sessionsHtml}
</main>
<footer>Generated by CertUilt &nbsp;|&nbsp; Data source: CCADB (Mozilla)</footer>
</body>
</html>`;
}

// ─── Entry point ─────────────────────────────────────────────────────────────

function generateLogSummary(logDir) {
  try {
    const today   = dateStr(nowGmt8());
    const logFile = path.join(logDir, `${today}.log`);
    if (!fs.existsSync(logFile)) return;

    const sessions = parseSessions(fs.readFileSync(logFile, 'utf8'));
    if (sessions.length === 0) return;

    const outFile = path.join(logDir, `${today}_Summary.html`);
    fs.writeFileSync(outFile, buildHtml(sessions, today), 'utf8');
    console.log(`[output] logs/${today}_Summary.html`);
  } catch (err) {
    console.warn('[summary] 無法產生執行彙總：', err.message);
  }
}

module.exports = { generateLogSummary };
