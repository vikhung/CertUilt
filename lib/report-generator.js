'use strict';

const fs = require('fs');
const path = require('path');

function formatDate(d) {
  if (!d || d.getTime() === 0) return 'N/A';
  return d.toISOString().slice(0, 10);
}

function formatSki(ski) {
  if (!ski) return '(none)';
  return ski.replace(/(.{2})(?=.)/g, '$1:').toUpperCase();
}

function countNodes(nodes) {
  return nodes.reduce((sum, n) => sum + 1 + countNodes(n.children), 0);
}

function maxDepth(nodes) {
  if (nodes.length === 0) return 0;
  return Math.max(...nodes.map(n => 1 + maxDepth(n.children)));
}

// ─── JSON ────────────────────────────────────────────────────────────────────

function nodeToJson(node, targetSki) {
  const { info, children } = node;
  return {
    name: info.certName || info.subject,
    caOwner: info.caOwner,
    status: info.status,
    ski: info.ski,
    aki: info.aki,
    validFrom: formatDate(info.validFrom),
    validTo: formatDate(info.validTo),
    serialNumber: info.serialNumber,
    isRoot: info.isRoot || false,
    isTarget: !!(targetSki && info.ski === targetSki),
    children: children.map(c => nodeToJson(c, targetSki)),
  };
}

function buildJson(results) {
  return {
    generatedAt: new Date().toISOString(),
    totalRootCAs: results.length,
    results: results.map(r => ({
      source: r.source,
      rootCA: { name: r.rootLabel, ski: r.rootSki, fingerprint: r.rootFingerprint || '' },
      stats: { totalUCAs: countNodes(r.nodes), maxDepth: maxDepth(r.nodes) },
      targetSki: r.targetSki || '',
      tree: r.nodes.map(n => nodeToJson(n, r.targetSki)),
    })),
  };
}

// ─── HTML ────────────────────────────────────────────────────────────────────

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderNode(node, targetSki) {
  const { info, children } = node;
  const name = esc(info.certName || info.subject.slice(0, 100));
  const owner = info.caOwner ? ` <span class="owner">(${esc(info.caOwner)})</span>` : '';
  const status = info.status ? ` <span class="status">${esc(info.status)}</span>` : '';
  const isTarget = !!(targetSki && info.ski === targetSki);
  const targetMark = isTarget ? ' <span class="target-badge">◄ 本次查詢標的</span>' : '';
  const hasChildren = children.length > 0;
  const toggleBtn = hasChildren
    ? `<button class="toggle" onclick="toggle(this)" title="展開/收合">▼</button>`
    : `<span class="toggle-placeholder"></span>`;
  const childHtml = hasChildren
    ? `<ul class="children">${children.map(c => renderNode(c, targetSki)).join('')}</ul>`
    : '';

  return `<li class="ni${isTarget ? ' ni-target' : ''}">
      <div class="nh">
        ${toggleBtn}
        <span class="nn">${name}</span>${owner}${status}${targetMark}
      </div>
      <div class="nd">
        <span class="dl">有效期</span> ${esc(formatDate(info.validFrom))} ～ ${esc(formatDate(info.validTo))}
        &nbsp;&nbsp;<span class="dl">SKI</span> <code>${esc(formatSki(info.ski))}</code>
        &nbsp;&nbsp;<span class="dl">AKI</span> <code>${esc(formatSki(info.aki))}</code>
      </div>
      ${childHtml}
    </li>`;
}

// Root CA 本身作為樹狀結構的根節點
function renderSection(result, idx) {
  const total = countNodes(result.nodes);
  const depth = maxDepth(result.nodes);
  const fpHtml = result.rootFingerprint
    ? `&nbsp;&nbsp;<span class="dl">SHA-256</span> <code>${esc(result.rootFingerprint.slice(0, 32))}…</code>`
    : '';
  const sourceHtml = result.source === 'whitelist'
    ? '<span class="badge-wl">白名單</span>'
    : `<span class="badge-file">憑證檔案</span> <code>${esc(result.source)}</code>`;
  const statsHtml = total > 0
    ? `<span class="stat-inline">${total} 個中繼 CA・${depth} 層</span>`
    : `<span class="stat-inline empty-stat">無中繼 CA</span>`;
  const hasChildren = result.nodes.length > 0;
  const toggleBtn = hasChildren
    ? `<button class="toggle root-toggle" onclick="toggle(this)" title="展開/收合">▼</button>`
    : `<span class="toggle-placeholder"></span>`;
  const childrenHtml = hasChildren
    ? `<ul class="children">${result.nodes.map(n => renderNode(n, result.targetSki)).join('')}</ul>`
    : `<div class="empty-root">CCADB 中未找到此 Root CA 的中繼憑證。<br>可能原因：不在主流信任程式中，或可查詢 crt.sh。</div>`;

  return `<section id="s${idx}">
    <ul class="tree-root">
      <li class="ni ni-root">
        <div class="nh root-nh">
          ${toggleBtn}
          <span class="nn root-name">${esc(result.rootLabel)}</span>
          <span class="root-badge">Root CA</span>
          ${statsHtml}
        </div>
        <div class="nd root-nd">
          ${sourceHtml}
          &nbsp;&nbsp;<span class="dl">SKI</span> <code>${esc(formatSki(result.rootSki))}</code>${fpHtml}
        </div>
        ${childrenHtml}
      </li>
    </ul>
  </section>`;
}

function buildHtml(results) {
  const genTime = new Date().toLocaleString('zh-TW', { timeZone: 'Asia/Taipei' });
  const navHtml = results.length > 1
    ? `<nav><ul>${results.map((r, i) => `<li><a href="#s${i}">${esc(r.rootLabel)}</a></li>`).join('')}</ul></nav>`
    : '';
  const sectionsHtml = results.map((r, i) => renderSection(r, i)).join('\n');

  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CertUilt CA 階層報表</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;font-size:14px;color:#222;background:#f0f2f5}
header{background:#1a3a5c;color:#fff;padding:18px 32px;display:flex;align-items:baseline;gap:20px}
header h1{font-size:20px;font-weight:600}
header p{font-size:12px;opacity:.75}
nav{background:#fff;border-bottom:1px solid #d9e0e8;padding:10px 32px}
nav ul{list-style:none;display:flex;flex-wrap:wrap;gap:8px}
nav a{color:#1a3a5c;text-decoration:none;padding:3px 12px;border:1px solid #1a3a5c;border-radius:20px;font-size:12px;transition:.15s}
nav a:hover{background:#1a3a5c;color:#fff}
main{max-width:1280px;margin:20px auto;padding:0 20px}
section{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:16px 20px;margin-bottom:14px}
ul.tree-root{list-style:none;padding:0}
.ni{margin:4px 0}
.nh{display:flex;align-items:center;gap:5px;padding:4px 8px;border-radius:4px;cursor:default}
.nh:hover{background:#f5f7fa}
/* Root CA 節點特殊樣式 */
.ni-root>.root-nh{background:#eef3fa;border-radius:6px;padding:8px 12px}
.ni-root>.root-nh:hover{background:#dce8f7}
.root-name{font-size:15px;font-weight:600;color:#1a3a5c}
.root-badge{font-size:11px;background:#1a3a5c;color:#fff;padding:2px 8px;border-radius:10px;margin-left:4px;flex-shrink:0}
.stat-inline{font-size:12px;color:#666;margin-left:6px}
.empty-stat{color:#aaa;font-style:italic}
.root-nd{font-size:12px;color:#666;padding:4px 12px 6px 40px;line-height:1.9}
.root-nd code{background:#e8eef5;padding:1px 6px;border-radius:3px;font-family:monospace;font-size:11px;word-break:break-all}
.root-toggle{font-size:14px !important;color:#1a3a5c !important}
/* 一般中繼 CA 節點 */
.ni-target>.nh{background:#fffbea;border:1px solid #ffd666}
.toggle{background:none;border:none;cursor:pointer;font-size:11px;color:#aaa;width:18px;flex-shrink:0;transition:transform .15s;padding:0}
.toggle-placeholder{width:18px;flex-shrink:0}
.nn{font-weight:500;font-size:13px}
.owner{color:#777;font-size:12px}
.status{font-size:11px;background:#ecfdf5;color:#065f46;padding:1px 7px;border-radius:10px;margin-left:2px}
.target-badge{font-size:11px;background:#fffbea;color:#92400e;padding:1px 7px;border-radius:10px;font-weight:600;border:1px solid #fcd34d;margin-left:4px}
.nd{font-size:11px;color:#888;padding:1px 8px 5px 26px;line-height:1.9}
.nd code{background:#f5f5f5;padding:1px 4px;border-radius:3px;font-family:monospace;font-size:10px;word-break:break-all}
ul.children{list-style:none;padding-left:22px;border-left:2px solid #e0e8f0;margin:4px 0 4px 9px}
.ni-root>ul.children{padding-left:28px;border-left:3px solid #c5d8f0;margin:6px 0 0 12px}
.collapsed>.children{display:none}
.collapsed>.nh>.toggle,.collapsed>.root-nh>.toggle{transform:rotate(-90deg)}
.empty-root{color:#999;font-style:italic;font-size:13px;padding:10px 12px 4px 40px}
.dl{color:#999;font-size:11px;margin-right:2px}
.badge-wl,.badge-file{display:inline-block;font-size:11px;padding:1px 8px;border-radius:10px;margin-right:4px}
.badge-wl{background:#e8f0fe;color:#1a56db}
.badge-file{background:#f0f0f0;color:#555}
.toolbar{display:flex;gap:8px;margin-bottom:12px}
.toolbar button{background:#f0f2f5;border:1px solid #d0d5dd;border-radius:4px;padding:4px 12px;font-size:12px;cursor:pointer}
.toolbar button:hover{background:#e4e7ec}
footer{text-align:center;color:#bbb;font-size:11px;padding:20px}
</style>
</head>
<body>
<header>
  <h1>CertUilt ─ CA 階層報表</h1>
  <p>產生時間：${esc(genTime)}　共 ${results.length} 個 Root CA</p>
</header>
${navHtml}
<main>
<div class="toolbar">
  <button onclick="expandAll()">展開全部</button>
  <button onclick="collapseAll()">收合全部</button>
</div>
${sectionsHtml}
</main>
<footer>Generated by CertUilt &nbsp;|&nbsp; Data source: CCADB (Mozilla)</footer>
<script>
function toggle(btn){
  const li=btn.closest('.ni');
  li.classList.toggle('collapsed');
}
function expandAll(){document.querySelectorAll('.ni.collapsed').forEach(n=>n.classList.remove('collapsed'));}
function collapseAll(){
  document.querySelectorAll('.ni').forEach(n=>{
    if(n.querySelector(':scope > .children, :scope > ul.children'))n.classList.add('collapsed');
  });
}
// 預設：深度 3 以上的節點自動收合（Root CA 本身不收合）
document.querySelectorAll('.children .children .ni').forEach(n=>{
  if(n.querySelector('.children'))n.classList.add('collapsed');
});
</script>
</body>
</html>`;
}

// ─── Entry point ─────────────────────────────────────────────────────────────

function ensureOutputDir() {
  const dir = path.join(process.cwd(), 'output');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  return dir;
}

function generateReports(results) {
  const outDir = ensureOutputDir();

  const jsonPath = path.join(outDir, 'result.json');
  fs.writeFileSync(jsonPath, JSON.stringify(buildJson(results), null, 2), 'utf8');
  console.log(`[output] JSON 結果：${jsonPath}`);

  const htmlPath = path.join(outDir, 'report.html');
  fs.writeFileSync(htmlPath, buildHtml(results), 'utf8');
  console.log(`[output] HTML 報表：${htmlPath}`);
}

module.exports = { generateReports };
