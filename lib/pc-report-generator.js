'use strict';

const fs = require('fs');
const path = require('path');

function formatDate(d) {
  if (!d || isNaN(d.getTime())) return 'N/A';
  return d.toISOString().slice(0, 10);
}

function formatSki(ski) {
  if (!ski) return '(none)';
  return ski.replace(/(.{2})(?=.)/g, '$1:').toUpperCase();
}

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function extractCN(dn) {
  if (!dn) return '';
  const m = dn.match(/CN\s*=\s*([^,\n]+)/i);
  return m ? m[1].trim() : dn.slice(0, 60);
}

function certStatus(cert) {
  const now = Date.now();
  if (cert.validTo < now) return 'expired';
  if (cert.validTo - now < 90 * 24 * 60 * 60 * 1000) return 'expiring';
  return 'valid';
}

// ─── JSON ────────────────────────────────────────────────────────────────────

function buildJson(data) {
  return {
    generatedAt: new Date().toISOString(),
    machine: data.machine,
    totalCerts: data.stores.reduce((s, st) => s + st.certs.length, 0),
    stores: data.stores.map(st => ({
      path: st.path,
      label: st.label,
      count: st.certs.length,
      certs: st.certs.map(c => ({
        friendlyName: c.friendlyName,
        subject: c.subject,
        issuer: c.issuer,
        thumbprint: c.thumbprint,
        serialNumber: c.serialNumber,
        validFrom: formatDate(c.validFrom),
        validTo: formatDate(c.validTo),
        ski: c.ski,
        aki: c.aki,
      })),
    })),
  };
}

// ─── HTML ────────────────────────────────────────────────────────────────────

function renderCertRow(cert, idx) {
  const status = certStatus(cert);
  const name = esc(cert.friendlyName || extractCN(cert.subject));
  const issuerCN = esc(extractCN(cert.issuer));
  const skiShort = cert.ski ? cert.ski.slice(0, 16).toUpperCase() + '…' : '(none)';
  const thumbShort = cert.thumbprint ? cert.thumbprint.slice(0, 16) + '…' : '(none)';
  const statusClass = status === 'expired' ? 'row-expired' : status === 'expiring' ? 'row-expiring' : '';

  return `<tr class="${statusClass}" data-idx="${idx}" onclick="toggleDetails(this)">
      <td class="td-name" title="${esc(cert.subject)}">${name}</td>
      <td title="${esc(cert.issuer)}">${issuerCN}</td>
      <td>${esc(formatDate(cert.validFrom))}</td>
      <td class="td-date${status === 'expired' ? ' expired' : status === 'expiring' ? ' expiring' : ''}">${esc(formatDate(cert.validTo))}</td>
      <td class="td-mono" title="${esc(formatSki(cert.ski))}">${esc(skiShort)}</td>
      <td class="td-mono" title="${esc(cert.thumbprint)}">${thumbShort}</td>
    </tr>
    <tr class="detail-row" id="detail-${idx}" style="display:none">
      <td colspan="6">
        <div class="detail-box">
          <div><span class="dl">主體：</span><code>${esc(cert.subject)}</code></div>
          <div><span class="dl">發行者：</span><code>${esc(cert.issuer)}</code></div>
          <div>
            <span class="dl">SKI：</span><code>${esc(formatSki(cert.ski))}</code>
            &nbsp;&nbsp;<span class="dl">AKI：</span><code>${esc(formatSki(cert.aki))}</code>
          </div>
          <div>
            <span class="dl">指紋 (SHA1)：</span><code>${esc(cert.thumbprint)}</code>
            &nbsp;&nbsp;<span class="dl">序號：</span><code>${esc(cert.serialNumber)}</code>
          </div>
        </div>
      </td>
    </tr>`;
}

function renderStore(store, storeIdx) {
  if (store.certs.length === 0) {
    return `<section id="st${storeIdx}">
      <h2>${esc(store.label)} <span class="count">0 張</span></h2>
      <p class="empty-store">此存放區無憑證。</p>
    </section>`;
  }

  const rows = store.certs.map((c, i) => renderCertRow(c, `${storeIdx}-${i}`)).join('');
  const expiredCount = store.certs.filter(c => certStatus(c) === 'expired').length;
  const expiringCount = store.certs.filter(c => certStatus(c) === 'expiring').length;
  const warningHtml = (expiredCount + expiringCount > 0)
    ? `<div class="warning-bar">${expiredCount > 0 ? `<span class="badge-expired">${expiredCount} 張已過期</span>` : ''}${expiringCount > 0 ? `<span class="badge-expiring">${expiringCount} 張 90 天內到期</span>` : ''}</div>`
    : '';

  return `<section id="st${storeIdx}">
    <h2>${esc(store.label)} <span class="count">${store.certs.length} 張</span></h2>
    ${warningHtml}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>名稱</th>
            <th>發行者</th>
            <th>有效起始</th>
            <th>有效截止</th>
            <th>SKI</th>
            <th>SHA1 指紋</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </section>`;
}

function buildHtml(data) {
  const genTime = new Date().toLocaleString('zh-TW', { timeZone: 'Asia/Taipei' });
  const totalCerts = data.stores.reduce((s, st) => s + st.certs.length, 0);
  const navHtml = data.stores
    .filter(st => st.certs.length > 0)
    .map((st, i) => `<li><a href="#st${i}">${esc(st.label)} (${st.certs.length})</a></li>`)
    .join('');
  const sectionsHtml = data.stores.map((st, i) => renderStore(st, i)).join('\n');

  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>本機 CA 憑證清單</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;font-size:14px;color:#222;background:#f0f2f5}
header{background:#1a4a3c;color:#fff;padding:18px 32px}
header h1{font-size:20px;font-weight:600}
header p{font-size:12px;opacity:.75;margin-top:4px}
nav{background:#fff;border-bottom:1px solid #d9e0e8;padding:10px 32px}
nav ul{list-style:none;display:flex;flex-wrap:wrap;gap:8px}
nav a{color:#1a4a3c;text-decoration:none;padding:3px 12px;border:1px solid #1a4a3c;border-radius:20px;font-size:12px;transition:.15s}
nav a:hover{background:#1a4a3c;color:#fff}
main{max-width:1400px;margin:20px auto;padding:0 20px}
section{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.1);padding:20px 24px;margin-bottom:16px}
section h2{font-size:15px;color:#1a4a3c;font-weight:600;border-bottom:2px solid #1a4a3c;padding-bottom:8px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.count{font-size:12px;font-weight:400;color:#666;background:#f0f0f0;padding:1px 8px;border-radius:10px}
.warning-bar{margin-bottom:10px;display:flex;gap:8px}
.badge-expired{background:#fee2e2;color:#991b1b;font-size:12px;padding:2px 10px;border-radius:10px}
.badge-expiring{background:#fef3c7;color:#92400e;font-size:12px;padding:2px 10px;border-radius:10px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#f8f9fa;color:#555;font-weight:600;padding:8px 12px;text-align:left;border-bottom:2px solid #e0e0e0;white-space:nowrap}
td{padding:6px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top}
tr.data-row:hover td{background:#f8fbff;cursor:pointer}
tr.row-expired td{background:#fff5f5}
tr.row-expiring td{background:#fffdf0}
.expired{color:#dc2626;font-weight:600}
.expiring{color:#d97706;font-weight:600}
.td-name{font-weight:500;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.td-mono{font-family:monospace;font-size:12px;color:#555}
.td-date{white-space:nowrap}
.detail-row td{padding:0}
.detail-box{background:#f8fafc;border-left:3px solid #1a4a3c;padding:10px 16px;font-size:12px;line-height:2}
.detail-box code{font-family:monospace;font-size:11px;background:#eef2f7;padding:1px 5px;border-radius:3px;word-break:break-all}
.dl{color:#888;font-size:11px;margin-right:4px}
.empty-store{color:#aaa;font-style:italic;font-size:13px;padding:8px 0}
footer{text-align:center;color:#bbb;font-size:11px;padding:20px}
</style>
</head>
<body>
<header>
  <h1>本機 CA 憑證清單 — ${esc(data.machine)}</h1>
  <p>產生時間：${esc(genTime)}　　共 ${totalCerts} 張憑證（${data.stores.length} 個存放區）</p>
</header>
<nav><ul>${navHtml}</ul></nav>
<main>
${sectionsHtml}
</main>
<footer>Generated by CertUilt listPCCA</footer>
<script>
function toggleDetails(row){
  if(!row.id){
    const idx=row.getAttribute('data-idx');
    const d=document.getElementById('detail-'+idx);
    if(d)d.style.display=d.style.display==='none'?'':'none';
  }
}
document.querySelectorAll('tbody tr:not(.detail-row)').forEach(tr=>{
  tr.classList.add('data-row');
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

function generatePcReports(data) {
  const outDir = ensureOutputDir();

  const jsonPath = path.join(outDir, 'pc-result.json');
  fs.writeFileSync(jsonPath, JSON.stringify(buildJson(data), null, 2), 'utf8');
  console.log(`[output] JSON 結果：${jsonPath}`);

  const htmlPath = path.join(outDir, 'pc-report.html');
  fs.writeFileSync(htmlPath, buildHtml(data), 'utf8');
  console.log(`[output] HTML 報表：${htmlPath}`);
}

module.exports = { generatePcReports };
