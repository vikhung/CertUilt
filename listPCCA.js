'use strict';

if (process.platform !== 'win32') {
  console.error('[error] listPCCA.js 僅支援 Windows 平台。');
  process.exit(1);
}

const { execFileSync } = require('child_process');
const { X509Certificate } = require('crypto');
const os = require('os');
const path = require('path');
const { parseCertMeta } = require('./lib/cert-parser');
const { generatePcReports } = require('./lib/pc-report-generator');
const { initLogger } = require('./lib/logger');
const { generateLogSummary } = require('./lib/log-summary-generator');

// Windows 憑證存放區清單
const STORES = [
  { path: 'LocalMachine\\Root',     label: '本機 - 信任的根憑證授權單位' },
  { path: 'LocalMachine\\CA',       label: '本機 - 中繼憑證授權單位' },
  { path: 'LocalMachine\\AuthRoot', label: '本機 - 協力廠商根憑證授權單位' },
  { path: 'CurrentUser\\Root',      label: '目前使用者 - 信任的根憑證授權單位' },
  { path: 'CurrentUser\\CA',        label: '目前使用者 - 中繼憑證授權單位' },
];

function buildPsScript(storePath) {
  // 使用字串陣列拼接，避免 Node.js template literal 誤解 PS 變數
  return [
    'try {',
    '  $ErrorActionPreference = "Stop"',
    `  $raw = @(Get-ChildItem -Path "Cert:\\${storePath}")`,
    '  if ($raw.Count -eq 0) { Write-Output "[]"; return }',
    '  $arr = $raw | ForEach-Object {',
    '    [PSCustomObject]@{',
    '      FriendlyName = [string]$_.FriendlyName',
    '      Subject      = [string]$_.Subject',
    '      Issuer       = [string]$_.Issuer',
    '      Thumbprint   = [string]$_.Thumbprint',
    '      SerialNumber = [string]$_.SerialNumber',
    '      NotBefore    = $_.NotBefore.ToString("o")',
    '      NotAfter     = $_.NotAfter.ToString("o")',
    '      DerBase64    = [Convert]::ToBase64String($_.RawData)',
    '    }',
    '  }',
    '  @($arr) | ConvertTo-Json -Compress -Depth 3',
    '} catch {',
    '  Write-Output "[]"',
    '}',
  ].join('\n');
}

function parseCertEntry(raw) {
  try {
    const der = Buffer.from(raw.DerBase64, 'base64');
    const x509 = new X509Certificate(der);
    const meta = parseCertMeta(x509);
    return {
      friendlyName: raw.FriendlyName || '',
      subject:      raw.Subject || meta.subject || '',
      issuer:       raw.Issuer  || meta.issuer  || '',
      thumbprint:   (raw.Thumbprint || '').toLowerCase(),
      serialNumber: raw.SerialNumber || meta.serialNumber || '',
      validFrom:    new Date(raw.NotBefore),
      validTo:      new Date(raw.NotAfter),
      ski:          meta.ski,
      aki:          meta.aki,
    };
  } catch {
    return null;
  }
}

function readStore(store) {
  console.log(`[pc] 讀取：${store.path}`);
  try {
    const ps = buildPsScript(store.path);
    const output = execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { encoding: 'utf8', timeout: 30000 }
    ).trim();

    if (!output || output === 'null' || output === '[]') {
      console.log(`[pc] ${store.path}：0 張`);
      return [];
    }

    const parsed = JSON.parse(output);
    const rawList = Array.isArray(parsed) ? parsed : [parsed];
    const certs = rawList.map(parseCertEntry).filter(Boolean);
    console.log(`[pc] ${store.path}：${certs.length} 張`);
    return certs;
  } catch (err) {
    console.warn(`[pc] 警告：無法讀取 ${store.path}: ${err.message}`);
    return [];
  }
}

async function main() {
  initLogger(path.join(process.cwd(), 'logs'));
  const args = process.argv.slice(2);

  if (args[0] === '--help' || args[0] === '-h') {
    console.log('用法：node listPCCA.js');
    console.log('');
    console.log('  列出本機 Windows 憑證存放區中的所有 CA 憑證，');
    console.log('  產生 output/pc-report.html 與 output/pc-result.json。');
    console.log('');
    console.log('  掃描的存放區：');
    STORES.forEach(s => console.log(`    Cert:\\${s.path}`));
    process.exit(0);
  }

  const machine = os.hostname();
  console.log(`[pc] 主機名稱：${machine}`);
  console.log(`[pc] 掃描 ${STORES.length} 個憑證存放區...\n`);

  const stores = STORES.map(store => ({
    path:  store.path,
    label: store.label,
    certs: readStore(store),
  }));

  const totalCerts = stores.reduce((s, st) => s + st.certs.length, 0);
  console.log(`\n[pc] 掃描完成，共 ${totalCerts} 張憑證。`);

  if (totalCerts === 0) {
    console.log('[pc] 未找到任何憑證，可能需要以系統管理員身份執行。');
    process.exit(0);
  }

  console.log('\n[output] 產生報表中...');
  generatePcReports({ machine, stores });

  generateLogSummary(path.join(process.cwd(), 'logs'));
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
