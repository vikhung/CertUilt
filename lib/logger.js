'use strict';

const fs = require('fs');
const path = require('path');

function nowGmt8() {
  return new Date(Date.now() + 8 * 60 * 60 * 1000);
}

function dateStr(d) {
  return d.toISOString().slice(0, 10).replace(/-/g, '');
}

// yyyy/MM/dd hh:mm:ss.SSS
function ts(d) {
  const iso = d.toISOString(); // e.g. 2026-05-22T04:30:00.123Z
  const date = iso.slice(0, 10).replace(/-/g, '/');
  const time = iso.slice(11, 23);            // hh:mm:ss.SSS
  return `${date} ${time}`;
}

function initLogger(logDir) {
  if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

  const logFile = path.join(logDir, `${dateStr(nowGmt8())}.log`);
  const argv    = process.argv.slice(1).join(' ');
  const header  = `\n${'='.repeat(72)}\n[${ts(nowGmt8())} GMT+8]  ${argv}\n${'='.repeat(72)}\n`;

  fs.appendFileSync(logFile, header, 'utf8');

  const write = (prefix, args) => {
    const msg = args.map(String).join(' ');
    const lines = msg.split('\n');
    const out = lines
      .map(line => line === '' ? '' : `[${ts(nowGmt8())}] ${prefix}${line}`)
      .join('\n');
    fs.appendFileSync(logFile, out + '\n', 'utf8');
  };

  const orig = { log: console.log, warn: console.warn, error: console.error };

  console.log   = (...args) => { orig.log(...args);   write('',         args); };
  console.warn  = (...args) => { orig.warn(...args);  write('[WARN] ',  args); };
  console.error = (...args) => { orig.error(...args); write('[ERROR] ', args); };
}

module.exports = { initLogger };
