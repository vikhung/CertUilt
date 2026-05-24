'use strict';

const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(process.cwd(), 'config.json');

const DEFAULTS = {
  rootCAWhitelist:  [],
  downloadFromCCADB: false,
};

function loadConfig() {
  if (!fs.existsSync(CONFIG_FILE)) return DEFAULTS;
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    const whitelist = (Array.isArray(raw.rootCAWhitelist) ? raw.rootCAWhitelist : [])
      .filter(e => e && (e.ski || e.name));
    return {
      rootCAWhitelist:  whitelist,
      downloadFromCCADB: raw.downloadFromCCADB === true,
    };
  } catch (err) {
    console.warn(`[config] 無法解析 config.json: ${err.message}`);
    return DEFAULTS;
  }
}

module.exports = { loadConfig };
