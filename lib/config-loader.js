'use strict';

const fs = require('fs');
const path = require('path');

const CONFIG_FILE = path.join(process.cwd(), 'config.json');

const DEFAULTS = {
  rootCAWhitelist: [],
  ccadb: {
    diffStoreLimit:   100,
    diffDisplayLimit: 20,
  },
};

function loadConfig() {
  if (!fs.existsSync(CONFIG_FILE)) return DEFAULTS;
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    const whitelist = (Array.isArray(raw.rootCAWhitelist) ? raw.rootCAWhitelist : [])
      .filter(e => e && (e.ski || e.name));
    const ccadb = raw.ccadb && typeof raw.ccadb === 'object' ? raw.ccadb : {};
    return {
      rootCAWhitelist: whitelist,
      ccadb: {
        diffStoreLimit:   Number.isInteger(ccadb.diffStoreLimit)   && ccadb.diffStoreLimit   > 0 ? ccadb.diffStoreLimit   : DEFAULTS.ccadb.diffStoreLimit,
        diffDisplayLimit: Number.isInteger(ccadb.diffDisplayLimit) && ccadb.diffDisplayLimit > 0 ? ccadb.diffDisplayLimit : DEFAULTS.ccadb.diffDisplayLimit,
      },
    };
  } catch (err) {
    console.warn(`[config] 無法解析 config.json: ${err.message}`);
    return DEFAULTS;
  }
}

module.exports = { loadConfig };
