'use strict';

const { X509Certificate } = require('crypto');
const fs = require('fs');

function normalizeHex(raw) {
  if (!raw) return '';
  return raw.replace(/[:\s]/g, '').toLowerCase();
}

// Read a DER length field. Returns { len, end } where end is the index of the value.
function readDerLength(buf, offset) {
  const b = buf[offset++];
  if (b < 0x80) return { len: b, end: offset };
  const nBytes = b & 0x7f;
  let len = 0;
  for (let i = 0; i < nBytes; i++) len = (len << 8) | buf[offset++];
  return { len, end: offset };
}

// Find extension extnValue (inner content of the OCTET STRING) by OID hex string.
// Looks for: 06 <oidLen> <oid bytes> [01 01 ff] 04 <len> <value>
function findExtensionValue(der, oidHex) {
  const oid = Buffer.from(oidHex, 'hex');
  for (let i = 0; i < der.length - oid.length - 4; i++) {
    if (der[i] !== 0x06 || der[i + 1] !== oid.length) continue;
    if (!der.slice(i + 2, i + 2 + oid.length).equals(oid)) continue;
    let pos = i + 2 + oid.length;
    // Skip CRITICAL boolean (01 01 ff) if present
    if (pos < der.length && der[pos] === 0x01) {
      const { len, end } = readDerLength(der, pos + 1);
      pos = end + len;
    }
    // Expect OCTET STRING wrapping the extension value
    if (pos < der.length && der[pos] === 0x04) {
      const { len, end } = readDerLength(der, pos + 1);
      return der.slice(end, end + len);
    }
  }
  return null;
}

// Extract SubjectKeyIdentifier (OID 2.5.29.14 = 55 1d 0e)
// extnValue = OCTET STRING { <20-byte key-id> }
function extractSki(der) {
  const val = findExtensionValue(der, '551d0e');
  if (!val || val[0] !== 0x04) return '';
  const { len, end } = readDerLength(val, 1);
  return val.slice(end, end + len).toString('hex');
}

// Extract AuthorityKeyIdentifier keyIdentifier (OID 2.5.29.35 = 55 1d 23)
// extnValue = SEQUENCE { [0] IMPLICIT OCTET STRING (keyIdentifier) ... }
function extractAki(der) {
  const val = findExtensionValue(der, '551d23');
  if (!val || val[0] !== 0x30) return '';
  const { end: seqEnd } = readDerLength(val, 1);
  if (seqEnd < val.length && val[seqEnd] === 0x80) {
    const { len, end } = readDerLength(val, seqEnd + 1);
    return val.slice(end, end + len).toString('hex');
  }
  return '';
}

function parseCertMeta(cert) {
  const der = cert.raw;
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    ski: extractSki(der),
    aki: extractAki(der),
    fingerprint: normalizeHex(cert.fingerprint256),
    validFrom: new Date(cert.validFrom),
    validTo: new Date(cert.validTo),
    serialNumber: cert.serialNumber,
  };
}

function parsePemChain(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const pemRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  const matches = raw.match(pemRegex);
  if (!matches || matches.length === 0) {
    throw new Error(`No PEM certificates found in: ${filePath}`);
  }
  return matches.map(pem => new X509Certificate(pem));
}

module.exports = { parseCertMeta, parsePemChain };
