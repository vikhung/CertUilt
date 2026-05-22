'use strict';

function buildTree(rootSki, akiIndex) {
  const seen = new Set();

  function recurse(ski, depth) {
    const children = akiIndex.get(ski) ?? [];
    return children.map(entry => {
      const nodeKey = entry.fingerprint || entry.certName + entry.validFrom;
      if (seen.has(nodeKey)) {
        return { info: entry, children: [], depth };
      }
      seen.add(nodeKey);
      const subChildren = entry.ski ? recurse(entry.ski, depth + 1) : [];
      return { info: entry, children: subChildren, depth };
    });
  }

  return recurse(rootSki, 1);
}

function formatDate(d) {
  if (!d || d.getTime() === 0) return 'N/A';
  return d.toISOString().slice(0, 10);
}

function formatSki(ski) {
  if (!ski) return '(none)';
  return ski.replace(/(.{2})(?=.)/g, '$1:').toUpperCase();
}

function extractCN(dn) {
  const match = dn.match(/CN\s*=\s*([^,\n]+)/i);
  return match ? match[1].trim() : dn.slice(0, 60);
}

function printNode(node, prefix, isLast, targetSki) {
  const connector = isLast ? '└─' : '├─';
  const childPfx  = prefix + (isLast ? '   ' : '│  ');
  const indent    = `${childPfx}  `;
  const status    = node.info.status ? ` [${node.info.status}]` : '';
  const validity  = `${formatDate(node.info.validFrom)} ~ ${formatDate(node.info.validTo)}`;
  const name      = node.info.certName || extractCN(node.info.subject);
  const owner     = node.info.caOwner ? ` (${node.info.caOwner})` : '';
  const isTarget  = targetSki && node.info.ski === targetSki;
  const marker    = isTarget ? '  ◄ 本次查詢標的' : '';
  const rootTag   = node.info.isRoot ? ' [Root]' : '';

  console.log(`${prefix}${connector} ${name}${owner}${rootTag}${status}${marker}`);
  console.log(`${indent}Valid: ${validity}`);
  console.log(`${indent}SKI:   ${formatSki(node.info.ski)}`);
  console.log(`${indent}AKI:   ${formatSki(node.info.aki)}`);

  node.children.forEach((child, i) => {
    printNode(child, childPfx, i === node.children.length - 1, targetSki);
  });
}

function printTree(rootLabel, rootSki, rootFingerprint, nodes, targetSki = '') {
  const fp = rootFingerprint
    ? `  [SHA-256: ${rootFingerprint.slice(0, 16)}...]`
    : '';
  console.log(`\nRoot CA: ${rootLabel}${fp}`);
  console.log(`         SKI: ${formatSki(rootSki)}`);

  if (nodes.length === 0) {
    console.log('\n  (No UCAs found in CCADB for this Root CA)');
    console.log('  Possible reasons:');
    console.log('  - This Root CA is not in a major public trust program');
    console.log('  - Try querying crt.sh for private/enterprise CAs');
    return;
  }

  console.log(`\n  Found ${countNodes(nodes)} UCA(s) total across ${maxDepth(nodes)} level(s):\n`);
  nodes.forEach((node, i) => {
    printNode(node, '  ', i === nodes.length - 1, targetSki);
  });
}

function countNodes(nodes) {
  return nodes.reduce((sum, n) => sum + 1 + countNodes(n.children), 0);
}

function maxDepth(nodes) {
  if (nodes.length === 0) return 0;
  return Math.max(...nodes.map(n => 1 + maxDepth(n.children)));
}

module.exports = { buildTree, printTree };
