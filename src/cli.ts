#!/usr/bin/env node
/**
 * SSWP CLI — Sovereign Software Witness Protocol
 * Usage: sswp witness [project-root]
 */

import { witness, formatAttestation } from './core/witness.js';
import {
  saveAttestation,
  getAttestationHistory,
  getLatestAttestation,
  getRiskyNodes,
  getAllNodesStats,
} from './core/registry-db.js';
import { resolve } from 'node:path';
import { writeFileSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

async function main() {
  const [,, command, ...rest] = process.argv;

  if (command === 'witness') {
    // Parse --regime flag
    let regime: 'developer' | 'ci' | 'strict' = 'developer';
    const positional: string[] = [];
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '--regime' && rest[i + 1]) {
        const val = rest[i + 1];
        if (val === 'developer' || val === 'ci' || val === 'strict') {
          regime = val;
          i++;
          continue;
        }
      }
      positional.push(rest[i]);
    }
    const projectRoot = resolve(positional[0] || process.cwd());
    console.error(`\u2b21  SSWP — Witnessing ${projectRoot}... (regime: ${regime})`);
    
    const att = await witness(projectRoot, regime);
    console.log(formatAttestation(att));

    // Write .sswp file
    const outPath = resolve(projectRoot, `${att.target.name}.sswp.json`);
    writeFileSync(outPath, JSON.stringify(att, null, 2));

    // Save to registry
    const nodeId = att.target.name;
    const { entry, appended } = saveAttestation(nodeId, att, outPath);
    if (appended) {
      console.error(`\u2713 Attestation written: ${outPath}`);
      console.error(`\u2713 Registry entry saved: ${entry.attestationHash.slice(0, 16)}...`);
    } else {
      console.error(`\u2713 Attestation written: ${outPath}`);
      console.error(`\u26a0 Registry append failed`);
    }

    // Exit code: 0 if overall PASS or WARN, 1 if FAIL
    const failed = att.overallStatus === 'FAIL';
    process.exit(failed ? 1 : 0);
  }

  if (command === 'verify') {
    const file = rest[0];
    if (!file) {
      console.error('Usage: sswp verify <file.sswp.json>');
      process.exit(1);
    }
    const att = JSON.parse(readFileSync(resolve(file), 'utf8'));
    const { signature, ...hashPayload } = att;
    const payload = JSON.stringify(hashPayload, Object.keys(hashPayload).sort());
    const computed = createHash('sha256').update(payload).digest('hex');
    const valid = computed === att.signature;
    console.log(valid ? '\u2713 VALID ATTESTATION' : '\u2717 SIGNATURE MISMATCH');
    process.exit(valid ? 0 : 1);
  }

  if (command === 'registry') {
    const subCommand = rest[0];

    if (subCommand === 'list') {
      const stats = getAllNodesStats();
      if (stats.length === 0) {
        console.log('No registry entries found.');
        process.exit(0);
      }
      console.log(`\u2b21  SSWP Registry — ${stats.length} node(s)\n`);
      console.log('NODE ID'.padEnd(28) + 'RISK'.padEnd(10) + 'LAST WITNESS'.padEnd(22) + 'COUNT');
      console.log('-'.repeat(70));
      for (const s of stats) {
        const riskStr = `${(s.latestRisk * 100).toFixed(1)}%`;
        const timeStr = new Date(s.latestTimestamp).toLocaleString();
        console.log(
          s.nodeId.padEnd(28) +
          riskStr.padEnd(10) +
          timeStr.padEnd(22) +
          String(s.witnessCount)
        );
      }
      process.exit(0);
    }

    if (subCommand === 'history') {
      const nodeId = rest[1];
      if (!nodeId) {
        console.error('Usage: sswp registry history <nodeId>');
        process.exit(1);
      }
      const hist = getAttestationHistory(nodeId);
      if (hist.length === 0) {
        console.log(`No history found for node ${nodeId}`);
        process.exit(0);
      }
      console.log(`\u2b21  SSWP History for ${nodeId} (${hist.length} attestations)\n`);
      console.log(
        'HASH'.padEnd(20) + 'TIMESTAMP'.padEnd(24) + 'RISK'.padEnd(10) + 'GATES' + ' ' + 'PATH'
      );
      console.log('-'.repeat(100));
      for (const h of hist) {
        const hash = h.attestationHash.slice(0, 16) + '...';
        const ts = new Date(h.timestamp).toLocaleString();
        const risk = `${(h.risk * 100).toFixed(1)}%`;
        const gates = `${h.passedGates}/${h.totalGates}`;
        console.log(`${hash.padEnd(20)}${ts.padEnd(24)}${risk.padEnd(10)}${gates}  ${h.attestationPath}`);
      }
      process.exit(0);
    }

    if (subCommand === 'risky') {
      const threshold = rest[1] ? parseFloat(rest[1]) : 0.3;
      const risky = getRiskyNodes(threshold);
      if (risky.length === 0) {
        console.log(`No nodes exceed risk threshold ${threshold}.`);
        process.exit(0);
      }
      console.log(`\u2b21  SSWP Risky Nodes (risk > ${threshold})\n`);
      console.log('NODE ID'.padEnd(28) + 'RISK'.padEnd(10) + 'LAST TIMESTAMP');
      console.log('-'.repeat(60));
      for (const r of risky) {
        console.log(
          r.nodeId.padEnd(28) +
          `${(r.risk * 100).toFixed(1)}%`.padEnd(10) +
          new Date(r.timestamp).toLocaleString()
        );
      }
      process.exit(0);
    }

    console.log(`\n registry subcommands:   list | history <nodeId> | risky [threshold]\n`);
    process.exit(1);
  }

  console.log(`
\u2b21  Sovereign Software Witness Protocol (SSWP) v1.0

Commands:
  sswp witness [dir]   Scan, build-test, adversarial-probe, and seal
  sswp verify <file>   Verify an existing .sswp.json attestation
  sswp registry list     List all nodes with latest risk
  sswp registry history <nodeId>   Print attestation history for a node
  sswp registry risky [threshold]  Print nodes with risk > threshold (default 0.3)

Examples:
  sswp witness /mnt/c/Veritas_Lab/veritas-topography-map
  sswp verify veritas-topography-map.sswp.json
  sswp registry list
  sswp registry risky 0.5
`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
