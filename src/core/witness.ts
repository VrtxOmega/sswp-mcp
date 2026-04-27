// src/sswp/core/witness.ts
/** SSWP orchestrator — builds, seals, and attests */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { seal } from '../../engine/sealer.js';
import { scanBuild } from './build-scanner.js';
import { runGates } from './gate-runner.js';
import { runAdversarialProbes } from './adversarial-probe.js';
import type { SswpAttestation, BuildEnvironment } from './types.js';

export async function witness(projectRoot: string): Promise<SswpAttestation> {
  // Phase 1: Scan
  const { entries, env, totalPackages, suspiciousCount } = await scanBuild(projectRoot);

  const scanSeal = seal(
    { phase: 'SCAN', totalPackages, suspiciousCount },
    `Scanned ${totalPackages} packages, ${suspiciousCount} flagged`
  );

  // Phase 2: Gates
  const gateResults = await runGates(projectRoot, env);
  const passedGates = gateResults.filter(g => g.status === 'PASS').length;

  const gateSeal = seal(
    { phase: 'GATES', passed: passedGates, total: gateResults.length },
    JSON.stringify(gateResults.map(g => ({ gate: g.gate, status: g.status })))
  );

  // Phase 3: Adversarial
  const adversarial = await runAdversarialProbes(entries);

  const advSeal = seal(
    { phase: 'ADVERSARIAL', overallRisk: adversarial.overallRisk, probes: adversarial.probes.length },
    JSON.stringify(adversarial)
  );

  // Phase 4: Attest
  const pkgJson = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'));
  const gitHash = execGit(projectRoot, ['rev-parse', 'HEAD']);
  const branch = execGit(projectRoot, ['rev-parse', '--abbrev-ref', 'HEAD']);

  // Deterministic signature — exclude signature field from hash
  const attestation: SswpAttestation = {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    target: {
      name: pkgJson.name || 'unknown',
      repo: projectRoot,
      commitHash: gitHash || 'unknown',
      branch: branch || 'unknown',
    },
    environment: {
      nodeVersion: env.nodeVersion,
      os: env.os,
      arch: env.arch,
      ci: env.ci,
    },
    dependencies: entries,
    gates: gateResults,
    adversarial,
    seal: {
      chainHash: scanSeal.hash,
      sequence: (gateSeal?.sequence ?? 0) + (advSeal?.sequence ?? 0),
    },
    signature: '',
  };

  const { signature, ...hashPayload } = attestation;
  attestation.signature = createHash('sha256').update(JSON.stringify(hashPayload, Object.keys(hashPayload).sort())).digest('hex');

  const finalSeal = seal(
    { phase: 'ATTEST', signature: attestation.signature },
    'Attestation sealed and signed'
  );

  return attestation;
}

function execGit(cwd: string, args: string[]): string {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8' });
  return r.stdout?.trim() || '';
}

export function formatAttestation(att: SswpAttestation): string {
  const lines: string[] = [];
  lines.push(`\u2b21  SSWP ATTESTATION v${att.version}`);
  lines.push(`   Target: ${att.target.name} (${att.target.commitHash.slice(0, 8)})`);
  lines.push(`   Branch: ${att.target.branch} | Env: ${att.environment.os}-${att.environment.arch}`);
  lines.push(`   Built: ${att.timestamp}`);
  lines.push('');
  lines.push('   GATES:');
  for (const g of att.gates) {
    const icon = g.status === 'PASS' ? '\u2713' : g.status === 'FAIL' ? '\u2717' : '\u25cb';
    lines.push(`     ${icon} ${g.gate.padEnd(22)} ${g.status.padEnd(14)} ${g.durationMs}ms`);
  }
  lines.push('');
  lines.push(`   DEPENDENCIES: ${att.dependencies.length} total, ${att.adversarial.suspiciousPackages} flagged`);
  lines.push(`   ADVERSARIAL RISK: ${(att.adversarial.overallRisk * 100).toFixed(1)}%`);
  lines.push(`   SEAL: ${att.signature.slice(0, 16)}...`);
  return lines.join('\n');
}

export function verifyAttestation(filePath: string): boolean {
  const att = JSON.parse(readFileSync(filePath, 'utf8'));
  const { signature, ...hashPayload } = att;
  const payload = JSON.stringify(hashPayload, Object.keys(hashPayload).sort());
  const computed = createHash('sha256').update(payload).digest('hex');
  return computed === att.signature;
}
