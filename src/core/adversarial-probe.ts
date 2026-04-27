// src/sswp/core/adversarial-probe.ts
/** Adversarial analysis — sends deps to Kimi/Gravity Omega for reasoning */

import type { DependencyEntry, AdversarialReport, ProbeResult } from './types.js';
import { kimiAnalyze } from './kimi-reasoner.js';

/**
 * Run adversarial probes on dependencies.
 * In full production, this calls Gravity Omega's inference endpoint.
 * For now, we use a local heuristic model plus a prompt-to-Kimi path.
 */
export async function runAdversarialProbes(deps: DependencyEntry[]): Promise<AdversarialReport> {
  const probes: ProbeResult[] = [];
  let suspiciousCount = 0;

  for (const dep of deps) {
    // Heuristic probes (fast, local)
    const p1 = probeTyposquatting(dep);
    const p2 = probeVersionAnomaly(dep);
    const p3 = probeMetadataIntegrity(dep);
    probes.push(p1, p2, p3);

    if ([p1, p2, p3].some(r => r.result === 'CRITICAL')) {
      dep.suspicious = true;
      dep.riskScore = Math.max(dep.riskScore, 0.9);
      suspiciousCount++;
    } else if ([p1, p2, p3].some(r => r.result === 'WARN')) {
      dep.riskScore = Math.max(dep.riskScore, 0.5);
      suspiciousCount++;
    }
  }

  // Extended probe: Kimi reasoning via local script
  if (deps.length > 0) {
    const kimiResults = await probeWithKimi(deps);
    probes.push(...kimiResults);
  }

  // Aggregate risk
  const totalRisk = probes.filter(p => p.result === 'CRITICAL').length * 0.4 +
                    probes.filter(p => p.result === 'WARN').length * 0.15;
  const overallRisk = Math.min(1.0, totalRisk / Math.max(1, deps.length));

  return {
    totalPackages: deps.length,
    suspiciousPackages: suspiciousCount,
    probes,
    overallRisk,
  };
}

function probeTyposquatting(dep: DependencyEntry): ProbeResult {
  const suspiciousPatterns = [
    'left-pad', 'event-stream', 'colors', 'faker', 'node-ipc',
    'rc', 'ua-parser-js', 'coa', 'esbuild', 'discord.js',
  ];
  const isSuspicious = suspiciousPatterns.some(p => dep.name.toLowerCase().includes(p));
  return {
    package: dep.name,
    probe: 'TYPO_SQUATTING',
    result: isSuspicious ? 'WARN' : 'PASS',
    detail: isSuspicious ? 'Name matches known suspicious packages' : 'Name heuristic clean',
  };
}

function probeVersionAnomaly(dep: DependencyEntry): ProbeResult {
  const range = ['*', '>=', '<', '^0', '~0', 'latest'];
  const isRange = range.some(r => dep.version.includes(r));
  return {
    package: dep.name,
    probe: 'VERSION_ANOMALY',
    result: isRange ? 'WARN' : 'PASS',
    detail: isRange ? `Unpinned version: ${dep.version}` : `Pinned: ${dep.version}`,
  };
}

function probeMetadataIntegrity(dep: DependencyEntry): ProbeResult {
  const hasIntegrity = dep.integrity != null;
  return {
    package: dep.name,
    probe: 'METADATA_INTEGRITY',
    result: hasIntegrity ? 'PASS' : 'CRITICAL',
    detail: hasIntegrity ? `Hash: ${dep.integrity}` : 'No integrity hash found',
  };
}

async function probeWithKimi(deps: DependencyEntry[]): Promise<ProbeResult[]> {
  return kimiAnalyze(deps);
}
