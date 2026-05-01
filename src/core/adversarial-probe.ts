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
  const highValueTargets = [
    'react', 'vue', 'lodash', 'axios', 'express', 'moment', 'chalk', 'commander', 'tslib', 'dotenv',
    'typescript', 'jest', 'eslint', 'prettier', 'vite', 'webpack', 'next', 'angular', 'rxjs', 'jquery'
  ];
  
  const name = dep.name.toLowerCase();
  
  // 1. Exact or substring match for known suspicious/compromised packages
  const suspiciousPatterns = [
    'crossenv', 'nodemail.js', 'flatmap-stream', 'peacenotwar', 'node-ipc',
    'left-pad', 'event-stream', 'colors', 'faker'
  ];
  
  if (suspiciousPatterns.some(p => name.includes(p))) {
    return {
      package: dep.name,
      probe: 'TYPO_SQUATTING',
      result: 'CRITICAL',
      detail: 'Matches known malicious or compromised package pattern',
    };
  }

  // 2. Levenshtein distance check against high-value targets
  for (const target of highValueTargets) {
    if (name === target) continue; // Legitimate package
    
    const distance = levenshteinDistance(name, target);
    // Distance of 1 or 2 is highly suspicious for short/medium names
    if (distance > 0 && distance <= 2 && name.length >= 4) {
      return {
        package: dep.name,
        probe: 'TYPO_SQUATTING',
        result: 'WARN',
        detail: `Potential typosquatting of '${target}' (edit distance: ${distance})`,
      };
    }
  }

  return {
    package: dep.name,
    probe: 'TYPO_SQUATTING',
    result: 'PASS',
    detail: 'Name heuristic clean',
  };
}

/** Simple Levenshtein distance implementation */
function levenshteinDistance(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, () => 
    new Array(b.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // deletion
        matrix[i][j - 1] + 1,      // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return matrix[a.length][b.length];
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
