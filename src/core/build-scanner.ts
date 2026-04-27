// src/sswp/core/build-scanner.ts
/** Discovers dependencies and computes integrity hashes */

import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import type { DependencyEntry, BuildEnvironment } from './types.js';

export interface ScanResult {
  entries: DependencyEntry[];
  env: BuildEnvironment;
  totalPackages: number;
  suspiciousCount: number;
}

export async function scanBuild(projectRoot: string): Promise<ScanResult> {
  const entries: DependencyEntry[] = [];

  // Discover npm dependencies
  const pkgPath = join(projectRoot, 'package.json');
  if (existsSync(pkgPath)) {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    for (const [name, version] of Object.entries(deps)) {
      const ver = String(version).replace('^', '').replace('~', '');
      entries.push(await analyzeDependency(projectRoot, name, ver));
    }
  }

  // Build environment
  const env: BuildEnvironment = {
    cwd: projectRoot,
    nodeVersion: process.version,
    os: process.platform,
    arch: process.arch,
    ci: !!process.env.CI,
    buildCommand: inferBuildCommand(projectRoot),
    buildOutput: 'dist/',
  };

  const suspiciousCount = entries.filter(e => e.suspicious).length;

  return { entries, env, totalPackages: entries.length, suspiciousCount };
}

async function analyzeDependency(projectRoot: string, name: string, version: string): Promise<DependencyEntry> {
  const path = join(projectRoot, 'node_modules', name);
  const pkgJsonPath = join(path, 'package.json');
  
  let integrity: string | null = null;
  if (existsSync(pkgJsonPath)) {
    const content = readFileSync(pkgJsonPath, 'utf8');
    integrity = createHash('sha256').update(content).digest('hex').slice(0, 16);
  }

  // Heuristic: flag if no integrity hash or version is range
  const suspicious = !integrity || version.startsWith('>') || version.startsWith('*');

  return {
    name,
    version,
    resolved: path,
    integrity,
    suspicious,
    riskScore: suspicious ? 0.7 : 0.1,
  };
}

function inferBuildCommand(projectRoot: string): string {
  if (existsSync(join(projectRoot, 'package.json'))) {
    const pkg = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'));
    if (pkg.scripts?.build) return `npm run build`;
    if (pkg.scripts?.compile) return `npm run compile`;
  }
  if (existsSync(join(projectRoot, 'Makefile'))) return 'make';
  if (existsSync(join(projectRoot, 'Cargo.toml'))) return 'cargo build';
  return 'unknown';
}
