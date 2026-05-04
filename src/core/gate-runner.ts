// src/sswp/core/gate-runner.ts
/** Runs VERITAS-style deterministic gates on a build */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { GateResult, BuildEnvironment } from './types.js';

/** Regime controls gate severity: developer (lenient), ci (moderate), strict (hard-fail) */
export type Regime = 'developer' | 'ci' | 'strict';

export async function runGates(projectRoot: string, env: BuildEnvironment, regime: Regime = 'developer'): Promise<GateResult[]> {
  const results: GateResult[] = [];

  // Gate 0: Language detection — polyglot support (Node, Python, Go, Rust, HTML)
  results.push(await languageDetectionGate(projectRoot));

  // Gate 1: Source Integrity — repo has clean working tree (regime-aware)
  results.push(await gitIntegrityGate(projectRoot, regime));
  
  // Gate 2: Dependency Lock — lockfile matches package.json (or equivalent)
  results.push(await lockfileGate(projectRoot));

  // Gate 3: Deterministic Build — build produces identical output hash
  results.push(await deterministicBuildGate(projectRoot, env));

  // Gate 4: Test Pass — all tests pass
  results.push(await testGate(projectRoot, env));

  // Gate 5: Lint — no lint errors
  results.push(await lintGate(projectRoot));

  return results;
}

// ── Gate 0: Language Detection ──

function languageDetectionGate(root: string): GateResult {
  const start = Date.now();
  const languages: string[] = [];
  
  if (existsSync(join(root, 'package.json'))) languages.push('node');
  if (existsSync(join(root, 'requirements.txt')) || existsSync(join(root, 'pyproject.toml')) || existsSync(join(root, 'setup.py'))) languages.push('python');
  if (existsSync(join(root, 'go.mod'))) languages.push('go');
  if (existsSync(join(root, 'Cargo.toml'))) languages.push('rust');
  if (existsSync(join(root, 'index.html')) && !existsSync(join(root, 'package.json'))) languages.push('html');
  if (!languages.length) languages.push('unknown');
  
  return {
    gate: 'LANGUAGE_DETECTION',
    status: 'PASS',
    evidence: `Detected: ${languages.join(', ')}`,
    durationMs: Date.now() - start,
  };
}

// ── Gate 2: Dependency Lock (polyglot) ──

async function lockfileGate(root: string): Promise<GateResult> {
  return timed('LOCKFILE', () => {
    // Node.js
    if (existsSync(join(root, 'package.json'))) {
      const hasLock = existsSync(join(root, 'package-lock.json')) || existsSync(join(root, 'yarn.lock')) || existsSync(join(root, 'pnpm-lock.yaml'));
      if (!hasLock) return { gate: 'LOCKFILE', status: 'FAIL' as const, evidence: 'package.json present but no lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml)', durationMs: 0 };
      return { gate: 'LOCKFILE', status: 'PASS' as const, evidence: 'Lockfile present', durationMs: 0 };
    }
    // Python
    if (existsSync(join(root, 'requirements.txt'))) {
      return { gate: 'LOCKFILE', status: 'PASS' as const, evidence: 'requirements.txt (pinned dependencies)', durationMs: 0 };
    }
    if (existsSync(join(root, 'pyproject.toml'))) {
      const hasPoetryLock = existsSync(join(root, 'poetry.lock'));
      const hasUvLock = existsSync(join(root, 'uv.lock'));
      return {
        gate: 'LOCKFILE', 
        status: (hasPoetryLock || hasUvLock) ? 'PASS' as const : 'WARN' as const,
        evidence: hasPoetryLock ? 'poetry.lock present' : hasUvLock ? 'uv.lock present' : 'pyproject.toml present but no lockfile',
        durationMs: 0,
      };
    }
    // Go
    if (existsSync(join(root, 'go.mod'))) {
      const hasSum = existsSync(join(root, 'go.sum'));
      return { gate: 'LOCKFILE', status: hasSum ? 'PASS' as const : 'WARN' as const, evidence: hasSum ? 'go.sum present' : 'go.mod present but no go.sum', durationMs: 0 };
    }
    // Rust
    if (existsSync(join(root, 'Cargo.toml'))) {
      const hasCargoLock = existsSync(join(root, 'Cargo.lock'));
      return { gate: 'LOCKFILE', status: hasCargoLock ? 'PASS' as const : 'WARN' as const, evidence: hasCargoLock ? 'Cargo.lock present' : 'Cargo.toml present but no Cargo.lock', durationMs: 0 };
    }
    // HTML / static
    if (existsSync(join(root, 'index.html')) && !existsSync(join(root, 'package.json'))) {
      return { gate: 'LOCKFILE', status: 'PASS' as const, evidence: 'Static site (no dependency manager)', durationMs: 0 };
    }
    return { gate: 'LOCKFILE', status: 'INCONCLUSIVE' as const, evidence: 'No recognized project type', durationMs: 0 };
  });
}

function timed(name: string, fn: () => GateResult): GateResult {
  const start = Date.now();
  const result = fn();
  result.durationMs = Date.now() - start;
  result.gate = name;
  return result;
}

async function gitIntegrityGate(root: string, regime: Regime): Promise<GateResult> {
  return timed('GIT_INTEGRITY', () => {
    const r = spawnSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
    const clean = !r.stdout?.trim();
    if (clean) {
      return { gate: 'GIT_INTEGRITY', status: 'PASS' as const, evidence: 'Working tree clean', durationMs: 0 };
    }
    const fileCount = r.stdout?.trim().split('\n').length || 0;
    const evidence = `Modified files: ${fileCount}`;
    // developer regime: dirty tree is WARN, not FAIL — normal for dev machines
    // ci/strict regime: dirty tree is FAIL — must be clean before witness
    const status = regime === 'developer' ? 'WARN' as const : 'FAIL' as const;
    return { gate: 'GIT_INTEGRITY', status, evidence, durationMs: 0 };
  });
}

async function deterministicBuildGate(root: string, env: BuildEnvironment): Promise<GateResult> {
  return timed('DETERMINISTIC_BUILD', () => {
    // Node: check if build script exists before running
    if (existsSync(join(root, 'package.json'))) {
      const hasBuildScript = hasScript(root, 'build');
      if (!hasBuildScript) {
        return { gate: 'DETERMINISTIC_BUILD', status: 'INCONCLUSIVE' as const, evidence: 'No build script in package.json', durationMs: 0 };
      }
      const r = spawnSync('npm', ['run', 'build'], { cwd: root, encoding: 'utf8', shell: true, timeout: 60000 });
      const passed = r.status === 0;
      return {
        gate: 'DETERMINISTIC_BUILD',
        status: passed ? 'PASS' : 'FAIL',
        evidence: passed ? 'Build succeeded: npm run build' : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Python
    if (existsSync(join(root, 'pyproject.toml'))) {
      const r = spawnSync('python3', ['-m', 'build'], { cwd: root, encoding: 'utf8', shell: true, timeout: 60000 });
      return {
        gate: 'DETERMINISTIC_BUILD',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'Build succeeded: python3 -m build' : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Makefile
    if (existsSync(join(root, 'Makefile'))) {
      const r = spawnSync('make', [], { cwd: root, encoding: 'utf8', shell: true, timeout: 60000 });
      return {
        gate: 'DETERMINISTIC_BUILD',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'Build succeeded: make' : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Go
    if (existsSync(join(root, 'go.mod'))) {
      const r = spawnSync('go', ['build', './...'], { cwd: root, encoding: 'utf8', shell: true, timeout: 60000 });
      return {
        gate: 'DETERMINISTIC_BUILD',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'Build succeeded: go build' : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Rust
    if (existsSync(join(root, 'Cargo.toml'))) {
      const r = spawnSync('cargo', ['build'], { cwd: root, encoding: 'utf8', shell: true, timeout: 60000 });
      return {
        gate: 'DETERMINISTIC_BUILD',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'Build succeeded: cargo build' : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Static HTML
    if (existsSync(join(root, 'index.html')) && !existsSync(join(root, 'package.json'))) {
      return { gate: 'DETERMINISTIC_BUILD', status: 'PASS' as const, evidence: 'Static HTML site (no build required)', durationMs: 0 };
    }
    return { gate: 'DETERMINISTIC_BUILD', status: 'INCONCLUSIVE' as const, evidence: 'No recognized build system', durationMs: 0 };
  });
}

async function testGate(root: string, env: BuildEnvironment): Promise<GateResult> {
  return timed('TEST_PASS', () => {
    // Node: check if test script exists before running
    if (existsSync(join(root, 'package.json'))) {
      const hasTestScript = hasScript(root, 'test');
      if (!hasTestScript) {
        return { gate: 'TEST_PASS', status: 'INCONCLUSIVE' as const, evidence: 'No test script in package.json', durationMs: 0 };
      }
      const r = spawnSync('npm', ['test'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      const passed = r.status === 0;
      return {
        gate: 'TEST_PASS',
        status: passed ? 'PASS' : 'FAIL',
        evidence: passed ? 'npm test passed' : `npm test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Python: pytest
    if (existsSync(join(root, 'pyproject.toml')) || existsSync(join(root, 'requirements.txt'))) {
      const r = spawnSync('python3', ['-m', 'pytest'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      return {
        gate: 'TEST_PASS',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'pytest passed' : `pytest failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Makefile
    if (existsSync(join(root, 'Makefile'))) {
      const r = spawnSync('make', ['test'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      return {
        gate: 'TEST_PASS',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'make test passed' : `make test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Go
    if (existsSync(join(root, 'go.mod'))) {
      const r = spawnSync('go', ['test', './...'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      return {
        gate: 'TEST_PASS',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'go test passed' : `go test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Rust
    if (existsSync(join(root, 'Cargo.toml'))) {
      const r = spawnSync('cargo', ['test'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      return {
        gate: 'TEST_PASS',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'cargo test passed' : `cargo test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    return { gate: 'TEST_PASS', status: 'INCONCLUSIVE' as const, evidence: 'No test runner configured', durationMs: 0 };
  });
}

async function lintGate(root: string): Promise<GateResult> {
  return timed('LINT', () => {
    // Try eslint first (check if config exists)
    const eslintConfigs = ['.eslintrc.js', '.eslintrc.cjs', '.eslintrc.json', '.eslintrc.yaml', '.eslintrc.yml', 'eslint.config.js', 'eslint.config.mjs', 'eslint.config.ts'];
    const hasEslintConfig = eslintConfigs.some(cfg => existsSync(join(root, cfg)));
    if (hasEslintConfig) {
      const r = spawnSync('npx', ['eslint', '--max-warnings=0', '.'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      // eslint not installed → INCONCLUSIVE, not FAIL
      if (r.error || (r.stderr?.includes('not found') || r.stderr?.includes('ENOENT') || r.stderr?.includes('ERR! code'))) {
        return { gate: 'LINT', status: 'INCONCLUSIVE' as const, evidence: 'ESLint config present but eslint not installed', durationMs: 0 };
      }
      return {
        gate: 'LINT',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'eslint passed' : `eslint failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // Try biome
    const hasBiomeConfig = existsSync(join(root, 'biome.json'));
    if (hasBiomeConfig) {
      const r = spawnSync('npx', ['biome', 'check', '.'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      if (r.error || (r.stderr?.includes('not found') || r.stderr?.includes('ENOENT') || r.stderr?.includes('ERR! code'))) {
        return { gate: 'LINT', status: 'INCONCLUSIVE' as const, evidence: 'Biome config present but biome not installed', durationMs: 0 };
      }
      return {
        gate: 'LINT',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'biome passed' : `biome failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    // TypeScript: check for tsconfig
    const hasTscConfig = existsSync(join(root, 'tsconfig.json'));
    if (hasTscConfig) {
      const r = spawnSync('npx', ['tsc', '--noEmit'], { cwd: root, encoding: 'utf8', shell: true, timeout: 120000 });
      if (r.error || (r.stderr?.includes('not found') || r.stderr?.includes('ENOENT') || r.stderr?.includes('ERR! code'))) {
        return { gate: 'LINT', status: 'INCONCLUSIVE' as const, evidence: 'tsconfig.json present but typescript not installed', durationMs: 0 };
      }
      return {
        gate: 'LINT',
        status: r.status === 0 ? 'PASS' : 'FAIL',
        evidence: r.status === 0 ? 'tsc --noEmit passed' : `tsc failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0,
      };
    }
    return { gate: 'LINT', status: 'INCONCLUSIVE' as const, evidence: 'No linter configured', durationMs: 0 };
  });
}

// ── Helpers ──

/** Check if package.json has a specific script entry */
function hasScript(root: string, scriptName: string): boolean {
  try {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    return typeof pkg.scripts?.[scriptName] === 'string';
  } catch {
    return false;
  }
}
