#!/usr/bin/env node
/**
 * SSWP MCP Server — Bulletproof Launcher
 * ========================================
 * Mirrors omega-brain's self-healing pattern:
 *   1. Rebuild better-sqlite3 if binary doesn't match platform
 *   2. Run the bundled SSWP MCP server
 * 
 * No bash wrapper. No separate script. One command, always works.
 * 
 * Config: use `node` directly in config.yaml:
 *   sswp:
 *     command: node
 *     args:
 *       - /mnt/c/Veritas_Lab/sswp-mcp/sswp_mcp_launcher.js
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const SCRIPT_DIR = __dirname;
const BETTER_SQLITE3_PATH = path.join(SCRIPT_DIR, 'node_modules', 'better-sqlite3', 'build', 'Release', 'better_sqlite3.node');

// ══ Pre-flight: self-heal native module ══
if (fs.existsSync(BETTER_SQLITE3_PATH)) {
    try {
        // Try loading it — if ELF mismatch, this throws
        process.dlopen({ exports: {} }, BETTER_SQLITE3_PATH);
    } catch (e) {
        console.error(`[SSWP] Native module mismatch detected: ${e.message}`);
        console.error('[SSWP] Rebuilding better-sqlite3...');
        try {
            execSync('npm rebuild better-sqlite3', { cwd: SCRIPT_DIR, stdio: 'inherit' });
            console.error('[SSWP] Rebuild succeeded.');
        } catch (rebuildErr) {
            console.error(`[SSWP] Rebuild failed: ${rebuildErr.message}`);
            process.exit(1);
        }
    }
} else {
    console.error('[SSWP] better-sqlite3 not found, installing...');
    try {
        execSync('npm rebuild better-sqlite3', { cwd: SCRIPT_DIR, stdio: 'inherit' });
    } catch (e) {
        console.error(`[SSWP] Install failed: ${e.message}`);
        process.exit(1);
    }
}

// ══ Pin cwd to sswp-mcp root ══
// dist/sswp.cjs resolves SCHEMA_PATH from process.cwd() ("src/sswp/registry/schema.sql").
// Hermes spawns this launcher from gravity-omega-v2/, so without this chdir
// the schema lookup fails with ENOENT and the MCP connection closes immediately.
process.chdir(SCRIPT_DIR);

// ══ Delegate to bundled CJS ══
require(path.join(SCRIPT_DIR, 'dist', 'sswp.cjs'));
