<div align="center">
  <img src="https://raw.githubusercontent.com/VrtxOmega/Gravity-Omega/master/omega_icon.png" width="120" alt="VERITAS Omega" />
  <h1>SSWP MCP</h1>
  <p><strong>Sovereign Software Witness Protocol — Deterministic Attestation · Adversarial Probing · Tamper-Proof Sealing</strong></p>
</div>

<div align="center">

![Status](https://img.shields.io/badge/Status-ACTIVE-success?style=flat-square&labelColor=000000&color=d4af37)
![Version](https://img.shields.io/badge/Version-v2.0.1-blue?style=flat-square&labelColor=000000)
![Node](https://img.shields.io/badge/Node-18%2B-informational?style=flat-square&labelColor=000000)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square&labelColor=000000)

[![sswp-mcp MCP server](https://glama.ai/mcp/servers/VrtxOmega/sswp-mcp/badges/card.svg)](https://glama.ai/mcp/servers/VrtxOmega/sswp-mcp)

</div>

---

## Ecosystem Canon

SSWP MCP is the attestation and witness layer of the **VERITAS & Sovereign Ecosystem (Omega Universe)**. Where Omega Brain governs execution paths through policy gates, SSWP governs the artifact itself — capturing what code was, what was done to it, and whether it survived disciplined attempts to break it, all sealed against revision. It exposes an MCP server that Hermes, Claude, Cline, or any compatible agent can call natively to witness any software project with deterministic attestation, probe dependencies for supply-chain risk, and audit the fleet registry across every node in the ecosystem. Every `sswp_witness` call produces a self-verifying `.sswp.json` attestation file. Every `sswp_bulk_witness` run is logged to the tamper-proof audit ledger. The fleet registry — currently **131 nodes** — makes the entire ecosystem auditable in one command.

> **SYSTEM INVARIANT:** SSWP does not certify that code is correct. SSWP certifies what code *was*, what was done to it, and by whom — sealed against revision.

---

## Table of Contents

- [Overview](#overview)
- [The Problem](#the-problem)
- [What SSWP Does](#what-sswp-does)
- [Example Attestation](#example-attestation)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Tools Reference](#tools-reference-8-tools)
- [CLI](#cli)
- [How Is This Different From sigstore / SLSA / in-toto?](#how-is-this-different-from-sigstore--slsa--in-toto)
- [Roadmap](#roadmap)
- [Omega Universe](#omega-universe)
- [License](#license)

---

## Overview

### What It Is

SSWP MCP is a self-contained **Model Context Protocol (MCP) server** that runs as a local process alongside any MCP-compatible AI client. It exposes **8 tools** covering four witness domains:

- **Deterministic attestation** — scan, gate-test, adversarially probe, and seal any software repo to a self-verifying `.sswp.json` file
- **Supply-chain probing** — typosquatting detection, version anomaly scanning, metadata integrity checks, and optional Kimi K2-powered reasoning
- **Fleet registry** — SQLite database with FTS5 search, health board, risk leaderboard, and gate trends across all witnessed repos
- **Tamper-proof audit ledger** — append-only SHA-256 hash chain; every witness run, every gate vote, every probe result is sealed

One repository. Node.js v18+. Zero cloud dependencies.

Compatible clients: Hermes, Claude Desktop, VS Code Copilot, Cursor, Cline, Windsurf, and any MCP-compliant host.

### What It Is Not

- **Not a build system.** SSWP witnesses — it does not orchestrate builds, deployments, or CI pipelines.
- **Not a CVE database.** The adversarial probes are heuristic (typosquatting patterns, version pinning, metadata integrity). They complement, not replace, dedicated vulnerability scanners.
- **Not a security audit.** SSWP produces evidence. Whether that evidence satisfies a reviewer's threshold is the reviewer's decision.
- **Not a cloud service.** All data remains on the operator's machine in `~/.sswp_registry.sqlite` and the `.sswp.json` files in each repo.

---

## The Problem

When an AI agent operates on a codebase, four questions haunt every serious reviewer:

1. **What state was the code in when the agent saw it?**
2. **What did the agent change, exactly?**
3. **Did the changes survive disciplined attempts to break them?**
4. **Can any of this be verified later, by someone who wasn't there?**

Existing supply-chain tools answer subsets of this. [Sigstore](https://www.sigstore.dev/) signs releases. [SLSA](https://slsa.dev/) attests build provenance. [in-toto](https://in-toto.io/) attests pipelines. None of them are agent-native, and none of them probe the artifact adversarially before sealing.

SSWP fills that gap.

## What SSWP Does

Every `sswp_witness` call performs four phases atomically against a target repo:

1. **Scan** — capture the full dependency graph (every `node_modules` package with resolved path, integrity hash, and risk score), the build environment (Node version, OS, arch, CI status), and repo metadata (name, commit hash, branch).

2. **Gate-test** — run a 5-gate deterministic pipeline against the codebase:

   | Gate | What it checks | Verdict |
   |------|---------------|---------|
   | `GIT_INTEGRITY` | `git status --porcelain` — working tree clean | PASS if no modified files |
   | `LOCKFILE` | `package-lock.json` exists | INCONCLUSIVE if no `package.json`, FAIL if missing lockfile |
   | `DETERMINISTIC_BUILD` | Detected build command exits 0 | INCONCLUSIVE if no build command detected |
   | `TEST_PASS` | `npm test` exits 0 | PASS / FAIL |
   | `LINT` | eslint → biome → tsc, first to pass wins | INCONCLUSIVE if no linter configured |

3. **Adversarially probe** — three per-package probes run on every dependency:

   | Probe | What it detects | Signal |
   |-------|----------------|--------|
   | `TYPO_SQUATTING` | Name matches known suspicious pattern list | WARN if matched |
   | `VERSION_ANOMALY` | Unpinned version ranges (`*`, `>=`, `^0`, `~0`, `latest`) | WARN on range |
   | `METADATA_INTEGRITY` | Integrity hash present on dep entry | CRITICAL if missing |

   Optional Kimi K2 reasoning (`KIMI_REASONING` probe) deepens the analysis when `OLLAMA_CLOUD_API_KEY` is set. Aggregate `overallRisk` = `(CRITICAL_count × 0.4 + WARN_count × 0.15) / dep_count`, clamped to [0, 1].

4. **Seal** — produces a `.sswp.json` attestation: SHA-256 over the scan, gates, adversarial report, and metadata (sorted keys, signature field excluded from hash). Written to disk and appended to the tamper-proof audit ledger in the SQLite registry.

Verification later is one call: `sswp_verify` recomputes the SHA against the file. If anything was edited after the seal, the hash diverges.

## Example Attestation

<details>
<summary><code>veritas-topography-map.sswp.json</code> — real witness run from April 27, 2026 (click to expand)</summary>

```json
{
  "version": "1.0.0",
  "timestamp": "2026-04-27T11:27:47.606Z",
  "target": {
    "name": "veritas-topography-map",
    "repo": "/mnt/c/Veritas_Lab/veritas-topography-map",
    "commitHash": "85887560bc0feedec78c4cb2524112200ffcd6ca",
    "branch": "master"
  },
  "environment": {
    "nodeVersion": "v22.14.0",
    "os": "linux",
    "arch": "x64",
    "ci": false
  },
  "dependencies": [
    { "name": "@modelcontextprotocol/sdk", "version": "1.29.0",
      "integrity": "7ab20eba8fee70f3", "suspicious": false, "riskScore": 0.1 },
    { "name": "better-sqlite3", "version": "12.9.0",
      "integrity": "9d2524247288858c", "suspicious": false, "riskScore": 0.1 },
    { "name": "esbuild", "version": "0.25.12",
      "integrity": "cb7d5b1fe478f8cb", "suspicious": false, "riskScore": 0.5 }
    // ... 14 more dependencies (17 total)
  ],
  "gates": [
    { "gate": "GIT_INTEGRITY",       "status": "FAIL", "evidence": "Modified files: 468", "durationMs": 1531 },
    { "gate": "LOCKFILE",            "status": "PASS", "evidence": "package-lock.json present", "durationMs": 1 },
    { "gate": "DETERMINISTIC_BUILD", "status": "PASS", "evidence": "Build succeeded: npm run build", "durationMs": 917 },
    { "gate": "TEST_PASS",           "status": "FAIL", "evidence": "Tests failed: Missing script: \"test\"", "durationMs": 149 },
    { "gate": "LINT",                "status": "PASS", "evidence": "npx tsc --noEmit passed", "durationMs": 4129 }
  ],
  "adversarial": {
    "totalPackages": 17,
    "suspiciousPackages": 1,
    "probes": [
      { "package": "@modelcontextprotocol/sdk", "probe": "TYPO_SQUATTING",  "result": "PASS", "detail": "Name heuristic clean" },
      { "package": "esbuild",                   "probe": "TYPO_SQUATTING",  "result": "WARN", "detail": "Name matches known suspicious patterns" },
      { "package": "@modelcontextprotocol/sdk", "probe": "VERSION_ANOMALY", "result": "PASS", "detail": "Pinned: 1.29.0" }
      // ... 48 more probes (51 total)
    ],
    "overallRisk": 0.0235
  },
  "seal": {
    "chainHash": "e8f4a...",
    "sequence": 4
  },
  "signature": "a7b3c91d2f84e6a09c..."
}
```

</details>

---

## Features

### Deterministic Attestation

- **Full repo witness** — scans every dependency in `node_modules`, captures build environment, runs the 5-gate pipeline, performs adversarial probing, and seals the result as a single `.sswp.json` file
- **Self-verifying** — the `signature` field is SHA-256 over the entire sorted payload (excluding signature itself); any edit to the file is detectable with one call to `sswp_verify`
- **Bulk mode** — `sswp_bulk_witness` runs sequentially across multiple repos, auto-saving each to the registry and logging to the ledger

### Supply-Chain Probing

- **Typosquatting detection** — matches package names against a known suspicious pattern list (e.g., `left-pad`, `event-stream`, `colors`, `faker`)
- **Version anomaly scanning** — flags unpinned version ranges (`*`, `>=`, `^0`, `~0`, `latest`) that allow uncontrolled dependency drift
- **Metadata integrity** — CRITICAL on any dependency missing an integrity hash
- **Kimi K2 reasoning** — optional deep analysis when `OLLAMA_CLOUD_API_KEY` is set; returns INCONCLUSIVE without it (not a failure)

### Fleet Registry

- **131 nodes tracked** — every repo witnessed gets a node record in the SQLite registry with type, status, tags, and metadata
- **FTS5 full-text search** — `sswp_node_search "anyio"` returns instant results across all witnessed repos
- **Health dashboard** — `sswp_registry_health` shows every node, last run time, risk score, and adversarial risk in a single view
- **Risk leaderboard** — sortable by VERITAS score; filter by threshold (e.g., "show me every repo below 0.3")
- **Gate trends** — per-node, per-gate history over configurable time windows

### Tamper-Proof Audit Ledger

- **Append-only SHA-256 hash chain** — every witness run generates internal entries (SCAN → GATES → ADVERSARIAL → ATTEST), each linked to its predecessor via `prev_hash`
- **Persistent** — full attestation JSON saved to the SQLite registry; ledger entries queryable via `sswp_ledger`
- **Verifiable** — the registry ledger can be validated end-to-end to confirm no entry has been altered or removed

---

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                    MCP CLIENT                         │
│     (Hermes / Claude Desktop / Cline / Copilot)       │
└───────────────────────┬───────────────────────────────┘
                        │  MCP stdio (JSON-RPC 2.0)
                        ▼
┌───────────────────────────────────────────────────────┐
│                SSWP MCP SERVER                        │
│            src/sswp/mcp/server.ts                     │
│                                                       │
│  ┌──────────────────────────┐  ┌────────────────────┐ │
│  │     WITNESS ENGINE       │  │   FLEET REGISTRY   │ │
│  │                          │  │                    │ │
│  │  1. Scan (dep graph)     │  │  nodes             │ │
│  │  2. Gates (5-gate run)   │  │  attestations      │ │
│  │  3. Probe (3 heuristic   │  │  gates_history     │ │
│  │     + Kimi reasoning)    │  │  ledger (SHA-256)  │ │
│  │  4. Seal → .sswp.json    │  │  dep_snapshots     │ │
│  │                          │  │  FTS5 search       │ │
│  └──────────┬───────────────┘  └─────────┬──────────┘ │
└─────────────│───────────────────────────│─────────────┘
              │                           │
              ▼  .sswp.json file          ▼  SQLite
    ┌──────────────────────┐    ┌──────────────────────┐
    │   <repo>/.sswp.json  │    │  ~/.sswp_registry    │
    │   (self-verifying)   │    │  .sqlite             │
    └──────────────────────┘    └──────────────────────┘
```

---

## Requirements

- **Node.js** v18 or later
- **npm** (installed with Node.js)
- A project with a `package.json` and `node_modules` to witness
- `git` available in PATH (for the `GIT_INTEGRITY` gate and commit hash capture)

---

## Installation

### Prerequisites

Ensure Node.js v18+ and npm are installed:

```bash
node --version  # v18.0.0 or higher
npm --version   # bundled with Node.js
```

### From Source

```bash
git clone https://github.com/VrtxOmega/sswp-mcp.git
cd sswp-mcp
npm install
```

The bundled CJS is pre-built in `dist/` — no TypeScript compilation required.

### Verify

```bash
node dist/sswp-cli.cjs witness --help
# SSWP CLI v2.0.0 — ready
```

---

## Quickstart

```bash
# Clone the repo
git clone https://github.com/VrtxOmega/sswp-mcp.git
cd sswp-mcp

# Install dependencies
npm install

# Witness a repo
npx tsx src/sswp/mcp/server.ts
# (MCP server starts on stdio — ready for client connection)

# Or use the bundled CJS (no TypeScript compilation needed)
node dist/sswp.cjs

# CLI (no MCP required)
node dist/sswp-cli.cjs witness /path/to/your/repo
node dist/sswp-cli.cjs verify /path/to/your/repo/.sswp.json
```

---

## Configuration

### Hermes (`~/.hermes/config.yaml`)

```yaml
mcp:
  servers:
    sswp:
      command: bash
      args:
        - /mnt/c/Veritas_Lab/sswp-mcp/run_mcp.sh
      env:
        OLLAMA_CLOUD_API_KEY: ${OLLAMA_CLOUD_API_KEY}
```

On Windows via WSL, the Hermes gateway spawns MCP servers from the Linux environment. The `run_mcp.sh` wrapper handles directory resolution automatically.

### Claude Desktop / Cline (`cline_mcp_settings.json`)

```json
{
  "mcpServers": {
    "sswp": {
      "command": "node",
      "args": ["C:\\Veritas_Lab\\sswp-mcp\\dist\\sswp-mcp.cjs"],
      "env": {
        "OLLAMA_CLOUD_API_KEY": "your-key-here"
      }
    }
  }
}
```

> **Note:** The `OLLAMA_CLOUD_API_KEY` environment variable is optional. Without it, adversarial probing still runs the three heuristic probes; only the Kimi K2 reasoning probe returns INCONCLUSIVE.

---

## Tools Reference (8 Tools)

| Tool | Description | When to use |
|------|-------------|-------------|
| `sswp_witness` | Full scan, gates, probe, seal → `.sswp.json` | Sealing a single repo before or after agent work |
| `sswp_verify` | SHA-256 signature validation on `.sswp.json` | Confirming an attestation matches current repo state |
| `sswp_bulk_witness` | Sequential witness on multiple repos, auto-save to registry | Nightly fleet audit or pre-release sweep |
| `sswp_check_repo` | Lightweight health check (exists, git, lockfile) | Quick CI gate without full witness overhead |
| `sswp_analyze_deps` | Kimi K2 reasoning on a dependency list | Deep supply-chain analysis on critical dependency trees |
| `sswp_registry_health` | Full fleet health board (all nodes, risk scores) | Dashboard view of ecosystem state |
| `sswp_ledger` | Query the tamper-proof audit ledger | Audit trail review, chain integrity verification |
| `sswp_node_search` | FTS5 search across registry nodes | Finding repos by name, tag, description, or dep name |

---

## CLI

SSWP ships with a standalone CLI that does not require an MCP client:

```bash
# Witness a single repo
node dist/sswp-cli.cjs witness /mnt/c/Veritas_Lab/veritas-topography-map

# Verify an attestation
node dist/sswp-cli.cjs verify /mnt/c/Veritas_Lab/veritas-topography-map/.sswp.json

# Registry operations
node dist/sswp-cli.cjs registry list              # all nodes
node dist/sswp-cli.cjs registry health            # health board
node dist/sswp-cli.cjs registry risky 0.3         # nodes below 0.3 score

# Ledger
node dist/sswp-cli.cjs registry ledger 20         # last 20 entries
node dist/sswp-cli.cjs registry verify-ledger     # chain integrity check
```

---

## How Is This Different From sigstore / SLSA / in-toto?

- **Agent-native.** SSWP is an MCP server first. Hermes, Claude, Cline, or any MCP client can witness a repo without leaving the conversation. Sigstore, SLSA, and in-toto require CI pipeline integration — they don't speak the protocol your agent already uses.

- **Adversarial probing built in.** Every seal includes the result of heuristic probes (typosquatting, version anomaly, metadata integrity) and optional AI-powered reasoning over the dependency tree. Other protocols attest *that something was built* — SSWP attests *what the dependency tree looked like and whether anything in it triggered known risk patterns*.

- **Fleet-aware.** The registry is part of the protocol, not an afterthought. Querying "show me every repo in my ecosystem with a suspicious dependency" is one tool call, not a custom pipeline across disparate tools.

- **Self-verifying artifact.** The `.sswp.json` file carries its own SHA-256 signature. Verification is stateless — give the file to someone who wasn't there, and they can confirm the attestation with one command.

---

## Roadmap

- [ ] Python/Maven/Cargo project support (currently JavaScript/TypeScript)
- [ ] CVE feed integration for typosquatting probe (replace hardcoded heuristic list)
- [ ] Deterministic build hash comparison across two builds
- [ ] Multi-user registry federation
- [ ] GitHub Action for CI-integrated witnessing

---

## Omega Universe

SSWP MCP is one component of the **VERITAS Omega Universe** — a sovereign AI infrastructure stack built on deterministic attestation, cryptographic audit, and operator-declared policy.

| Repo | Role |
|------|------|
| [omega-brain-mcp](https://github.com/VrtxOmega/omega-brain-mcp) | Governance core — 10-gate VERITAS pipeline, Cortex approval gate, S.E.A.L. audit ledger |
| [Gravity-Omega](https://github.com/VrtxOmega/Gravity-Omega) | Desktop operator terminal — Electron + Python agent loop |
| [Ollama-Omega](https://github.com/VrtxOmega/Ollama-Omega) | Ollama → MCP inference bridge (6 tools) |
| [VERITAS-Omega-CODE](https://github.com/VrtxOmega/VERITAS-Omega-CODE) | Deterministic verification spec + dashboard |
| [veritas-vault](https://github.com/VrtxOmega/veritas-vault) | AI knowledge retention engine |
| **sswp-mcp** | Attestation and witness layer (this repo) |

---

## License

[MIT License](./LICENSE)

---

<div align="center">
  <sub>Part of the <a href="https://github.com/VrtxOmega">Omega Universe</a> — sovereign AI infrastructure with built-in trust, provenance, and security.</sub>
</div>
