"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/mcp/server.ts
var server_exports = {};
__export(server_exports, {
  definitions: () => definitions,
  dispatch: () => dispatch,
  start: () => start
});
module.exports = __toCommonJS(server_exports);
var import_server = require("@modelcontextprotocol/sdk/server/index.js");
var import_stdio = require("@modelcontextprotocol/sdk/server/stdio.js");
var import_types = require("@modelcontextprotocol/sdk/types.js");

// src/registry/manager.ts
var import_better_sqlite32 = __toESM(require("better-sqlite3"));

// src/registry/schema.sql
var schema_default = "-- src/sswp/registry/schema.sql\n-- SSWP SQLite Registry Schema \u2014 mirrors Omega Brain tables + SSWP-specific domain\n\nPRAGMA journal_mode = WAL;\nPRAGMA foreign_keys = ON;\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- CORE TABLES\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS nodes (\n    node_id     TEXT PRIMARY KEY,\n    name        TEXT NOT NULL,\n    repo_path   TEXT NOT NULL UNIQUE,\n    node_type   TEXT NOT NULL DEFAULT 'node',   -- node, infrastructure, tool\n    status      TEXT NOT NULL DEFAULT 'active', -- active, deprecated, archived\n    first_seen  TEXT DEFAULT (datetime('now')),\n    last_seen   TEXT DEFAULT (datetime('now')),\n    description TEXT,\n    tags        TEXT, -- JSON array\n    metadata    TEXT  -- JSON blob\n);\n\nCREATE INDEX IF NOT EXISTS idx_nodes_type   ON nodes(node_type);\nCREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- ATTESTATIONS  (one per witness run)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS attestations (\n    attestation_id  TEXT PRIMARY KEY, -- UUID\n    node_id         TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,\n    run_at          TEXT DEFAULT (datetime('now')),\n    overall_status  TEXT NOT NULL,      -- PASS, FAIL, PARTIAL\n    risk_score      REAL DEFAULT 0,     -- 0.0 - 1.0\n    adversarial_risk REAL DEFAULT 0,    -- 0.0 - 1.0\n    gate_pass_count INTEGER DEFAULT 0,\n    gate_fail_count INTEGER DEFAULT 0,\n    sha256          TEXT,\n    sswp_json_path  TEXT,\n    raw_json        TEXT,               -- full .sswp.json blob\n    metadata        TEXT                -- JSON blob\n);\n\nCREATE INDEX IF NOT EXISTS idx_att_node    ON attestations(node_id);\nCREATE INDEX IF NOT EXISTS idx_att_time    ON attestations(run_at);\nCREATE INDEX IF NOT EXISTS idx_att_status  ON attestations(overall_status);\nCREATE INDEX IF NOT EXISTS idx_att_risk    ON attestations(risk_score);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- GATES_HISTORY  (one row per gate per attestation)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS gates_history (\n    id              INTEGER PRIMARY KEY AUTOINCREMENT,\n    attestation_id  TEXT NOT NULL REFERENCES attestations(attestation_id) ON DELETE CASCADE,\n    node_id         TEXT NOT NULL,\n    gate_name       TEXT NOT NULL,      -- INTAKE, TYPE, DEPENDENCY, EVIDENCE, MATH, COST, INCENTIVE, SECURITY, ADVERSARY, TRACE\n    gate_number     INTEGER NOT NULL,   -- 1-10\n    status          TEXT NOT NULL,      -- PASS, FAIL, SKIP, ERROR\n    reason_code     TEXT,\n    detail          TEXT,\n    duration_ms     INTEGER DEFAULT 0\n);\n\nCREATE INDEX IF NOT EXISTS idx_gh_att   ON gates_history(attestation_id);\nCREATE INDEX IF NOT EXISTS idx_gh_node  ON gates_history(node_id);\nCREATE INDEX IF NOT EXISTS idx_gh_gate  ON gates_history(gate_name);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- LEDGER  (append-only SEAL-like audit trail)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS ledger (\n    id          INTEGER PRIMARY KEY AUTOINCREMENT,\n    prev_hash   TEXT,\n    event_type  TEXT NOT NULL,          -- WITNESS, VERIFY, ALERT, SYNC, CRON\n    payload     TEXT NOT NULL,          -- JSON blob\n    hash        TEXT UNIQUE,            -- SHA-256 of (prev_hash + payload + timestamp)\n    timestamp   TEXT DEFAULT (datetime('now'))\n);\n\nCREATE INDEX IF NOT EXISTS idx_ledger_type ON ledger(event_type);\nCREATE INDEX IF NOT EXISTS idx_ledger_time ON ledger(timestamp);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- DEPENDENCY SNAPSHOTS  (what deps looked like at witness time)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS dep_snapshots (\n    id              INTEGER PRIMARY KEY AUTOINCREMENT,\n    attestation_id  TEXT NOT NULL REFERENCES attestations(attestation_id) ON DELETE CASCADE,\n    node_id         TEXT NOT NULL,\n    package_name    TEXT NOT NULL,\n    version         TEXT,\n    resolved        TEXT,\n    integrity       TEXT,\n    suspicious      INTEGER DEFAULT 0,\n    risk_score      REAL DEFAULT 0\n);\n\nCREATE INDEX IF NOT EXISTS idx_ds_att ON dep_snapshots(attestation_id);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- FTS5 FULL-TEXT INDICES (mirrors Omega Brain)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(\n    name, description, tags,\n    tokenize='porter unicode61',\n    content='nodes',\n    content_rowid='rowid'\n);\n\nCREATE VIRTUAL TABLE IF NOT EXISTS attestations_fts USING fts5(\n    raw_json, metadata,\n    tokenize='porter unicode61',\n    content='attestations',\n    content_rowid='rowid'\n);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- TRIGGERS: keep FTS in sync\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TRIGGER IF NOT EXISTS nodes_ai AFTER INSERT ON nodes BEGIN\n    INSERT INTO nodes_fts(rowid, name, description, tags)\n    VALUES (new.rowid, new.name, new.description, new.tags);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS nodes_ad AFTER DELETE ON nodes BEGIN\n    INSERT INTO nodes_fts(nodes_fts, rowid, name, description, tags)\n    VALUES ('delete', old.rowid, old.name, old.description, old.tags);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS nodes_au AFTER UPDATE ON nodes BEGIN\n    INSERT INTO nodes_fts(nodes_fts, rowid, name, description, tags)\n    VALUES ('delete', old.rowid, old.name, old.description, old.tags);\n    INSERT INTO nodes_fts(rowid, name, description, tags)\n    VALUES (new.rowid, new.name, new.description, new.tags);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS attestations_ai AFTER INSERT ON attestations BEGIN\n    INSERT INTO attestations_fts(rowid, raw_json, metadata)\n    VALUES (new.rowid, new.raw_json, new.metadata);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS attestations_ad AFTER DELETE ON attestations BEGIN\n    INSERT INTO attestations_fts(attestations_fts, rowid, raw_json, metadata)\n    VALUES ('delete', old.rowid, old.raw_json, old.metadata);\nEND;\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- VIEWS: convenience dashboards\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE VIEW IF NOT EXISTS v_node_health AS\nSELECT\n    n.node_id,\n    n.name,\n    n.status,\n    COUNT(DISTINCT a.attestation_id) AS total_runs,\n    MAX(a.run_at) AS last_run,\n    a.overall_status AS last_status,\n    a.risk_score AS last_risk,\n    a.adversarial_risk AS last_adversarial\nFROM nodes n\nLEFT JOIN attestations a ON a.node_id = n.node_id\nGROUP BY n.node_id;\n\nCREATE VIEW IF NOT EXISTS v_gate_trend AS\nSELECT\n    node_id,\n    gate_name,\n    run_at,\n    status,\n    COUNT(*) OVER (PARTITION BY node_id, gate_name ORDER BY run_at ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS pass_rate_window\nFROM gates_history gh\nJOIN attestations a ON a.attestation_id = gh.attestation_id;\n\nCREATE VIEW IF NOT EXISTS v_risk_leaderboard AS\nSELECT\n    node_id,\n    name,\n    last_risk,\n    last_adversarial,\n    total_runs,\n    CASE\n        WHEN last_risk > 0.7 THEN 'CRITICAL'\n        WHEN last_risk > 0.4 THEN 'WARNING'\n        ELSE 'OK'\n    END AS risk_band\nFROM v_node_health\nORDER BY last_risk DESC;\n";

// src/core/integrity.ts
var import_node_crypto2 = require("node:crypto");
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");
var import_better_sqlite3 = __toESM(require("better-sqlite3"));
var import_node_os = require("node:os");

// src/core/source-state.ts
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var import_node_child_process = require("node:child_process");
var excluded = /* @__PURE__ */ new Set([".git", "node_modules", ".venv", "__pycache__", ".sswp.json"]);
function gitFiles(root, mode) {
  const args = ["-C", root, "ls-files", mode, "-z"];
  if (mode === "--others") args.push("--exclude-standard");
  args.push("--");
  const result2 = (0, import_node_child_process.spawnSync)("git", args, { env: { ...process.env, LC_ALL: "C" }, timeout: 1e4, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
  if (result2.error) {
    if (result2.error.code === "ENOENT") return null;
    throw Error("Cannot enumerate source inputs: " + result2.error.message);
  }
  if (result2.status !== 0) {
    const error = result2.stderr?.toString("utf8") || "Git source enumeration failed";
    if (error.toLowerCase().includes("not a git repository")) return null;
    throw Error("Cannot enumerate source inputs: " + error);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(result2.stdout).split("\0").filter(Boolean);
}
function sourceFiles(root) {
  root = (0, import_node_fs.realpathSync)(root);
  const tracked = gitFiles(root, "--cached");
  const candidates = /* @__PURE__ */ new Set();
  if (tracked !== null) {
    const other = gitFiles(root, "--others");
    if (other === null) throw Error("Git source enumeration became unavailable");
    for (const name of tracked) candidates.add(name);
    for (const name of other) if (!name.split("/").some((part) => excluded.has(part))) candidates.add(name);
  } else {
    const walk = (folder) => {
      for (const name of (0, import_node_fs.readdirSync)(folder)) {
        if (excluded.has(name)) continue;
        const path = (0, import_node_path.join)(folder, name), stat = (0, import_node_fs.lstatSync)(path);
        if (stat.isSymbolicLink()) throw Error("Source symlinks require an explicit packaged source snapshot");
        if (stat.isDirectory()) walk(path);
        else if (stat.isFile()) candidates.add((0, import_node_path.relative)(root, path).replaceAll("\\", "/"));
      }
    };
    walk(root);
  }
  const result2 = [];
  for (const name of [...candidates].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
    const parts = name.split("/");
    if ((0, import_node_path.isAbsolute)(name) || parts.includes("..")) throw Error("Source path escapes the approved root");
    let path = root, missing = false;
    for (const part of parts) {
      path = (0, import_node_path.join)(path, part);
      try {
        if ((0, import_node_fs.lstatSync)(path).isSymbolicLink()) throw Error("Source symlinks require an explicit packaged source snapshot");
      } catch (error) {
        if (["ENOENT", "ENOTDIR"].includes(error.code || "")) {
          missing = true;
          break;
        }
        throw error;
      }
    }
    if (missing) continue;
    const stat = (0, import_node_fs.lstatSync)(path);
    if (stat.isFile()) result2.push(name);
    else if (stat.isDirectory()) throw Error("Tracked directories/submodules require an explicit packaged source snapshot");
    else throw Error("Unsupported source file type");
  }
  return result2;
}
function sourceIdentity(root) {
  const hash = (0, import_node_crypto.createHash)("sha256");
  for (const name of sourceFiles(root)) hash.update(name + "\0" + (0, import_node_crypto.createHash)("sha256").update((0, import_node_fs.readFileSync)((0, import_node_path.join)(root, name))).digest("hex") + "\n");
  return hash.digest("hex");
}
function copySources(root, dest) {
  for (const name of sourceFiles(root)) {
    const target = (0, import_node_path.join)(dest, name);
    (0, import_node_fs.mkdirSync)((0, import_node_path.dirname)(target), { recursive: true });
    (0, import_node_fs.copyFileSync)((0, import_node_path.join)(root, name), target);
  }
}

// src/core/integrity.ts
function canonical(v) {
  if (v === null || typeof v !== "object") {
    const s = JSON.stringify(v);
    if (s === void 0 || typeof v === "number" && !Number.isFinite(v)) throw Error("Non-JSON value");
    return s;
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
var sha = (s) => (0, import_node_crypto2.createHash)("sha256").update(s).digest("hex");
function initLedger(db) {
  db.exec("CREATE TABLE IF NOT EXISTS ledger_v2(id INTEGER PRIMARY KEY,prev_hash TEXT NOT NULL,event_json TEXT NOT NULL,hash TEXT NOT NULL UNIQUE)");
}
function row(db, type, payload, taskId) {
  const last = db.prepare("SELECT id,hash FROM ledger_v2 ORDER BY id DESC LIMIT 1").get();
  const sequence = last ? last.id + 1 : 1, prev = last?.hash ?? "GENESIS_V2";
  const event = canonical({ version: 2, sequence, task_id: taskId, event_type: type, payload, timestamp: (/* @__PURE__ */ new Date()).toISOString() });
  const hash = sha(prev + "\n" + event);
  db.prepare("INSERT INTO ledger_v2 VALUES(?,?,?,?)").run(sequence, prev, event, hash);
  return hash;
}
function appendLedger(db, type, payload, taskId = "system") {
  initLedger(db);
  return db.transaction(() => {
    if (verifyLedger(db).invalid_rows.length) throw Error("Existing v2 ledger is invalid; append refused");
    if (!db.prepare("SELECT 1 FROM ledger_v2 LIMIT 1").get()) {
      const digest = (0, import_node_crypto2.createHash)("sha256");
      let count = 0;
      if (db.prepare("SELECT 1 FROM sqlite_master WHERE name='ledger'").get()) for (const r of db.prepare("SELECT * FROM ledger ORDER BY id").iterate()) {
        digest.update(canonical(r) + "\n");
        count++;
      }
      row(db, "LEGACY_BOUNDARY", { legacy_rows: count, legacy_logical_sha256: digest.digest("hex"), legacy_status: "preserved_unverified", format: "v2" }, "system");
    }
    return row(db, type, payload, taskId);
  }).immediate();
}
function verifyLedger(db) {
  initLedger(db);
  let prev = "GENESIS_V2", count = 0;
  const invalid = [];
  for (const r of db.prepare("SELECT * FROM ledger_v2 ORDER BY id").iterate()) {
    count++;
    let structural = false;
    try {
      const e = JSON.parse(r.event_json);
      structural = e.version === 2 && e.sequence === r.id && canonical(e) === r.event_json;
    } catch {
    }
    if (!structural || r.id !== count || r.prev_hash !== prev || sha(r.prev_hash + "\n" + r.event_json) !== r.hash) invalid.push(r.id);
    prev = r.hash;
  }
  return { format: 2, rows: count, valid: count > 0 && invalid.length === 0, invalid_rows: invalid, head: prev, legacy_status: "preserved_unverified", guarantee: "local tamper-evident chain; no independent external anchor" };
}
var sharedPath = () => process.env.VERITAS_SHARED_DIR || (0, import_node_path2.join)((0, import_node_os.homedir)(), ".veritas-shared");
function consumeApproval(tool, args, receipt, taskId) {
  if (!taskId || !receipt?.payload || !receipt.mac) throw Error("A task-bound operator-policy approval receipt is required");
  const shared = sharedPath(), policyBytes = (0, import_node_fs2.readFileSync)((0, import_node_path2.join)(shared, "operator-policy.json")), policy = JSON.parse(policyBytes.toString());
  const real = (0, import_node_fs2.realpathSync)(args.repoPath).replaceAll("\\", "/");
  const pathkey = (p2) => process.platform === "win32" ? p2.toLowerCase() : p2;
  const allowed = (policy.witness_roots || []).flatMap((p2) => {
    try {
      return [pathkey((0, import_node_fs2.realpathSync)(p2).replaceAll("\\", "/"))];
    } catch (error) {
      if (["ENOENT", "ENOTDIR", "EACCES", "EPERM"].includes(error.code || "")) return [];
      throw error;
    }
  });
  if (!allowed.includes(pathkey(real))) throw Error("Project is not registered in operator policy");
  const key = (0, import_node_fs2.readFileSync)((0, import_node_path2.join)(shared, "approval.key")), expected = (0, import_node_crypto2.createHmac)("sha256", key).update(canonical(receipt.payload)).digest();
  const actual = Buffer.from(receipt.mac, "hex");
  if (actual.length !== expected.length || !(0, import_node_crypto2.timingSafeEqual)(actual, expected)) throw Error("Invalid approval MAC");
  const p = receipt.payload;
  if (p.version !== 1 || p.tool !== tool || p.task_id !== taskId || p.args_sha256 !== sha(canonical(args)) || p.policy_sha256 !== sha(policyBytes.toString()) || p.expires < Math.floor(Date.now() / 1e3) || p.expires > Math.floor(Date.now() / 1e3) + 180) throw Error("Approval is stale or bound to different arguments/task/policy");
  if (p.source_sha256 !== sourceIdentity(real)) throw Error("Source changed since approval; request a fresh receipt");
  const db = new import_better_sqlite3.default((0, import_node_path2.join)(shared, "coordination.sqlite"));
  db.pragma("busy_timeout=30000");
  try {
    db.exec("CREATE TABLE IF NOT EXISTS used_approvals(nonce TEXT PRIMARY KEY,used_at TEXT NOT NULL)");
    db.prepare("INSERT INTO used_approvals VALUES(?,?)").run(p.nonce, (/* @__PURE__ */ new Date()).toISOString());
  } finally {
    db.close();
  }
  return policy;
}
function deliverOutbox(db) {
  const shared = sharedPath();
  (0, import_node_fs2.mkdirSync)(shared, { recursive: true });
  const bus = new import_better_sqlite3.default((0, import_node_path2.join)(shared, "coordination.sqlite"));
  bus.pragma("busy_timeout=30000");
  try {
    bus.exec("CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,event_type TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL)");
    const present = new Set(bus.prepare("SELECT id FROM events").all().map((e) => e.id));
    for (const e of db.prepare("SELECT * FROM event_outbox ORDER BY created_at").all()) {
      if (e.delivered && present.has(e.id)) continue;
      bus.prepare("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?)").run(e.id, e.task_id, e.event_type, e.payload, e.created_at);
      db.prepare("UPDATE event_outbox SET delivered=1 WHERE id=?").run(e.id);
    }
  } finally {
    bus.close();
  }
}

// src/registry/manager.ts
var import_node_crypto3 = require("node:crypto");
var import_node_fs3 = require("node:fs");
var import_node_path3 = require("node:path");
var SCHEMA_PATH = (0, import_node_path3.resolve)(process.cwd(), "src/sswp/registry/schema.sql");
var DEFAULT_DB = process.env.SSWP_DB || (0, import_node_path3.resolve)(require("node:os").homedir(), ".sswp_registry.sqlite");
var RegistryManager = class {
  db;
  dbPath;
  constructor(cfg = {}) {
    this.dbPath = cfg.dbPath ?? DEFAULT_DB;
    const dir = (0, import_node_path3.dirname)(this.dbPath);
    if (!(0, import_node_fs3.existsSync)(dir)) (0, import_node_fs3.mkdirSync)(dir, { recursive: true });
    this.db = new import_better_sqlite32.default(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    if (cfg.autoInit !== false) this.initSchema();
  }
  initSchema() {
    const sql = schema_default;
    this.db.exec(sql);
    this.db.pragma("busy_timeout=30000");
    this.db.exec("CREATE TABLE IF NOT EXISTS event_outbox(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,event_type TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL,delivered INTEGER DEFAULT 0)");
    initLedger(this.db);
    if (!this.db.prepare("SELECT 1 FROM ledger_v2 LIMIT 1").get()) appendLedger(this.db, "MIGRATION_READY", { version: 2 });
  }
  close() {
    this.db.close();
  }
  // ═══════════════════════════════════════════════════════════════
  // NODES
  // ═══════════════════════════════════════════════════════════════
  upsertNode(node) {
    const id = node.node_id ?? this.getNodeByPath(node.repo_path)?.node_id ?? (0, import_node_crypto3.randomUUID)();
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const tagsJson = node.tags ? JSON.stringify(node.tags) : null;
    const metaJson = node.metadata ? JSON.stringify(node.metadata) : null;
    const stmt = this.db.prepare(`
      INSERT INTO nodes (node_id, name, repo_path, node_type, status, first_seen, last_seen, description, tags, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(node_id) DO UPDATE SET
        name=excluded.name,
        repo_path=excluded.repo_path,
        node_type=excluded.node_type,
        status=excluded.status,
        last_seen=excluded.last_seen,
        description=excluded.description,
        tags=excluded.tags,
        metadata=excluded.metadata
      RETURNING *
    `);
    const row2 = stmt.get(
      id,
      node.name,
      node.repo_path,
      node.node_type ?? "node",
      node.status ?? "active",
      now,
      now,
      node.description ?? null,
      tagsJson,
      metaJson
    );
    return this.deserializeNode(row2);
  }
  getNode(nodeId) {
    const stmt = this.db.prepare("SELECT * FROM nodes WHERE node_id = ?");
    const row2 = stmt.get(nodeId);
    if (!row2) return void 0;
    return this.deserializeNode(row2);
  }
  getNodeByPath(repoPath) {
    const stmt = this.db.prepare("SELECT * FROM nodes WHERE repo_path = ?");
    const row2 = stmt.get(repoPath);
    if (!row2) return void 0;
    return this.deserializeNode(row2);
  }
  listNodes(opts) {
    let sql = "SELECT * FROM nodes WHERE 1=1";
    const params = [];
    if (opts?.type) {
      sql += " AND node_type = ?";
      params.push(opts.type);
    }
    if (opts?.status) {
      sql += " AND status = ?";
      params.push(opts.status);
    }
    sql += " ORDER BY last_seen DESC";
    if (opts?.limit) {
      sql += " LIMIT ?";
      params.push(opts.limit);
    }
    if (opts?.offset) {
      sql += " OFFSET ?";
      params.push(opts.offset);
    }
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params);
    return rows.map((r) => this.deserializeNode(r));
  }
  searchNodes(query, limit2 = 20) {
    const stmt = this.db.prepare(`
      SELECT n.* FROM nodes n
      JOIN nodes_fts f ON n.rowid = f.rowid
      WHERE nodes_fts MATCH ?
      ORDER BY rank
      LIMIT ?
    `);
    const rows = stmt.all(query, limit2);
    return rows.map((r) => this.deserializeNode(r));
  }
  deserializeNode(row2) {
    return {
      node_id: String(row2.node_id),
      name: String(row2.name),
      repo_path: String(row2.repo_path),
      node_type: String(row2.node_type),
      status: String(row2.status),
      first_seen: String(row2.first_seen),
      last_seen: String(row2.last_seen),
      description: row2.description ? String(row2.description) : void 0,
      tags: row2.tags ? JSON.parse(String(row2.tags)) : void 0,
      metadata: row2.metadata ? JSON.parse(String(row2.metadata)) : void 0
    };
  }
  // ═══════════════════════════════════════════════════════════════
  // ATTESTATIONS
  // ═══════════════════════════════════════════════════════════════
  saveAttestation(nodeId, att, jsonPath, rawJson) {
    const id = att.id ?? (0, import_node_crypto3.randomUUID)();
    return this.db.transaction(() => {
      const passCount = att.gates.filter((g) => g.status === "PASS").length;
      const failCount = att.gates.filter((g) => g.status === "FAIL" || g.status === "ERROR").length;
      const overall = att.gates.some((g) => g.status === "ERROR") ? "ERROR" : failCount ? "FAIL" : att.gates.some((g) => g.status === "INCONCLUSIVE") ? "INCONCLUSIVE" : passCount ? "PASS" : "NOT_APPLICABLE";
      const row2 = this.db.prepare("INSERT INTO attestations(attestation_id,node_id,run_at,overall_status,risk_score,adversarial_risk,gate_pass_count,gate_fail_count,sha256,sswp_json_path,raw_json,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *").get(id, nodeId, att.timestamp, overall, att.adversarial?.overallRisk ?? 0, att.adversarial?.overallRisk ?? 0, passCount, failCount, (0, import_node_crypto3.createHash)("sha256").update(rawJson).digest("hex"), jsonPath, rawJson, JSON.stringify({ version: 2, materialization: "pending", assessment: "risk scores are not safety probabilities" }));
      for (const g of att.gates) this.saveGateHistory(id, nodeId, g);
      for (const d of att.dependencies) this.saveDepSnapshot(id, nodeId, d);
      const taskId = att.taskId;
      if (!taskId) throw Error("taskId required");
      const payload = { attestation_id: id, node_id: nodeId, signature: att.signature, overall, repo: att.target.repo };
      appendLedger(this.db, "WITNESS", payload, taskId);
      this.db.prepare("INSERT INTO event_outbox(id,task_id,event_type,payload,created_at) VALUES(?,?,?,?,?)").run("sswp:" + id, taskId, "SSWP_ATTESTATION", canonical(payload), (/* @__PURE__ */ new Date()).toISOString());
      return row2;
    }).immediate();
  }
  saveGateHistory(attId, nodeId, g) {
    const stmt = this.db.prepare(`
      INSERT INTO gates_history (attestation_id, node_id, gate_name, gate_number, status, reason_code, detail, duration_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(attId, nodeId, g.gate, 0, g.status, g.evidence ?? null, null, g.durationMs ?? 0);
  }
  getLatestAttestation(nodeId) {
    const stmt = this.db.prepare("SELECT * FROM attestations WHERE node_id = ? ORDER BY run_at DESC LIMIT 1");
    return stmt.get(nodeId);
  }
  getAttestationHistory(nodeId, limit2 = 50) {
    const stmt = this.db.prepare("SELECT * FROM attestations WHERE node_id = ? ORDER BY run_at DESC LIMIT ?");
    return stmt.all(nodeId, limit2);
  }
  getAttestationGates(attestationId) {
    const stmt = this.db.prepare("SELECT * FROM gates_history WHERE attestation_id = ? ORDER BY gate_number");
    return stmt.all(attestationId);
  }
  // ═══════════════════════════════════════════════════════════════
  // DEPENDENCY SNAPSHOTS
  // ═══════════════════════════════════════════════════════════════
  saveDepSnapshot(attId, nodeId, dep) {
    const stmt = this.db.prepare(`
      INSERT INTO dep_snapshots (attestation_id, node_id, package_name, version, resolved, integrity, suspicious, risk_score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      attId,
      nodeId,
      dep.name,
      dep.version ?? null,
      dep.resolved ?? null,
      dep.integrity ?? null,
      dep.suspicious ? 1 : 0,
      dep.riskScore ?? 0
    );
  }
  getDepSnapshots(attestationId) {
    const stmt = this.db.prepare("SELECT * FROM dep_snapshots WHERE attestation_id = ?");
    return stmt.all(attestationId);
  }
  // ═══════════════════════════════════════════════════════════════
  // LEDGER
  // ═══════════════════════════════════════════════════════════════
  appendLedger(eventType, payload) {
    appendLedger(this.db, eventType, payload, String(payload.task_id || "system"));
  }
  getLedger(limit2 = 100) {
    return this.db.prepare("SELECT * FROM ledger_v2 ORDER BY id DESC LIMIT ?").all(Math.max(1, Math.min(limit2, 100)));
  }
  verifyLedger() {
    return verifyLedger(this.db);
  }
  flushEvents() {
    deliverOutbox(this.db);
  }
  // ═══════════════════════════════════════════════════════════════
  // DASHBOARD VIEWS
  // ═══════════════════════════════════════════════════════════════
  getHealthBoard() {
    return this.db.prepare("WITH ranked AS (SELECT a.*,ROW_NUMBER() OVER(PARTITION BY node_id ORDER BY run_at DESC,attestation_id DESC) rn FROM attestations a) SELECT n.name,n.repo_path,n.status,r.overall_status,r.run_at,r.risk_score FROM nodes n LEFT JOIN ranked r ON r.node_id=n.node_id AND r.rn=1 ORDER BY r.run_at DESC").all().map((r) => ({ ...r, localPathExists: (0, import_node_fs3.existsSync)(r.repo_path), evidenceScope: "historical; check timestamp and source revision before reuse" }));
  }
  getRiskLeaderboard() {
    return this.db.prepare("SELECT * FROM v_risk_leaderboard").all();
  }
  getGateTrend(nodeId, gateName, windowDays = 30) {
    const sql = `SELECT * FROM v_gate_trend WHERE node_id = ? AND run_at > datetime('now', '-${windowDays} days')` + (gateName ? " AND gate_name = ?" : "") + " ORDER BY run_at DESC";
    const stmt = this.db.prepare(sql);
    return gateName ? stmt.all(nodeId, gateName) : stmt.all(nodeId);
  }
  // ═══════════════════════════════════════════════════════════════
  // BULK SEED FROM FILESYSTEM
  // ═══════════════════════════════════════════════════════════════
  syncFromDisk(nodesJsonPath) {
    const nodes = JSON.parse((0, import_node_fs3.readFileSync)(nodesJsonPath, "utf-8"));
    let inserted = 0, updated = 0;
    const errors = [];
    this.db.prepare("BEGIN TRANSACTION").run();
    try {
      for (const n of nodes) {
        try {
          const existing = this.getNodeByPath(n.path);
          this.upsertNode({
            node_id: existing?.node_id,
            name: n.name,
            repo_path: n.path,
            node_type: n.type ?? "node",
            tags: n.tags,
            description: n.description
          });
          existing ? updated++ : inserted++;
        } catch (e) {
          errors.push(`${n.name}: ${e.message}`);
        }
      }
      this.db.prepare("COMMIT").run();
    } catch (e) {
      this.db.prepare("ROLLBACK").run();
      throw e;
    }
    return { inserted, updated, errors };
  }
  // ═══════════════════════════════════════════════════════════════
  // OMEGA BRAIN BRIDGE
  // ═══════════════════════════════════════════════════════════════
  exportToOmegaBrain(opts) {
    let sql = `
      SELECT a.attestation_id, n.name, a.overall_status, a.risk_score, a.run_at, a.raw_json
      FROM attestations a
      JOIN nodes n ON n.node_id = a.node_id
      WHERE 1=1
    `;
    const params = [];
    if (opts?.since) {
      sql += " AND a.run_at > ?";
      params.push(opts.since);
    }
    if (opts?.limit) {
      sql += " LIMIT ?";
      params.push(opts.limit);
    }
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params);
    return rows.map((r) => ({
      fragment_id: `sswp-att-${r.attestation_id}`,
      content: `[SSWP ATTESTATION] ${r.name}
Status: ${r.overall_status}
Risk: ${(r.risk_score * 100).toFixed(1)}%
Run: ${r.run_at}`,
      tier: r.overall_status === "PASS" ? "B" : "C"
    }));
  }
};

// src/core/witness.ts
var import_node_fs5 = require("node:fs");
var import_node_path5 = require("node:path");
var import_node_crypto5 = require("node:crypto");

// src/core/gate-runner.ts
var import_node_child_process2 = require("node:child_process");
var import_node_fs4 = require("node:fs");
var import_node_path4 = require("node:path");
var import_node_os2 = require("node:os");
var import_node_crypto4 = require("node:crypto");
async function runCommand(command, args, cwd, timeout = 6e4, env = {}) {
  return new Promise((resolve5) => {
    const child = (0, import_node_child_process2.spawn)(command, args, { cwd, shell: false, windowsHide: true, detached: process.platform !== "win32", env: { ...process.env, ...env } });
    let stdout = "", stderr = "", settled = false, timedOut = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve5(value);
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === "win32" && child.pid) {
        const killer = (0, import_node_child_process2.spawn)("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true });
        killer.on("error", () => child.kill());
      } else if (child.pid) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          child.kill("SIGKILL");
        }
      }
    }, Math.max(50, Math.min(timeout, 3e5)));
    child.stdout?.on("data", (d) => {
      stdout = (stdout + d).slice(-65536);
    });
    child.stderr?.on("data", (d) => {
      stderr = (stderr + d).slice(-65536);
    });
    child.on("error", (e) => finish({ status: null, stdout, stderr, error: e.message }));
    child.on("close", (status) => finish({ status, stdout, stderr, ...timedOut ? { error: "TIMEOUT" } : {} }));
  });
}
var result = (gate, status, evidence, durationMs = 0) => ({ gate, status, evidence, durationMs });
async function gitIntegrityGate(root) {
  const start2 = Date.now();
  const r = await runCommand("git", ["status", "--porcelain=v1", "--untracked-files=all"], root, 1e4);
  if (r.error || r.status !== 0) return result("GIT_INTEGRITY", "ERROR", r.error || r.stderr || `git exit ${r.status}`, Date.now() - start2);
  return result("GIT_INTEGRITY", r.stdout.trim() ? "FAIL" : "PASS", r.stdout.trim() ? "Working tree has changes" : "Git command succeeded; working tree clean", Date.now() - start2);
}
function lockfileGate(root) {
  if (!(0, import_node_fs4.existsSync)((0, import_node_path4.join)(root, "package.json"))) {
    const locks2 = ["uv.lock", "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum"].filter((f) => (0, import_node_fs4.existsSync)((0, import_node_path4.join)(root, f)));
    return result("LOCKFILE_PRESENT", locks2.length ? "PASS" : "NOT_APPLICABLE", locks2.length ? `${locks2.join(", ")} present; content consistency not established` : "No supported lockfile ecosystem detected");
  }
  const locks = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"].filter((f) => (0, import_node_fs4.existsSync)((0, import_node_path4.join)(root, f)));
  return result("LOCKFILE_PRESENT", locks.length === 1 ? "PASS" : locks.length ? "INCONCLUSIVE" : "FAIL", locks.length === 1 ? `${locks[0]} present; consistency not established` : locks.length ? "Multiple lockfiles; package manager selection required" : "No lockfile");
}
async function runGates(root, _env, policy = {}) {
  const output = [await gitIntegrityGate(root), lockfileGate(root)];
  const profile = policy.projects?.[(0, import_node_fs4.realpathSync)(root).replaceAll("\\", "/")] || {};
  for (const [gate, key] of [["BUILD_SUCCESS", "build"], ["TEST_PASS", "test"], ["LINT", "lint"]]) {
    const command = profile[key];
    if (!command) {
      output.push(result(gate, "INCONCLUSIVE", "No explicit operator command configured"));
      continue;
    }
    if (!Array.isArray(command.argv) || !command.argv.length || command.argv.some((a) => typeof a !== "string")) {
      output.push(result(gate, "ERROR", "Invalid operator command"));
      continue;
    }
    const start2 = Date.now();
    const r = await runCommand(command.argv[0], command.argv.slice(1), root, command.timeoutMs || 6e4);
    output.push(result(gate, r.error ? "ERROR" : r.status === 0 ? "PASS" : "FAIL", r.error || `exit=${r.status}; ${(r.stdout + "\n" + r.stderr).slice(-8e3)}`, Date.now() - start2));
  }
  output.push(await reproducibleBuildGate(root, profile.reproducible));
  return output;
}
function outputManifest(root, outputs) {
  const manifest = {};
  const walk = (p) => {
    const stat = (0, import_node_fs4.lstatSync)(p);
    if (stat.isSymbolicLink()) throw Error("Output symlinks are not supported");
    if (stat.isDirectory()) {
      for (const name of (0, import_node_fs4.readdirSync)(p).sort()) walk((0, import_node_path4.join)(p, name));
    } else if (stat.isFile()) manifest[(0, import_node_path4.relative)(root, p).replaceAll("\\", "/")] = (0, import_node_crypto4.createHash)("sha256").update((0, import_node_fs4.readFileSync)(p)).digest("hex");
  };
  for (const output of outputs) {
    const target = (0, import_node_path4.resolve)(root, output);
    if ((0, import_node_path4.isAbsolute)(output) || !target.startsWith((0, import_node_path4.resolve)(root) + import_node_path4.sep)) throw Error("Output must be inside build directory");
    walk(target);
  }
  return Object.fromEntries(Object.entries(manifest).sort(([a], [b]) => a.localeCompare(b)));
}
async function reproducibleBuildGate(root, profile) {
  if (!profile) return result("REPRODUCIBLE_BUILD", "INCONCLUSIVE", "No independent-build profile configured");
  if (!Array.isArray(profile.outputs) || !profile.outputs.length || !Array.isArray(profile.argv) || !profile.argv.length) return result("REPRODUCIBLE_BUILD", "ERROR", "Explicit argv and output paths are required");
  const start2 = Date.now(), base = (0, import_node_fs4.mkdtempSync)((0, import_node_path4.join)((0, import_node_os2.tmpdir)(), "sswp-repeat-")), manifests = [];
  try {
    const source = sourceIdentity(root);
    for (let i = 0; i < 2; i++) {
      const dest = (0, import_node_path4.join)(base, String(i));
      (0, import_node_fs4.mkdirSync)(dest);
      copySources(root, dest);
      for (const out of profile.outputs) {
        const target = (0, import_node_path4.resolve)(dest, out);
        if (typeof out !== "string" || (0, import_node_path4.isAbsolute)(out) || !target.startsWith((0, import_node_path4.resolve)(dest) + import_node_path4.sep)) throw Error("Output escapes isolated build");
        if ((0, import_node_fs4.existsSync)(target)) (0, import_node_fs4.rmSync)(target, { recursive: true, force: true });
      }
      const commands = [...profile.setup || [], { argv: profile.argv, timeoutMs: profile.timeoutMs }];
      for (const command of commands) {
        if (!Array.isArray(command.argv) || !command.argv.length || command.argv.some((x) => typeof x !== "string")) throw Error("Invalid independent-build command");
        const run = await runCommand(command.argv[0], command.argv.slice(1), dest, command.timeoutMs || 6e4, { TZ: "UTC", SOURCE_DATE_EPOCH: "0", ...profile.env || {} });
        if (run.error || run.status !== 0) return result("REPRODUCIBLE_BUILD", run.error ? "ERROR" : "FAIL", `Independent build ${i + 1}: ${run.error || run.stderr || run.stdout || run.status}`, Date.now() - start2);
      }
      const manifest = outputManifest(dest, profile.outputs);
      if (!Object.keys(manifest).length) throw Error("No output files produced");
      manifests.push(manifest);
    }
    if (sourceIdentity(root) !== source) return result("REPRODUCIBLE_BUILD", "ERROR", "Source changed while independent builds ran", Date.now() - start2);
    const match = JSON.stringify(manifests[0]) === JSON.stringify(manifests[1]);
    return result("REPRODUCIBLE_BUILD", match ? "PASS" : "FAIL", JSON.stringify({ source_sha256: source, matching: match, manifests, scope: "Two separate source copies on this host with explicit commands; not a hermetic environment or cross-host proof" }), Date.now() - start2);
  } catch (e) {
    return result("REPRODUCIBLE_BUILD", "ERROR", String(e), Date.now() - start2);
  } finally {
    const safe = (0, import_node_fs4.realpathSync)(base);
    if (safe.startsWith((0, import_node_fs4.realpathSync)((0, import_node_os2.tmpdir)()) + import_node_path4.sep) && safe.includes("sswp-repeat-")) (0, import_node_fs4.rmSync)(safe, { recursive: true, force: true });
  }
}

// src/core/witness.ts
var import_yaml = require("yaml");
function dependencyInventory(root) {
  const lock = (0, import_node_path5.join)(root, "package-lock.json");
  if (!(0, import_node_fs5.existsSync)(lock)) {
    const pnpm = (0, import_node_path5.join)(root, "pnpm-lock.yaml");
    if ((0, import_node_fs5.existsSync)(pnpm)) {
      const data2 = (0, import_yaml.parse)((0, import_node_fs5.readFileSync)(pnpm, "utf8")), entries2 = [];
      for (const [key, value] of Object.entries(data2.packages || {})) {
        const p = value, at = key.lastIndexOf("@");
        entries2.push({ name: at > 0 ? key.slice(0, at) : key, version: at > 0 ? key.slice(at + 1) : "unknown", resolved: p.resolution?.tarball || key, integrity: p.resolution?.integrity || null, suspicious: !p.resolution?.integrity, riskScore: 0 });
      }
      return { entries: entries2, scope: "pnpm lock package entries including transitive packages; declared integrity, not independently verified installed bytes" };
    }
    return { entries: [], scope: "No supported npm/pnpm lockfile; dependency coverage unverified" };
  }
  const data = JSON.parse((0, import_node_fs5.readFileSync)(lock, "utf8"));
  const entries = [];
  for (const [location, value] of Object.entries(data.packages || {})) {
    if (!location) continue;
    const p = value;
    entries.push({ name: p.name || location.split("node_modules/").pop() || location, version: p.version || "unknown", resolved: p.resolved || location, integrity: p.integrity || null, suspicious: !p.integrity && !p.link, riskScore: 0 });
  }
  return { entries, scope: "npm lockfile package entries; integrity fields are declared metadata, not independently verified installed bytes" };
}
async function witness(root, policy = {}, taskId = "unscoped") {
  root = (0, import_node_fs5.realpathSync)(root);
  const inventory = dependencyInventory(root);
  const sourceBefore = sourceIdentity(root);
  const env = { cwd: root, nodeVersion: process.version, os: process.platform, arch: process.arch, ci: !!process.env.CI, buildCommand: "operator-profile", buildOutput: "" };
  const before = await runCommand("git", ["rev-parse", "HEAD"], root, 1e4);
  const gates = await runGates(root, env, policy);
  const after = await runCommand("git", ["rev-parse", "HEAD"], root, 1e4);
  const sourceAfter = sourceIdentity(root);
  if (sourceBefore !== sourceAfter) gates.push({ gate: "SOURCE_BYTES", status: "FAIL", evidence: "Source bytes changed while checks ran", durationMs: 0 });
  if (before.status !== 0 || after.status !== 0 || before.stdout !== after.stdout) gates.push({ gate: "SOURCE_REVISION", "status": "ERROR", evidence: "Cannot establish one stable Git revision across the checks", durationMs: 0 });
  const att = { id: (0, import_node_crypto5.randomUUID)(), version: "2.1.0", signatureAlgorithm: "sha256-canonical-json-v2", timestamp: (/* @__PURE__ */ new Date()).toISOString(), taskId, target: { name: (0, import_node_path5.basename)(root), repo: root, commitHash: before.status === 0 ? before.stdout.trim() : "unknown", branch: "recorded-by-commit" }, environment: { nodeVersion: env.nodeVersion, os: env.os, arch: env.arch, ci: env.ci }, dependencies: inventory.entries, dependencyCoverage: inventory.scope, gates, adversarial: { totalPackages: inventory.entries.length, suspiciousPackages: inventory.entries.filter((d) => d.suspicious).length, probes: [], overallRisk: 0, assessment: "NOT_PERFORMED; zero is not a safety probability" }, seal: { chainHash: "assigned-by-persistent-registry", sequence: 0 } };
  att.source = { before: sourceBefore, after: sourceAfter, scope: "Source tree; installed dependencies and runtime are host-trusted" };
  att.adversarial.probes = inventory.entries.map((d) => ({ package: d.name, probe: "LOCK_METADATA", result: !d.integrity ? "INCONCLUSIVE" : "PASS", detail: !d.integrity ? "No integrity declaration" : "Integrity declaration present; installed bytes and vulnerabilities not checked" }));
  att.adversarial.assessment = "Local metadata probes only; no adversarial execution or vulnerability feed consulted";
  att.signature = sha(canonical(att));
  return att;
}
function verifyAttestation(filePath) {
  const att = JSON.parse((0, import_node_fs5.readFileSync)(filePath, "utf8"));
  if (att.signatureAlgorithm !== "sha256-canonical-json-v2") return false;
  const { signature, ...payload } = att;
  return typeof signature === "string" && sha(canonical(payload)) === signature;
}

// src/mcp/server.ts
var import_node_fs6 = require("node:fs");
var import_node_path6 = require("node:path");
var import_node_crypto6 = require("node:crypto");
var import_ajv = __toESM(require("ajv"));
var REG = new RegistryManager({ autoInit: true });
var input = (properties, required = []) => ({ type: "object", properties, required, additionalProperties: false });
var str = { type: "string", minLength: 1 };
var limit = { type: "integer", minimum: 1, maximum: 100, default: 20 };
var action = { repoPath: str, task_id: str, approval: { type: "object" } };
var definitions = [
  { name: "sswp_witness", description: "Run explicitly configured checks within an operator-approved project. Requires a task-bound, one-use receipt from omega_authorize_action. Missing evidence is INCONCLUSIVE; a successful build does not prove reproducibility.", inputSchema: input(action, ["repoPath", "task_id", "approval"]) },
  { name: "sswp_bulk_witness", description: "Run individually approved witness actions. Each item requires its own one-use approval receipt.", inputSchema: input({ items: { type: "array", minItems: 1, maxItems: 20, items: input(action, ["repoPath", "task_id", "approval"]) } }, ["items"]) },
  { name: "sswp_verify", description: "Check all nested fields of a v2 attestation against its content hash. Legacy formats are unverified. A matching hash establishes internal consistency, not authorship or truth.", inputSchema: input({ filePath: str }, ["filePath"]) },
  { name: "sswp_check_repo", description: "Read-only Git execution and lockfile-presence checks; no project build scripts run.", inputSchema: input({ repoPath: str }, ["repoPath"]) },
  { name: "sswp_registry_health", description: "Latest check per node with historical timestamps, current path availability, capture delivery status and v2 ledger integrity.", inputSchema: input({ limit }) },
  { name: "sswp_ledger", description: "Versioned local ledger and verification status. Historical records are preserved separately and are not certified by this chain.", inputSchema: input({ limit }) },
  { name: "sswp_node_search", description: "Find registry nodes by literal name, description or path.", inputSchema: input({ query: str, limit }, ["query"]) },
  { name: "sswp_analyze_deps", description: "Local metadata checks. Flags unpinned versions and missing integrity declarations; does not establish maliciousness, CVE coverage or package safety.", inputSchema: input({ packages: { type: "array", maxItems: 1e3, items: { type: "object", properties: { name: str, version: str, integrity: { type: "string" } }, required: ["name", "version"], additionalProperties: false } } }, ["packages"]) },
  { name: "sswp_export_to_omega", description: "Retry durable delivery of committed attestations to Brain. Delivery is idempotent; Brain consumption status is separate.", inputSchema: input({}) }
];
var ajv = new import_ajv.default({ strict: false });
var validators = new Map(definitions.map((t) => [t.name, ajv.compile(t.inputSchema)]));
function materializePending() {
  const rows = REG.db.prepare("SELECT a.*,n.repo_path FROM attestations a JOIN nodes n ON n.node_id=a.node_id WHERE json_extract(a.metadata,'$.materialization')='pending' ORDER BY a.run_at").all();
  for (const row2 of rows) {
    try {
      const latest = REG.getLatestAttestation(row2.node_id);
      if (latest?.attestation_id !== row2.attestation_id) {
        REG.db.prepare("UPDATE attestations SET metadata=json_set(metadata,'$.materialization','superseded') WHERE attestation_id=?").run(row2.attestation_id);
        continue;
      }
      if (!(0, import_node_fs6.existsSync)(row2.repo_path) || (0, import_node_path6.resolve)(row2.sswp_json_path) !== (0, import_node_path6.resolve)(row2.repo_path, ".sswp.json")) throw Error("Recorded destination unavailable or invalid");
      const temporary = row2.sswp_json_path + "." + (0, import_node_crypto6.randomUUID)() + ".tmp";
      (0, import_node_fs6.writeFileSync)(temporary, row2.raw_json);
      (0, import_node_fs6.renameSync)(temporary, row2.sswp_json_path);
      REG.db.prepare("UPDATE attestations SET metadata=json_set(metadata,'$.materialization','complete') WHERE attestation_id=?").run(row2.attestation_id);
    } catch (e) {
      console.error("SSWP materialization pending:", String(e));
    }
  }
}
async function witnessAction(args) {
  const target = { repoPath: (0, import_node_fs6.realpathSync)(args.repoPath).replaceAll("\\", "/") };
  if (args.repoPath !== target.repoPath) throw Error("Use the canonical absolute repoPath for approval and execution");
  const policy = consumeApproval("sswp_witness", target, args.approval, args.task_id);
  const att = await witness(target.repoPath, policy, args.task_id);
  const node = REG.upsertNode({ name: att.target.name, repo_path: target.repoPath });
  const destination = (0, import_node_path6.join)(target.repoPath, ".sswp.json"), raw = canonical(att);
  REG.saveAttestation(node.node_id, att, destination, raw);
  materializePending();
  try {
    REG.flushEvents();
  } catch (e) {
    return { attestation: att, delivery: "pending", delivery_error: String(e) };
  }
  return { attestation: att, delivery: "queued_for_brain", materialization: REG.db.prepare("SELECT metadata FROM attestations WHERE attestation_id=?").get(att.id) };
}
async function dispatch(name, args) {
  const validate = validators.get(name);
  if (!validate) throw Error("Unknown tool");
  if (!validate(args)) throw Error(ajv.errorsText(validate.errors));
  if (name === "sswp_witness") return witnessAction(args);
  if (name === "sswp_bulk_witness") {
    const result2 = [];
    for (const item of args.items) {
      try {
        result2.push(await witnessAction(item));
      } catch (e) {
        result2.push({ repoPath: item.repoPath, error: String(e) });
      }
    }
    return result2;
  }
  if (name === "sswp_verify") {
    const att = JSON.parse((0, import_node_fs6.readFileSync)(args.filePath, "utf8"));
    return { verified: verifyAttestation(args.filePath), status: att.signatureAlgorithm === "sha256-canonical-json-v2" ? verifyAttestation(args.filePath) ? "HASH_VALID" : "HASH_MISMATCH" : "LEGACY_UNVERIFIED", meaning: "content consistency only; no assertion of origin or correctness" };
  }
  if (name === "sswp_check_repo") return { git: await gitIntegrityGate(args.repoPath), lockfile: lockfileGate(args.repoPath) };
  if (name === "sswp_registry_health") return { nodes: REG.getHealthBoard().slice(0, args.limit || 20), integrity: REG.verifyLedger(), delivery_pending: REG.db.prepare("SELECT COUNT(*) n FROM event_outbox WHERE delivered=0").get(), materialization_pending: REG.db.prepare("SELECT COUNT(*) n FROM attestations WHERE json_extract(metadata,'$.materialization')='pending'").get() };
  if (name === "sswp_ledger") return { integrity: REG.verifyLedger(), entries: REG.getLedger(args.limit || 20) };
  if (name === "sswp_node_search") {
    const q = args.query.toLowerCase();
    return REG.listNodes().filter((n) => (n.name + " " + n.repo_path + " " + n.description).toLowerCase().includes(q)).slice(0, args.limit || 20);
  }
  if (name === "sswp_analyze_deps") return { assessment: "metadata signals only; not a security verdict", packages: args.packages.map((p) => ({ ...p, unpinned: /[\^~*<>]|latest/.test(p.version), integrityDeclaration: p.integrity ? "PRESENT_UNVERIFIED" : "MISSING", vulnerabilityStatus: "NOT_CHECKED" })) };
  if (name === "sswp_export_to_omega") {
    materializePending();
    REG.flushEvents();
    return { queued: true, pending: REG.db.prepare("SELECT COUNT(*) n FROM event_outbox WHERE delivered=0").get() };
  }
}
async function start() {
  const server = new import_server.Server({ name: "sswp-mcp", version: "2.1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(import_types.ListToolsRequestSchema, async () => ({ tools: definitions.map((t) => ({ ...t, annotations: { readOnlyHint: !["sswp_witness", "sswp_bulk_witness", "sswp_export_to_omega"].includes(t.name), idempotentHint: !["sswp_witness", "sswp_bulk_witness"].includes(t.name), openWorldHint: false } })) }));
  server.setRequestHandler(import_types.CallToolRequestSchema, async (r) => {
    try {
      return { content: [{ type: "text", text: JSON.stringify(await dispatch(r.params.name, r.params.arguments || {})) }] };
    } catch (e) {
      return { isError: true, content: [{ type: "text", text: String(e) }] };
    }
  });
  await server.connect(new import_stdio.StdioServerTransport());
  const timer = setInterval(() => {
    try {
      materializePending();
      REG.flushEvents();
    } catch (e) {
      console.error("SSWP delivery pending:", String(e));
    }
  }, 5e3);
  timer.unref();
}
if (require.main === module) start().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  definitions,
  dispatch,
  start
});
