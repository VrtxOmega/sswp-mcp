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

// src/registry/manager.ts
var manager_exports = {};
__export(manager_exports, {
  RegistryManager: () => RegistryManager,
  default: () => manager_default
});
module.exports = __toCommonJS(manager_exports);
var import_better_sqlite32 = __toESM(require("better-sqlite3"));

// src/registry/schema.sql
var schema_default = "-- src/sswp/registry/schema.sql\n-- SSWP SQLite Registry Schema \u2014 mirrors Omega Brain tables + SSWP-specific domain\n\nPRAGMA journal_mode = WAL;\nPRAGMA foreign_keys = ON;\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- CORE TABLES\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS nodes (\n    node_id     TEXT PRIMARY KEY,\n    name        TEXT NOT NULL,\n    repo_path   TEXT NOT NULL UNIQUE,\n    node_type   TEXT NOT NULL DEFAULT 'node',   -- node, infrastructure, tool\n    status      TEXT NOT NULL DEFAULT 'active', -- active, deprecated, archived\n    first_seen  TEXT DEFAULT (datetime('now')),\n    last_seen   TEXT DEFAULT (datetime('now')),\n    description TEXT,\n    tags        TEXT, -- JSON array\n    metadata    TEXT  -- JSON blob\n);\n\nCREATE INDEX IF NOT EXISTS idx_nodes_type   ON nodes(node_type);\nCREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- ATTESTATIONS  (one per witness run)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS attestations (\n    attestation_id  TEXT PRIMARY KEY, -- UUID\n    node_id         TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,\n    run_at          TEXT DEFAULT (datetime('now')),\n    overall_status  TEXT NOT NULL,      -- PASS, FAIL, PARTIAL\n    risk_score      REAL DEFAULT 0,     -- 0.0 - 1.0\n    adversarial_risk REAL DEFAULT 0,    -- 0.0 - 1.0\n    gate_pass_count INTEGER DEFAULT 0,\n    gate_fail_count INTEGER DEFAULT 0,\n    sha256          TEXT,\n    sswp_json_path  TEXT,\n    raw_json        TEXT,               -- full .sswp.json blob\n    metadata        TEXT                -- JSON blob\n);\n\nCREATE INDEX IF NOT EXISTS idx_att_node    ON attestations(node_id);\nCREATE INDEX IF NOT EXISTS idx_att_time    ON attestations(run_at);\nCREATE INDEX IF NOT EXISTS idx_att_status  ON attestations(overall_status);\nCREATE INDEX IF NOT EXISTS idx_att_risk    ON attestations(risk_score);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- GATES_HISTORY  (one row per gate per attestation)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS gates_history (\n    id              INTEGER PRIMARY KEY AUTOINCREMENT,\n    attestation_id  TEXT NOT NULL REFERENCES attestations(attestation_id) ON DELETE CASCADE,\n    node_id         TEXT NOT NULL,\n    gate_name       TEXT NOT NULL,      -- INTAKE, TYPE, DEPENDENCY, EVIDENCE, MATH, COST, INCENTIVE, SECURITY, ADVERSARY, TRACE\n    gate_number     INTEGER NOT NULL,   -- 1-10\n    status          TEXT NOT NULL,      -- PASS, FAIL, SKIP, ERROR\n    reason_code     TEXT,\n    detail          TEXT,\n    duration_ms     INTEGER DEFAULT 0\n);\n\nCREATE INDEX IF NOT EXISTS idx_gh_att   ON gates_history(attestation_id);\nCREATE INDEX IF NOT EXISTS idx_gh_node  ON gates_history(node_id);\nCREATE INDEX IF NOT EXISTS idx_gh_gate  ON gates_history(gate_name);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- LEDGER  (append-only SEAL-like audit trail)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS ledger (\n    id          INTEGER PRIMARY KEY AUTOINCREMENT,\n    prev_hash   TEXT,\n    event_type  TEXT NOT NULL,          -- WITNESS, VERIFY, ALERT, SYNC, CRON\n    payload     TEXT NOT NULL,          -- JSON blob\n    hash        TEXT UNIQUE,            -- SHA-256 of (prev_hash + payload + timestamp)\n    timestamp   TEXT DEFAULT (datetime('now'))\n);\n\nCREATE INDEX IF NOT EXISTS idx_ledger_type ON ledger(event_type);\nCREATE INDEX IF NOT EXISTS idx_ledger_time ON ledger(timestamp);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- DEPENDENCY SNAPSHOTS  (what deps looked like at witness time)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TABLE IF NOT EXISTS dep_snapshots (\n    id              INTEGER PRIMARY KEY AUTOINCREMENT,\n    attestation_id  TEXT NOT NULL REFERENCES attestations(attestation_id) ON DELETE CASCADE,\n    node_id         TEXT NOT NULL,\n    package_name    TEXT NOT NULL,\n    version         TEXT,\n    resolved        TEXT,\n    integrity       TEXT,\n    suspicious      INTEGER DEFAULT 0,\n    risk_score      REAL DEFAULT 0\n);\n\nCREATE INDEX IF NOT EXISTS idx_ds_att ON dep_snapshots(attestation_id);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- FTS5 FULL-TEXT INDICES (mirrors Omega Brain)\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(\n    name, description, tags,\n    tokenize='porter unicode61',\n    content='nodes',\n    content_rowid='rowid'\n);\n\nCREATE VIRTUAL TABLE IF NOT EXISTS attestations_fts USING fts5(\n    raw_json, metadata,\n    tokenize='porter unicode61',\n    content='attestations',\n    content_rowid='rowid'\n);\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- TRIGGERS: keep FTS in sync\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE TRIGGER IF NOT EXISTS nodes_ai AFTER INSERT ON nodes BEGIN\n    INSERT INTO nodes_fts(rowid, name, description, tags)\n    VALUES (new.rowid, new.name, new.description, new.tags);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS nodes_ad AFTER DELETE ON nodes BEGIN\n    INSERT INTO nodes_fts(nodes_fts, rowid, name, description, tags)\n    VALUES ('delete', old.rowid, old.name, old.description, old.tags);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS nodes_au AFTER UPDATE ON nodes BEGIN\n    INSERT INTO nodes_fts(nodes_fts, rowid, name, description, tags)\n    VALUES ('delete', old.rowid, old.name, old.description, old.tags);\n    INSERT INTO nodes_fts(rowid, name, description, tags)\n    VALUES (new.rowid, new.name, new.description, new.tags);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS attestations_ai AFTER INSERT ON attestations BEGIN\n    INSERT INTO attestations_fts(rowid, raw_json, metadata)\n    VALUES (new.rowid, new.raw_json, new.metadata);\nEND;\n\nCREATE TRIGGER IF NOT EXISTS attestations_ad AFTER DELETE ON attestations BEGIN\n    INSERT INTO attestations_fts(attestations_fts, rowid, raw_json, metadata)\n    VALUES ('delete', old.rowid, old.raw_json, old.metadata);\nEND;\n\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n-- VIEWS: convenience dashboards\n-- \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n\nCREATE VIEW IF NOT EXISTS v_node_health AS\nSELECT\n    n.node_id,\n    n.name,\n    n.status,\n    COUNT(DISTINCT a.attestation_id) AS total_runs,\n    MAX(a.run_at) AS last_run,\n    a.overall_status AS last_status,\n    a.risk_score AS last_risk,\n    a.adversarial_risk AS last_adversarial\nFROM nodes n\nLEFT JOIN attestations a ON a.node_id = n.node_id\nGROUP BY n.node_id;\n\nCREATE VIEW IF NOT EXISTS v_gate_trend AS\nSELECT\n    node_id,\n    gate_name,\n    run_at,\n    status,\n    COUNT(*) OVER (PARTITION BY node_id, gate_name ORDER BY run_at ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS pass_rate_window\nFROM gates_history gh\nJOIN attestations a ON a.attestation_id = gh.attestation_id;\n\nCREATE VIEW IF NOT EXISTS v_risk_leaderboard AS\nSELECT\n    node_id,\n    name,\n    last_risk,\n    last_adversarial,\n    total_runs,\n    CASE\n        WHEN last_risk > 0.7 THEN 'CRITICAL'\n        WHEN last_risk > 0.4 THEN 'WARNING'\n        ELSE 'OK'\n    END AS risk_band\nFROM v_node_health\nORDER BY last_risk DESC;\n";

// src/core/integrity.ts
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var import_better_sqlite3 = __toESM(require("better-sqlite3"));
var import_node_os = require("node:os");
function canonical(v) {
  if (v === null || typeof v !== "object") {
    const s = JSON.stringify(v);
    if (s === void 0 || typeof v === "number" && !Number.isFinite(v)) throw Error("Non-JSON value");
    return s;
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
var sha = (s) => (0, import_node_crypto.createHash)("sha256").update(s).digest("hex");
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
      const digest = (0, import_node_crypto.createHash)("sha256");
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
var sharedPath = () => process.env.VERITAS_SHARED_DIR || (0, import_node_path.join)((0, import_node_os.homedir)(), ".veritas-shared");
function deliverOutbox(db) {
  const shared = sharedPath();
  (0, import_node_fs.mkdirSync)(shared, { recursive: true });
  const bus = new import_better_sqlite3.default((0, import_node_path.join)(shared, "coordination.sqlite"));
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
var import_node_crypto2 = require("node:crypto");
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");
var SCHEMA_PATH = (0, import_node_path2.resolve)(process.cwd(), "src/sswp/registry/schema.sql");
var DEFAULT_DB = process.env.SSWP_DB || (0, import_node_path2.resolve)(require("node:os").homedir(), ".sswp_registry.sqlite");
var RegistryManager = class {
  db;
  dbPath;
  constructor(cfg = {}) {
    this.dbPath = cfg.dbPath ?? DEFAULT_DB;
    const dir = (0, import_node_path2.dirname)(this.dbPath);
    if (!(0, import_node_fs2.existsSync)(dir)) (0, import_node_fs2.mkdirSync)(dir, { recursive: true });
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
    const id = node.node_id ?? this.getNodeByPath(node.repo_path)?.node_id ?? (0, import_node_crypto2.randomUUID)();
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
  searchNodes(query, limit = 20) {
    const stmt = this.db.prepare(`
      SELECT n.* FROM nodes n
      JOIN nodes_fts f ON n.rowid = f.rowid
      WHERE nodes_fts MATCH ?
      ORDER BY rank
      LIMIT ?
    `);
    const rows = stmt.all(query, limit);
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
    const id = att.id ?? (0, import_node_crypto2.randomUUID)();
    return this.db.transaction(() => {
      const passCount = att.gates.filter((g) => g.status === "PASS").length;
      const failCount = att.gates.filter((g) => g.status === "FAIL" || g.status === "ERROR").length;
      const overall = att.gates.some((g) => g.status === "ERROR") ? "ERROR" : failCount ? "FAIL" : att.gates.some((g) => g.status === "INCONCLUSIVE") ? "INCONCLUSIVE" : passCount ? "PASS" : "NOT_APPLICABLE";
      const row2 = this.db.prepare("INSERT INTO attestations(attestation_id,node_id,run_at,overall_status,risk_score,adversarial_risk,gate_pass_count,gate_fail_count,sha256,sswp_json_path,raw_json,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *").get(id, nodeId, att.timestamp, overall, att.adversarial?.overallRisk ?? 0, att.adversarial?.overallRisk ?? 0, passCount, failCount, (0, import_node_crypto2.createHash)("sha256").update(rawJson).digest("hex"), jsonPath, rawJson, JSON.stringify({ version: 2, materialization: "pending", assessment: "risk scores are not safety probabilities" }));
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
  getAttestationHistory(nodeId, limit = 50) {
    const stmt = this.db.prepare("SELECT * FROM attestations WHERE node_id = ? ORDER BY run_at DESC LIMIT ?");
    return stmt.all(nodeId, limit);
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
  getLedger(limit = 100) {
    return this.db.prepare("SELECT * FROM ledger_v2 ORDER BY id DESC LIMIT ?").all(Math.max(1, Math.min(limit, 100)));
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
    return this.db.prepare("WITH ranked AS (SELECT a.*,ROW_NUMBER() OVER(PARTITION BY node_id ORDER BY run_at DESC,attestation_id DESC) rn FROM attestations a) SELECT n.name,n.repo_path,n.status,r.overall_status,r.run_at,r.risk_score FROM nodes n LEFT JOIN ranked r ON r.node_id=n.node_id AND r.rn=1 ORDER BY r.run_at DESC").all().map((r) => ({ ...r, localPathExists: (0, import_node_fs2.existsSync)(r.repo_path), evidenceScope: "historical; check timestamp and source revision before reuse" }));
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
    const nodes = JSON.parse((0, import_node_fs2.readFileSync)(nodesJsonPath, "utf-8"));
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
var manager_default = RegistryManager;
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  RegistryManager
});
