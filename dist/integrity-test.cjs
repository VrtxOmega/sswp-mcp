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

// src/core/integrity.ts
var integrity_exports = {};
__export(integrity_exports, {
  appendLedger: () => appendLedger,
  canonical: () => canonical,
  consumeApproval: () => consumeApproval,
  deliverOutbox: () => deliverOutbox,
  initLedger: () => initLedger,
  sha: () => sha,
  sharedPath: () => sharedPath,
  verifyLedger: () => verifyLedger
});
module.exports = __toCommonJS(integrity_exports);
var import_node_crypto2 = require("node:crypto");
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");
var import_better_sqlite3 = __toESM(require("better-sqlite3"));
var import_node_os = require("node:os");

// src/core/source-state.ts
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var excluded = /* @__PURE__ */ new Set([".git", "node_modules", ".venv", "data", "__pycache__", ".sswp.json"]);
function sourceFiles(root) {
  const result = [];
  const walk = (folder) => {
    for (const name of (0, import_node_fs.readdirSync)(folder)) {
      if (excluded.has(name)) continue;
      const p = (0, import_node_path.join)(folder, name), s = (0, import_node_fs.lstatSync)(p);
      if (s.isSymbolicLink()) throw Error("Source symlinks require an explicit packaged source snapshot");
      if (s.isDirectory()) walk(p);
      else if (s.isFile()) result.push((0, import_node_path.relative)(root, p).replaceAll("\\", "/"));
    }
  };
  walk(root);
  return result.sort();
}
function sourceIdentity(root) {
  const hash = (0, import_node_crypto.createHash)("sha256");
  for (const f of sourceFiles(root)) hash.update(f + "\0" + (0, import_node_crypto.createHash)("sha256").update((0, import_node_fs.readFileSync)((0, import_node_path.join)(root, f))).digest("hex") + "\n");
  return hash.digest("hex");
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
  const allowed = (policy.witness_roots || []).map((p2) => pathkey((0, import_node_fs2.realpathSync)(p2).replaceAll("\\", "/")));
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  appendLedger,
  canonical,
  consumeApproval,
  deliverOutbox,
  initLedger,
  sha,
  sharedPath,
  verifyLedger
});
