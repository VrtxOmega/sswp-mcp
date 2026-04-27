// src/sswp/registry/manager.ts
/** SSWP Registry Manager — SQLite-backed with FTS5, ledger, Omega Brain bridge */

import Database from "better-sqlite3";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { SswpAttestation, GateResult, DependencyEntry } from "../core/types.js";

const SCHEMA_PATH = resolve(process.cwd(), "src/sswp/registry/schema.sql");
const DEFAULT_DB = resolve(process.env.HOME ?? "/tmp", ".sswp_registry.sqlite");

export interface RegistryConfig {
  dbPath?: string;
  autoInit?: boolean;
}

export interface NodeRecord {
  node_id: string;
  name: string;
  repo_path: string;
  node_type: string;
  status: string;
  first_seen: string;
  last_seen: string;
  description?: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export interface AttestationRecord {
  attestation_id: string;
  node_id: string;
  run_at: string;
  overall_status: string;
  risk_score: number;
  adversarial_risk: number;
  gate_pass_count: number;
  gate_fail_count: number;
  sha256: string;
  sswp_json_path: string;
  raw_json: string;
}

export interface LedgerEntry {
  id: number;
  prev_hash: string;
  event_type: string;
  payload: string;
  hash: string;
  timestamp: string;
}

export class RegistryManager {
  private db: Database.Database;
  private dbPath: string;

  constructor(cfg: RegistryConfig = {}) {
    this.dbPath = cfg.dbPath ?? DEFAULT_DB;
    const dir = dirname(this.dbPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    this.db = new Database(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    if (cfg.autoInit !== false) this.initSchema();
  }

  initSchema() {
    const sql = readFileSync(SCHEMA_PATH, "utf-8");
    this.db.exec(sql);
  }

  close() {
    this.db.close();
  }

  // ═══════════════════════════════════════════════════════════════
  // NODES
  // ═══════════════════════════════════════════════════════════════

  upsertNode(node: Partial<NodeRecord> & { name: string; repo_path: string }): NodeRecord {
    const id = node.node_id ?? randomUUID();
    const now = new Date().toISOString();
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
    const row = stmt.get(id, node.name, node.repo_path, node.node_type ?? "node",
      node.status ?? "active", now, now, node.description ?? null, tagsJson, metaJson) as Record<string, unknown>;
    return this.deserializeNode(row);
  }

  getNode(nodeId: string): NodeRecord | undefined {
    const stmt = this.db.prepare("SELECT * FROM nodes WHERE node_id = ?");
    const row = stmt.get(nodeId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.deserializeNode(row);
  }

  getNodeByPath(repoPath: string): NodeRecord | undefined {
    const stmt = this.db.prepare("SELECT * FROM nodes WHERE repo_path = ?");
    const row = stmt.get(repoPath) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return this.deserializeNode(row);
  }

  listNodes(opts?: { type?: string; status?: string; limit?: number; offset?: number }): NodeRecord[] {
    let sql = "SELECT * FROM nodes WHERE 1=1";
    const params: (string | number)[] = [];
    if (opts?.type) { sql += " AND node_type = ?"; params.push(opts.type); }
    if (opts?.status) { sql += " AND status = ?"; params.push(opts.status); }
    sql += " ORDER BY last_seen DESC";
    if (opts?.limit) { sql += " LIMIT ?"; params.push(opts.limit); }
    if (opts?.offset) { sql += " OFFSET ?"; params.push(opts.offset); }
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as Record<string, unknown>[];
    return rows.map(r => this.deserializeNode(r));
  }

  searchNodes(query: string, limit = 20): NodeRecord[] {
    const stmt = this.db.prepare(`
      SELECT n.* FROM nodes n
      JOIN nodes_fts f ON n.rowid = f.rowid
      WHERE nodes_fts MATCH ?
      ORDER BY rank
      LIMIT ?
    `);
    const rows = stmt.all(query, limit) as Record<string, unknown>[];
    return rows.map(r => this.deserializeNode(r));
  }

  private deserializeNode(row: Record<string, unknown>): NodeRecord {
    return {
      node_id: String(row.node_id),
      name: String(row.name),
      repo_path: String(row.repo_path),
      node_type: String(row.node_type),
      status: String(row.status),
      first_seen: String(row.first_seen),
      last_seen: String(row.last_seen),
      description: row.description ? String(row.description) : undefined,
      tags: row.tags ? JSON.parse(String(row.tags)) : undefined,
      metadata: row.metadata ? JSON.parse(String(row.metadata)) : undefined,
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // ATTESTATIONS
  // ═══════════════════════════════════════════════════════════════

  saveAttestation(nodeId: string, att: SswpAttestation, jsonPath: string, rawJson: string): AttestationRecord {
    const id = att.id ?? randomUUID();
    const passCount = att.gates.filter(g => g.status === "PASS").length;
    const failCount = att.gates.length - passCount;
    const overall = failCount === 0 ? "PASS" : (passCount > 0 ? "PARTIAL" : "FAIL");
    const hash = createHash("sha256").update(rawJson).digest("hex");

    const stmt = this.db.prepare(`
      INSERT INTO attestations
        (attestation_id, node_id, overall_status, risk_score, adversarial_risk,
         gate_pass_count, gate_fail_count, sha256, sswp_json_path, raw_json, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      RETURNING *
    `);
    const row = stmt.get(
      id, nodeId, overall,
      att.adversarial?.overallRisk ?? 0,
      att.adversarial?.overallRisk ?? 0,
      passCount, failCount,
      hash, jsonPath, rawJson,
      JSON.stringify({ tool: "sswp_witness", version: "1.0.0" })
    ) as Record<string, unknown>;

    // Save gate history
    for (const g of att.gates) {
      this.saveGateHistory(id, nodeId, g);
    }

    // Ledger entry
    this.appendLedger("WITNESS", { attestationId: id, nodeId, overall, risk: att.adversarial?.overallRisk });

    return row as unknown as AttestationRecord;
  }

  private saveGateHistory(attId: string, nodeId: string, g: GateResult) {
    const stmt = this.db.prepare(`
      INSERT INTO gates_history (attestation_id, node_id, gate_name, gate_number, status, reason_code, detail, duration_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(attId, nodeId, g.gate, 0, g.status, g.evidence ?? null, null, g.durationMs ?? 0);
  }

  getLatestAttestation(nodeId: string): AttestationRecord | undefined {
    const stmt = this.db.prepare("SELECT * FROM attestations WHERE node_id = ? ORDER BY run_at DESC LIMIT 1");
    return stmt.get(nodeId) as AttestationRecord | undefined;
  }

  getAttestationHistory(nodeId: string, limit = 50): AttestationRecord[] {
    const stmt = this.db.prepare("SELECT * FROM attestations WHERE node_id = ? ORDER BY run_at DESC LIMIT ?");
    return stmt.all(nodeId, limit) as AttestationRecord[];
  }

  getAttestationGates(attestationId: string): Array<Record<string, unknown>> {
    const stmt = this.db.prepare("SELECT * FROM gates_history WHERE attestation_id = ? ORDER BY gate_number");
    return stmt.all(attestationId) as Array<Record<string, unknown>>;
  }

  // ═══════════════════════════════════════════════════════════════
  // DEPENDENCY SNAPSHOTS
  // ═══════════════════════════════════════════════════════════════

  saveDepSnapshot(attId: string, nodeId: string, dep: DependencyEntry) {
    const stmt = this.db.prepare(`
      INSERT INTO dep_snapshots (attestation_id, node_id, package_name, version, resolved, integrity, suspicious, risk_score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(attId, nodeId, dep.name, dep.version ?? null, dep.resolved ?? null, dep.integrity ?? null,
      dep.suspicious ? 1 : 0, dep.riskScore ?? 0);
  }

  getDepSnapshots(attestationId: string) {
    const stmt = this.db.prepare("SELECT * FROM dep_snapshots WHERE attestation_id = ?");
    return stmt.all(attestationId) as Array<Record<string, unknown>>;
  }

  // ═══════════════════════════════════════════════════════════════
  // LEDGER
  // ═══════════════════════════════════════════════════════════════

  appendLedger(eventType: string, payload: Record<string, unknown>): void {
    const last = this.db.prepare("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1").get() as { hash?: string } | undefined;
    const prev = last?.hash ?? "0";
    const ts = new Date().toISOString();
    const payloadJson = JSON.stringify(payload);
    const hash = createHash("sha256").update(prev + payloadJson + ts).digest("hex");

    const stmt = this.db.prepare("INSERT INTO ledger (prev_hash, event_type, payload, hash) VALUES (?, ?, ?, ?)");
    stmt.run(prev, eventType, payloadJson, hash);
  }

  getLedger(limit = 100): LedgerEntry[] {
    const stmt = this.db.prepare("SELECT * FROM ledger ORDER BY id DESC LIMIT ?");
    return stmt.all(limit) as LedgerEntry[];
  }

  verifyLedger(): boolean {
    const rows = this.db.prepare("SELECT * FROM ledger ORDER BY id").all() as LedgerEntry[];
    let prev = "0";
    for (const row of rows) {
      const expected = createHash("sha256").update(row.prev_hash + row.payload + row.timestamp).digest("hex");
      if (expected !== row.hash) return false;
      if (row.prev_hash !== prev) return false;
      prev = row.hash;
    }
    return true;
  }

  // ═══════════════════════════════════════════════════════════════
  // DASHBOARD VIEWS
  // ═══════════════════════════════════════════════════════════════

  getHealthBoard(): Array<Record<string, unknown>> {
    return this.db.prepare("SELECT * FROM v_node_health ORDER BY last_risk DESC").all() as Array<Record<string, unknown>>;
  }

  getRiskLeaderboard(): Array<Record<string, unknown>> {
    return this.db.prepare("SELECT * FROM v_risk_leaderboard").all() as Array<Record<string, unknown>>;
  }

  getGateTrend(nodeId: string, gateName?: string, windowDays = 30): Array<Record<string, unknown>> {
    const sql = `SELECT * FROM v_gate_trend WHERE node_id = ? AND run_at > datetime('now', '-${windowDays} days')` +
      (gateName ? " AND gate_name = ?" : "") + " ORDER BY run_at DESC";
    const stmt = this.db.prepare(sql);
    return (gateName ? stmt.all(nodeId, gateName) : stmt.all(nodeId)) as Array<Record<string, unknown>>;
  }

  // ═══════════════════════════════════════════════════════════════
  // BULK SEED FROM FILESYSTEM
  // ═══════════════════════════════════════════════════════════════

  syncFromDisk(nodesJsonPath: string): { inserted: number; updated: number; errors: string[] } {
    const nodes: Array<{ name: string; path: string; type?: string; tags?: string[]; description?: string }> =
      JSON.parse(readFileSync(nodesJsonPath, "utf-8"));
    let inserted = 0, updated = 0;
    const errors: string[] = [];

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
            description: n.description,
          });
          existing ? updated++ : inserted++;
        } catch (e: any) {
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

  exportToOmegaBrain(opts?: { limit?: number; since?: string }): Array<{ fragment_id: string; content: string; tier: string }> {
    let sql = `
      SELECT a.attestation_id, n.name, a.overall_status, a.risk_score, a.run_at, a.raw_json
      FROM attestations a
      JOIN nodes n ON n.node_id = a.node_id
      WHERE 1=1
    `;
    const params: (string | number)[] = [];
    if (opts?.since) { sql += " AND a.run_at > ?"; params.push(opts.since); }
    if (opts?.limit) { sql += " LIMIT ?"; params.push(opts.limit); }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as Array<Record<string, unknown>>;

    return rows.map(r => ({
      fragment_id: `sswp-att-${r.attestation_id}`,
      content: `[SSWP ATTESTATION] ${r.name}\nStatus: ${r.overall_status}\nRisk: ${(r.risk_score as number * 100).toFixed(1)}%\nRun: ${r.run_at}`,
      tier: r.overall_status === "PASS" ? "B" : "C",
    }));
  }
}

export default RegistryManager;
