// src/sswp/registry/manager.ts
/** SSWP Registry Manager — SQLite-backed with FTS5, ledger, Omega Brain bridge */

import Database from "better-sqlite3";
import schemaSql from "./schema.sql";
import {appendLedger as appendV2,verifyLedger as verifyV2,initLedger,canonical,deliverOutbox} from "../core/integrity.js";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { SswpAttestation, GateResult, DependencyEntry } from "../core/types.js";

const SCHEMA_PATH = resolve(process.cwd(), "src/sswp/registry/schema.sql");
const DEFAULT_DB = process.env.SSWP_DB || resolve(require("node:os").homedir(), ".sswp_registry.sqlite");

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
  public db: Database.Database;
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
    const sql = schemaSql;
    this.db.exec(sql);
    this.db.pragma('busy_timeout=30000');
    this.db.exec('CREATE TABLE IF NOT EXISTS event_outbox(id TEXT PRIMARY KEY,task_id TEXT NOT NULL,event_type TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL,delivered INTEGER DEFAULT 0)');
    initLedger(this.db);
    if(!this.db.prepare('SELECT 1 FROM ledger_v2 LIMIT 1').get())appendV2(this.db,'MIGRATION_READY',{version:2});

  }

  close() {
    this.db.close();
  }

  // ═══════════════════════════════════════════════════════════════
  // NODES
  // ═══════════════════════════════════════════════════════════════

  upsertNode(node: Partial<NodeRecord> & { name: string; repo_path: string }): NodeRecord {
    const id = node.node_id ?? this.getNodeByPath(node.repo_path)?.node_id ?? randomUUID();
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
    return this.db.transaction(()=>{
      const passCount=att.gates.filter(g=>g.status==='PASS').length;
      const failCount=att.gates.filter(g=>g.status==='FAIL'||g.status==='ERROR').length;
      const overall=att.gates.some(g=>g.status==='ERROR')?'ERROR':failCount?'FAIL':att.gates.some(g=>g.status==='INCONCLUSIVE')?'INCONCLUSIVE':passCount?'PASS':'NOT_APPLICABLE';
      const row=this.db.prepare('INSERT INTO attestations(attestation_id,node_id,run_at,overall_status,risk_score,adversarial_risk,gate_pass_count,gate_fail_count,sha256,sswp_json_path,raw_json,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING *').get(id,nodeId,att.timestamp,overall,att.adversarial?.overallRisk??0,att.adversarial?.overallRisk??0,passCount,failCount,createHash('sha256').update(rawJson).digest('hex'),jsonPath,rawJson,JSON.stringify({version:2,materialization:'pending',assessment:'risk scores are not safety probabilities'}));
      for(const g of att.gates)this.saveGateHistory(id,nodeId,g);
      for(const d of att.dependencies)this.saveDepSnapshot(id,nodeId,d);
      const taskId=(att as any).taskId;
      if(!taskId)throw Error('taskId required');
      const payload={attestation_id:id,node_id:nodeId,signature:att.signature,overall,repo:att.target.repo};
      appendV2(this.db,'WITNESS',payload,taskId);
      this.db.prepare('INSERT INTO event_outbox(id,task_id,event_type,payload,created_at) VALUES(?,?,?,?,?)').run('sswp:'+id,taskId,'SSWP_ATTESTATION',canonical(payload),new Date().toISOString());
      return row as AttestationRecord;
    }).immediate();
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

  appendLedger(eventType:string,payload:Record<string,unknown>):void {appendV2(this.db,eventType,payload,String(payload.task_id||'system'));}
  getLedger(limit=100):any[] {return this.db.prepare('SELECT * FROM ledger_v2 ORDER BY id DESC LIMIT ?').all(Math.max(1,Math.min(limit,100)));}
  verifyLedger():any {return verifyV2(this.db);}
  flushEvents():void {deliverOutbox(this.db);}
  // ═══════════════════════════════════════════════════════════════
  // DASHBOARD VIEWS
  // ═══════════════════════════════════════════════════════════════

  getHealthBoard() {
    return this.db.prepare('WITH ranked AS (SELECT a.*,ROW_NUMBER() OVER(PARTITION BY node_id ORDER BY run_at DESC,attestation_id DESC) rn FROM attestations a) SELECT n.name,n.repo_path,n.status,r.overall_status,r.run_at,r.risk_score FROM nodes n LEFT JOIN ranked r ON r.node_id=n.node_id AND r.rn=1 ORDER BY r.run_at DESC').all().map((r:any)=>({...r,localPathExists:existsSync(r.repo_path),evidenceScope:'historical; check timestamp and source revision before reuse'}));
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
