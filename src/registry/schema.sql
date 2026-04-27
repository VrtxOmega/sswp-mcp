-- src/sswp/registry/schema.sql
-- SSWP SQLite Registry Schema — mirrors Omega Brain tables + SSWP-specific domain

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ════════════════════════════════════════════════════════════════
-- CORE TABLES
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS nodes (
    node_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    repo_path   TEXT NOT NULL UNIQUE,
    node_type   TEXT NOT NULL DEFAULT 'node',   -- node, infrastructure, tool
    status      TEXT NOT NULL DEFAULT 'active', -- active, deprecated, archived
    first_seen  TEXT DEFAULT (datetime('now')),
    last_seen   TEXT DEFAULT (datetime('now')),
    description TEXT,
    tags        TEXT, -- JSON array
    metadata    TEXT  -- JSON blob
);

CREATE INDEX IF NOT EXISTS idx_nodes_type   ON nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);

-- ════════════════════════════════════════════════════════════════
-- ATTESTATIONS  (one per witness run)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS attestations (
    attestation_id  TEXT PRIMARY KEY, -- UUID
    node_id         TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    run_at          TEXT DEFAULT (datetime('now')),
    overall_status  TEXT NOT NULL,      -- PASS, FAIL, PARTIAL
    risk_score      REAL DEFAULT 0,     -- 0.0 - 1.0
    adversarial_risk REAL DEFAULT 0,    -- 0.0 - 1.0
    gate_pass_count INTEGER DEFAULT 0,
    gate_fail_count INTEGER DEFAULT 0,
    sha256          TEXT,
    sswp_json_path  TEXT,
    raw_json        TEXT,               -- full .sswp.json blob
    metadata        TEXT                -- JSON blob
);

CREATE INDEX IF NOT EXISTS idx_att_node    ON attestations(node_id);
CREATE INDEX IF NOT EXISTS idx_att_time    ON attestations(run_at);
CREATE INDEX IF NOT EXISTS idx_att_status  ON attestations(overall_status);
CREATE INDEX IF NOT EXISTS idx_att_risk    ON attestations(risk_score);

-- ════════════════════════════════════════════════════════════════
-- GATES_HISTORY  (one row per gate per attestation)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS gates_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attestation_id  TEXT NOT NULL REFERENCES attestations(attestation_id) ON DELETE CASCADE,
    node_id         TEXT NOT NULL,
    gate_name       TEXT NOT NULL,      -- INTAKE, TYPE, DEPENDENCY, EVIDENCE, MATH, COST, INCENTIVE, SECURITY, ADVERSARY, TRACE
    gate_number     INTEGER NOT NULL,   -- 1-10
    status          TEXT NOT NULL,      -- PASS, FAIL, SKIP, ERROR
    reason_code     TEXT,
    detail          TEXT,
    duration_ms     INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_gh_att   ON gates_history(attestation_id);
CREATE INDEX IF NOT EXISTS idx_gh_node  ON gates_history(node_id);
CREATE INDEX IF NOT EXISTS idx_gh_gate  ON gates_history(gate_name);

-- ════════════════════════════════════════════════════════════════
-- LEDGER  (append-only SEAL-like audit trail)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ledger (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    prev_hash   TEXT,
    event_type  TEXT NOT NULL,          -- WITNESS, VERIFY, ALERT, SYNC, CRON
    payload     TEXT NOT NULL,          -- JSON blob
    hash        TEXT UNIQUE,            -- SHA-256 of (prev_hash + payload + timestamp)
    timestamp   TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ledger_type ON ledger(event_type);
CREATE INDEX IF NOT EXISTS idx_ledger_time ON ledger(timestamp);

-- ════════════════════════════════════════════════════════════════
-- DEPENDENCY SNAPSHOTS  (what deps looked like at witness time)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS dep_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    attestation_id  TEXT NOT NULL REFERENCES attestations(attestation_id) ON DELETE CASCADE,
    node_id         TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    version         TEXT,
    resolved        TEXT,
    integrity       TEXT,
    suspicious      INTEGER DEFAULT 0,
    risk_score      REAL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_ds_att ON dep_snapshots(attestation_id);

-- ════════════════════════════════════════════════════════════════
-- FTS5 FULL-TEXT INDICES (mirrors Omega Brain)
-- ════════════════════════════════════════════════════════════════

CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(
    name, description, tags,
    tokenize='porter unicode61',
    content='nodes',
    content_rowid='rowid'
);

CREATE VIRTUAL TABLE IF NOT EXISTS attestations_fts USING fts5(
    raw_json, metadata,
    tokenize='porter unicode61',
    content='attestations',
    content_rowid='rowid'
);

-- ════════════════════════════════════════════════════════════════
-- TRIGGERS: keep FTS in sync
-- ════════════════════════════════════════════════════════════════

CREATE TRIGGER IF NOT EXISTS nodes_ai AFTER INSERT ON nodes BEGIN
    INSERT INTO nodes_fts(rowid, name, description, tags)
    VALUES (new.rowid, new.name, new.description, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS nodes_ad AFTER DELETE ON nodes BEGIN
    INSERT INTO nodes_fts(nodes_fts, rowid, name, description, tags)
    VALUES ('delete', old.rowid, old.name, old.description, old.tags);
END;

CREATE TRIGGER IF NOT EXISTS nodes_au AFTER UPDATE ON nodes BEGIN
    INSERT INTO nodes_fts(nodes_fts, rowid, name, description, tags)
    VALUES ('delete', old.rowid, old.name, old.description, old.tags);
    INSERT INTO nodes_fts(rowid, name, description, tags)
    VALUES (new.rowid, new.name, new.description, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS attestations_ai AFTER INSERT ON attestations BEGIN
    INSERT INTO attestations_fts(rowid, raw_json, metadata)
    VALUES (new.rowid, new.raw_json, new.metadata);
END;

CREATE TRIGGER IF NOT EXISTS attestations_ad AFTER DELETE ON attestations BEGIN
    INSERT INTO attestations_fts(attestations_fts, rowid, raw_json, metadata)
    VALUES ('delete', old.rowid, old.raw_json, old.metadata);
END;

-- ════════════════════════════════════════════════════════════════
-- VIEWS: convenience dashboards
-- ════════════════════════════════════════════════════════════════

CREATE VIEW IF NOT EXISTS v_node_health AS
SELECT
    n.node_id,
    n.name,
    n.status,
    COUNT(DISTINCT a.attestation_id) AS total_runs,
    MAX(a.run_at) AS last_run,
    a.overall_status AS last_status,
    a.risk_score AS last_risk,
    a.adversarial_risk AS last_adversarial
FROM nodes n
LEFT JOIN attestations a ON a.node_id = n.node_id
GROUP BY n.node_id;

CREATE VIEW IF NOT EXISTS v_gate_trend AS
SELECT
    node_id,
    gate_name,
    run_at,
    status,
    COUNT(*) OVER (PARTITION BY node_id, gate_name ORDER BY run_at ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS pass_rate_window
FROM gates_history gh
JOIN attestations a ON a.attestation_id = gh.attestation_id;

CREATE VIEW IF NOT EXISTS v_risk_leaderboard AS
SELECT
    node_id,
    name,
    last_risk,
    last_adversarial,
    total_runs,
    CASE
        WHEN last_risk > 0.7 THEN 'CRITICAL'
        WHEN last_risk > 0.4 THEN 'WARNING'
        ELSE 'OK'
    END AS risk_band
FROM v_node_health
ORDER BY last_risk DESC;
