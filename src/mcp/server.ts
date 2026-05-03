// src/sswp/mcp/server.ts
/** SSWP MCP Server v2 — auto-saves to registry, ledger, Omega Brain bridge */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { witness, verifyAttestation, formatAttestation } from "../core/witness.js";
import { toWslPath } from "./path-util.js";
import { kimiAnalyze } from "../core/kimi-reasoner.js";
import type { DependencyEntry } from "../core/types.js";
import { RegistryManager } from "../registry/manager.js";
import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const REG = new RegistryManager({ autoInit: true });

const server = new Server(
  { name: "sswp-mcp", version: "2.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "sswp_witness",
      description:
        "Witness a software project with deterministic attestation. Scans the full dependency graph (every node_modules package with resolved path, integrity hash, and risk score), runs a 5-gate pipeline (GIT_INTEGRITY, LOCKFILE, DETERMINISTIC_BUILD, TEST_PASS, LINT), adversarially probes every dependency for typosquatting, version anomalies, and missing integrity hashes, then produces a self-verifying .sswp.json attestation sealed with SHA-256. Auto-saves the attestation to the SQLite fleet registry and appends an entry to the tamper-proof audit ledger. This is the primary attestation tool — use it when you need a full cryptographic witness of a single repo's state. For multiple repos, use sswp_bulk_witness instead.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: {
        type: "object",
        properties: {
          repoPath: { type: "string", description: "Absolute path to the project root directory containing package.json and node_modules. The tool resolves WSL/Windows path translations automatically." },
          traceId: { type: "string", description: "Optional VERITAS trace ID (VT-YYYYMMDD-xxxxxxxx) for cross-system correlation with Omega Brain SEAL chain and Stenographer." },
          cortexVerdict: { type: "string", enum: ["APPROVED", "STEERED", "NOT_CHECKED"], description: "Gap #3 — Governance: result of omega_cortex_check run BEFORE calling sswp_witness. Pass 'APPROVED' or 'STEERED' to confirm the Cortex gate was satisfied." }
        },
        required: ["repoPath"]
      }
    },
    {
      name: "sswp_verify",
      description:
        "Verify the SHA-256 cryptographic signature of an existing .sswp.json attestation file. Recomputes the hash over the entire attestation payload (sorted keys, excluding the signature field) and compares it against the stored signature. Returns VALID ATTESTATION if the file is intact and unmodified, or SIGNATURE MISMATCH if the file was altered after sealing. Use this to audit an attestation you received from someone else, or to confirm a repo's attestation still matches the file on disk. For generating new attestations, use sswp_witness; for quick repo readiness checks without sealing, use sswp_check_repo.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: {
        type: "object",
        properties: { filePath: { type: "string", description: "Absolute path to the .sswp.json attestation file to verify. The file must contain a valid SSWP attestation with a 'signature' field." } },
        required: ["filePath"]
      }
    },
    {
      name: "sswp_analyze_deps",
      description:
        "Analyze a list of dependencies for supply-chain risk using Kimi K2 reasoning. Provide an array of {name, version} objects for any npm packages you want evaluated. The tool performs four analysis passes: typosquatting detection (matching names against known suspicious patterns like left-pad, event-stream), version anomaly scanning (flagging unpinned ranges like *, >=, ^0), metadata integrity checks (CRITICAL if a dependency lacks an integrity hash), and optional Kimi K2 deep reasoning (requires OLLAMA_CLOUD_API_KEY — returns INCONCLUSIVE without it). Returns a JSON object with per-probe results, overall risk score (0-1), and suspicious package counts. Use this for targeted supply-chain analysis on critical dependency trees. For generating full attestations that include probing, use sswp_witness.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true
      },
      inputSchema: {
        type: "object",
        properties: {
          packages: {
            type: "array",
            description: "Array of dependency objects to analyze. Each must include the package name and version string.",
            items: {
              type: "object",
              description: "A single dependency entry to analyze.",
              properties: {
                name: { type: "string", description: "The npm package name (e.g., 'better-sqlite3', '@modelcontextprotocol/sdk')." },
                version: { type: "string", description: "The version string as it appears in package-lock.json (e.g., '12.9.0', '^1.0.0')." }
              },
              required: ["name", "version"]
            }
          }
        },
        required: ["packages"]
      }
    },
    {
      name: "sswp_bulk_witness",
      description:
        "Run deterministic attestation on multiple repositories sequentially. For each repo path provided, runs the full SSWP witness pipeline (scan, 5-gate test, adversarial probe, SHA-256 seal) and auto-saves the .sswp.json attestation to the fleet registry. Reports per-repo PASS/FAIL status with risk percentages and a final summary of passed, failed, and skipped counts. Missing repos are skipped by default. Use this for nightly fleet audits, pre-release sweeps across the ecosystem, or any batch witnessing operation. For a single repo, prefer sswp_witness.",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: {
        type: "object",
        properties: {
          repoPaths: { type: "array", items: { type: "string" }, description: "Array of absolute paths to project root directories to witness. Each path must contain a package.json and node_modules." },
          skipMissing: { type: "boolean", default: true, description: "If true (default), skip repos that don't exist on disk and continue processing remaining repos. If false, returns an error immediately on the first missing repo." }
        },
        required: ["repoPaths"]
      }
    },
    {
      name: "sswp_check_repo",
      description:
        "Perform a lightweight repo health check without running the full witness pipeline. Verifies four conditions: the directory exists on disk, a .git directory is present (indicating a git repository), a package-lock.json exists (indicating locked dependencies), and a package.json exists (indicating a valid Node.js project). Returns a status line for each condition and an overall READY/NOT READY verdict. Use this as a fast pre-check in CI pipelines or before calling sswp_witness to ensure the repo is in a valid state. Does not seal an attestation or modify the registry.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: {
        type: "object",
        properties: { repoPath: { type: "string", description: "Absolute path to the project root directory to check. Must be a valid filesystem path." } },
        required: ["repoPath"]
      }
    },
    {
      name: "sswp_registry_health",
      description:
        "Display the full fleet health board from the SSWP SQLite registry. Returns a formatted table showing every witnessed node with its name, status (active/deprecated/archived), last witness run timestamp, overall risk score (as percentage), and adversarial risk score (as percentage). Results are ordered by risk descending (most risky nodes first). Use this for an ecosystem-wide dashboard view of attestation status. For searching specific nodes by name, tag, or description, use sswp_node_search. For querying the audit ledger directly, use sswp_ledger.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Maximum number of nodes to display in the health board. Defaults to 50 if not specified.", default: 50 }
        }
      }
    },
    {
      name: "sswp_ledger",
      description:
        "Query the tamper-proof SSWP audit ledger, an append-only SHA-256 hash chain that records every witness run, gate vote, and probe result. Returns a formatted table showing ledger entries with their sequence ID, event type (WITNESS, BULK_WITNESS), hash, and timestamp. Optionally filter by event type to narrow results. The ledger chain is cryptographically verifiable — any altered or removed entry breaks the chain. Use this for audit trail review, compliance reporting, or incident investigation. For a quick fleet overview, use sswp_registry_health instead.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Number of ledger entries to return, ordered newest first. Defaults to 20 if not specified.", default: 20 },
          eventType: { type: "string", description: "Filter entries by event type. Common values: 'WITNESS' (single repo attestation), 'BULK_WITNESS' (batch run). Omit to return all event types." }
        }
      }
    },
    {
      name: "sswp_node_search",
      description:
        "Search the SSWP fleet registry using full-text search (FTS5) across node names, tags, and descriptions. Matches partial keywords and ranks results by relevance. Returns a formatted table showing matching nodes with their name, node type, status, and repository path. Use this to find specific projects in the ecosystem registry by name fragment, technology tag, or description keyword. For a full sorted health board of all nodes, use sswp_registry_health instead.",
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      },
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query string. Supports partial keyword matching across node names, tags, and descriptions. Example: 'anyio' or 'omega' or 'witness'." },
          limit: { type: "number", description: "Maximum number of matching results to return, ordered by FTS5 relevance rank. Defaults to 10 if not specified.", default: 10 }
        },
        required: ["query"]
      }
    },
    {
      name: "sswp_export_to_omega",
      description: "Gap #2 — Formats the most recent SSWP attestation as an omega_seal_run payload, closing the SSWP→Omega Brain SEAL bridge gap. Enables one-click chaining: sswp_witness → sswp_export_to_omega → omega_seal_run. Returns ready-to-use context and response fields.",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      inputSchema: {
        type: "object",
        properties: {
          repoPath: { type: "string", description: "Optional: path to the repo whose attestation to export. Defaults to most recently witnessed node." },
          traceId: { type: "string", description: "Optional VERITAS trace ID to embed in the seal context." }
        }
      }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;

  if (name === "sswp_witness") {
    const rawPath = (args as any).repoPath as string;
    const wslPath = toWslPath(rawPath);
    if (!existsSync(wslPath)) {
      return mkText("Repo not found: " + wslPath + " (from " + rawPath + ")", true);
    }
    try {
      const att = await witness(wslPath);
      const ok = att.gates.every(g => g.status === "PASS");

      // Auto-save to registry
      let node = REG.getNodeByPath(wslPath);
      if (!node) {
        node = REG.upsertNode({ name: att.target.name || "unknown", repo_path: wslPath, node_type: "node" });
      }
      const jsonPath = resolve(wslPath, ".sswp.json");
      const rawJson = JSON.stringify(att, null, 2);
      writeFileSync(jsonPath, rawJson);
      REG.saveAttestation(node.node_id, att, jsonPath, rawJson);

      // Gap #2: emit to VERITAS shared event bus for Omega Brain SEAL chaining
      // Gap #3: record cortex governance state
      const cortexVerdict = (args as any).cortexVerdict as string || "NOT_CHECKED";
      const traceId = (args as any).traceId as string || "VT-UNTRACED";
      try {
        const os = await import("node:os");
        const { mkdirSync, appendFileSync } = await import("node:fs");
        const sharedDir = os.homedir() + "/.veritas-shared";
        mkdirSync(sharedDir, { recursive: true });
        const event = JSON.stringify({
          trace_id: traceId,
          event_type: "SSWP_WITNESS_COMPLETE",
          source: "sswp",
          payload: {
            target: att.target.name,
            repo: att.target.repo,
            commit: att.target.commitHash?.slice(0, 8) || "unknown",
            overall_status: ok ? "PASS" : "FAIL",
            adversarial_risk: att.adversarial.overallRisk,
            gates_passed: att.gates.filter(g => g.status === "PASS").length,
            gates_total: att.gates.length,
            signature: att.signature?.slice(0, 16),
            cortex_verdict: cortexVerdict,
            cortex_governed: cortexVerdict !== "NOT_CHECKED",
          },
          timestamp: new Date().toISOString(),
        });
        appendFileSync(sharedDir + "/events.jsonl", event + "\n");
        if (cortexVerdict === "NOT_CHECKED") {
          appendFileSync(sharedDir + "/events.jsonl", JSON.stringify({
            trace_id: traceId, event_type: "SSWP_CORTEX_NOT_CHECKED", source: "sswp",
            payload: { repo: att.target.repo, note: "sswp_witness called without prior omega_cortex_check" },
            timestamp: new Date().toISOString(),
          }) + "\n");
        }
      } catch (_e) { /* non-fatal */ }

      const cortexNote = cortexVerdict === "NOT_CHECKED"
        ? "\n\n⚠ CORTEX NOT CHECKED — Call omega_cortex_check before sswp_witness for governed attestation."
        : `\n\n✓ Cortex: ${cortexVerdict}`;
      return mkText(formatAttestation(att) + "\n\n[REGISTRY] Saved attestation " + att.id + cortexNote, !ok);
    } catch (err: any) {
      return mkText("SSWP ERROR: " + (err.message || String(err)), true);
    }
  }

  if (name === "sswp_verify") {
    const rawPath = (args as any).filePath as string;
    const filePath = resolve(rawPath);
    if (!existsSync(filePath)) {
      return mkText("File not found: " + filePath, true);
    }
    try {
      const valid = verifyAttestation(filePath);
      return mkText(valid ? "VALID ATTESTATION" : "SIGNATURE MISMATCH", !valid);
    } catch (err: any) {
      return mkText("VERIFY ERROR: " + (err.message || String(err)), true);
    }
  }

  if (name === "sswp_analyze_deps") {
    const packages = (args as any).packages as { name: string; version: string }[];
    if (!packages?.length) {
      return mkText("No packages provided.", true);
    }
    try {
      const deps: DependencyEntry[] = packages.map(p => ({
        name: p.name,
        version: p.version,
        resolved: "",
        integrity: null,
        suspicious: false,
        riskScore: 0,
      }));
      const results = await kimiAnalyze(deps);
      return mkText(JSON.stringify(results, null, 2), false);
    } catch (err: any) {
      return mkText("ANALYZE ERROR: " + (err.message || String(err)), true);
    }
  }

  if (name === "sswp_bulk_witness") {
    const paths = (args as any).repoPaths as string[];
    const skipMissing = (args as any).skipMissing !== false;
    const results: string[] = [];
    let pass = 0, fail = 0, skip = 0;
    for (const raw of paths) {
      const wsl = toWslPath(raw);
      if (!existsSync(wsl)) {
        if (skipMissing) { skip++; results.push("SKIP: " + raw); continue; }
        return mkText("Missing repo (skipMissing=false): " + raw, true);
      }
      try {
        const att = await witness(wsl);
        const ok = att.gates.every(g => g.status === "PASS");
        if (ok) pass++; else fail++;

        // Auto-save each
        let node = REG.getNodeByPath(wsl);
        if (!node) node = REG.upsertNode({ name: att.target.name || "unknown", repo_path: wsl, node_type: "node" });
        const jsonPath = resolve(wsl, ".sswp.json");
        const rawJson = JSON.stringify(att, null, 2);
        writeFileSync(jsonPath, rawJson);
        REG.saveAttestation(node.node_id, att, jsonPath, rawJson);

        results.push("[" + (ok ? "PASS" : "FAIL") + "] " + raw + " - risk " + (att.adversarial.overallRisk * 100).toFixed(1) + "%");
      } catch (err: any) {
        fail++;
        results.push("[ERROR] " + raw + ": " + err.message);
      }
    }
    const summary = "BULK DONE - " + pass + " passed, " + fail + " failed, " + skip + " skipped / " + paths.length + "\n\n" + results.join("\n");
    return mkText(summary, fail > 0);
  }

  if (name === "sswp_check_repo") {
    const rawPath = (args as any).repoPath as string;
    const wsl = toWslPath(rawPath);
    const checks = {
      exists: existsSync(wsl),
      isGit: existsSync(resolve(wsl, ".git")),
      hasLockfile: existsSync(resolve(wsl, "package-lock.json")),
      hasPackageJson: existsSync(resolve(wsl, "package.json")),
    };
    const ok = checks.exists && (checks.hasLockfile || checks.hasPackageJson);
    const text = "Repo: " + wsl + "\n" +
      "  exists: " + checks.exists + "\n" +
      "  git: " + checks.isGit + "\n" +
      "  package-lock.json: " + checks.hasLockfile + "\n" +
      "  package.json: " + checks.hasPackageJson + "\n" +
      "  status: " + (ok ? "READY" : "NOT READY");
    return mkText(text, !ok);
  }

  if (name === "sswp_registry_health") {
    const limit = (args as any).limit ?? 50;
    const rows = REG.getHealthBoard();
    if (!rows.length) return mkText("No nodes in registry.", false);
    const lines = ["NODE                 STATUS   LAST_RUN              RISK    ADVERSARIAL"];
    for (const r of rows.slice(0, limit)) {
      const name = String(r.name).slice(0, 20).padEnd(20, " ");
      const status = String(r.status).slice(0, 8).padEnd(8, " ");
      const last = r.last_run ? String(r.last_run).slice(0, 19) : "never     ";
      const risk = r.last_risk != null ? ((r.last_risk as number) * 100).toFixed(1) + "%" : "N/A  ";
      const adv = r.last_adversarial != null ? ((r.last_adversarial as number) * 100).toFixed(1) + "%" : "N/A";
      lines.push(`${name}  ${status}  ${last}  ${risk}  ${adv}`);
    }
    return mkText(lines.join("\n"), false);
  }

  if (name === "sswp_ledger") {
    const limit = (args as any).limit ?? 20;
    const eventType = (args as any).eventType as string | undefined;
    let rows = REG.getLedger(limit * 2);
    if (eventType) rows = rows.filter(r => r.event_type === eventType);
    rows = rows.slice(0, limit);
    if (!rows.length) return mkText("No ledger entries.", false);
    const lines = ["ID    TYPE         HASH                                      TIMESTAMP"];
    for (const r of rows) {
      const id = String(r.id).padEnd(5, " ");
      const type = String(r.event_type).slice(0, 12).padEnd(12, " ");
      const hash = String(r.hash).slice(0, 40).padEnd(42, " ");
      const ts = String(r.timestamp);
      lines.push(`${id}  ${type}  ${hash}  ${ts}`);
    }
    return mkText(lines.join("\n"), false);
  }

  if (name === "sswp_node_search") {
    const query = (args as any).query as string;
    const limit = (args as any).limit ?? 10;
    const rows = REG.searchNodes(query, limit);
    if (!rows.length) return mkText("No nodes matched: " + query, false);
    const lines = ["NAME                 TYPE       STATUS   PATH"];
    for (const r of rows) {
      const name = r.name.slice(0, 20).padEnd(20, " ");
      const type = r.node_type.slice(0, 10).padEnd(10, " ");
      const status = r.status.slice(0, 8).padEnd(8, " ");
      lines.push(`${name}  ${type}  ${status}  ${r.repo_path}`);
    }
    return mkText(lines.join("\n"), false);
  }

  if (name === "sswp_export_to_omega") {
    // Gap #2: format attestation as omega_seal_run payload
    const rawPath2 = (args as any).repoPath as string | undefined;
    const traceId2 = (args as any).traceId as string || "VT-UNTRACED";
    try {
      const rows = REG.getHealthBoard();
      let row: any;
      if (rawPath2) {
        const wsl2 = toWslPath(rawPath2);
        row = rows.find((r: any) => r.repo_path === wsl2);
        if (!row) return mkText("No attestation found for: " + rawPath2, true);
      } else {
        if (!rows.length) return mkText("No attestations in registry.", true);
        row = rows[0];
      }
      const riskPct = row.last_risk != null ? (row.last_risk * 100).toFixed(1) + "%" : "N/A";
      const advPct  = row.last_adversarial != null ? (row.last_adversarial * 100).toFixed(1) + "%" : "N/A";
      const sealPayload = {
        context: {
          event_type: "SSWP_WITNESS", source: "sswp", trace_id: traceId2,
          node: row.name, repo_path: row.repo_path,
          status: row.last_status || "UNKNOWN",
          risk_score: row.last_risk || 0,
          adversarial_risk: row.last_adversarial || 0,
          last_run: row.last_run,
        },
        response: `SSWP attestation — ${row.name} | Status: ${row.last_status || "UNKNOWN"} | Risk: ${riskPct} | Adversarial: ${advPct} | Run: ${row.last_run || "unknown"} | TraceID: ${traceId2}`
      };
      return mkText(
        "# omega_seal_run payload — ready to use\n\n" +
        "Call omega_seal_run with these arguments:\n\n" +
        JSON.stringify(sealPayload, null, 2), false
      );
    } catch (err: any) {
      return mkText("EXPORT ERROR: " + (err.message || String(err)), true);
    }
  }

  return mkText("Unknown tool: " + name, true);
});

function mkText(text: string, isError: boolean) {
  return { content: [{ type: "text" as const, text }], isError };
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SSWP MCP server v2 started (stdio)");
}

main().catch(err => {
  console.error("SSWP MCP fatal:", err);
  process.exit(1);
});
