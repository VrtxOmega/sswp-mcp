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
      description: "Run full SSWP witness on a project. Auto-saves to registry.",
      inputSchema: {
        type: "object",
        properties: { repoPath: { type: "string", description: "Project root path." } },
        required: ["repoPath"]
      }
    },
    {
      name: "sswp_verify",
      description: "Verify SHA-256 signature of a .sswp.json file.",
      inputSchema: {
        type: "object",
        properties: { filePath: { type: "string", description: ".sswp.json path." } },
        required: ["filePath"]
      }
    },
    {
      name: "sswp_analyze_deps",
      description: "Send deps to Kimi for supply-chain risk analysis.",
      inputSchema: {
        type: "object",
        properties: {
          packages: {
            type: "array",
            items: {
              type: "object",
              properties: { name: { type: "string" }, version: { type: "string" } },
              required: ["name", "version"]
            }
          }
        },
        required: ["packages"]
      }
    },
    {
      name: "sswp_bulk_witness",
      description: "Run witness on multiple repos sequentially. Auto-saves each.",
      inputSchema: {
        type: "object",
        properties: {
          repoPaths: { type: "array", items: { type: "string" } },
          skipMissing: { type: "boolean", default: true }
        },
        required: ["repoPaths"]
      }
    },
    {
      name: "sswp_check_repo",
      description: "Quick repo health check.",
      inputSchema: {
        type: "object",
        properties: { repoPath: { type: "string", description: "Project root path." } },
        required: ["repoPath"]
      }
    },
    {
      name: "sswp_registry_health",
      description: "Show SSWP registry health board for all nodes.",
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Max rows", default: 50 }
        }
      }
    },
    {
      name: "sswp_ledger",
      description: "Query the SSWP audit ledger.",
      inputSchema: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Entries to show", default: 20 },
          eventType: { type: "string", description: "Filter by event type" }
        }
      }
    },
    {
      name: "sswp_node_search",
      description: "Search nodes in the SSWP registry by name/tag/description.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          limit: { type: "number", description: "Max results", default: 10 }
        },
        required: ["query"]
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

      return mkText(formatAttestation(att) + "\n\n[REGISTRY] Saved attestation " + att.id, !ok);
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
