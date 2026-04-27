// src/sswp/registry/cli.ts
/** SSWP Registry CLI — dashboard health, seed, sync, ledger */

import { RegistryManager } from "./manager.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const DB_PATH = resolve(process.env.HOME ?? "/tmp", ".sswp_registry.sqlite");
const NODES_JSON = resolve("/mnt/c/Veritas_Lab/veritas-topography-map/data/nodes.json");

function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const mgr = new RegistryManager({ dbPath: DB_PATH });

  switch (cmd) {
    case "seed":
      seed(mgr, args[0] ?? NODES_JSON);
      break;
    case "health":
      health(mgr);
      break;
    case "risk":
      riskBoard(mgr);
      break;
    case "ledger":
      ledger(mgr, parseInt(args[0] ?? "20", 10));
      break;
    case "verify-ledger":
      verifyLedger(mgr);
      break;
    case "omega-export":
      omegaExport(mgr, parseInt(args[0] ?? "50", 10));
      break;
    default:
      console.log(`SSWP Registry CLI

  seed [nodes.json]      — seed nodes from topology file
  health                 — show node health board
  risk                   — show risk leaderboard
  ledger [n]             — show last n ledger entries (default 20)
  verify-ledger          — verify chain integrity
  omega-export [n]       — export attestations to Omega Brain format
`);
  }

  mgr.close();
}

function seed(mgr: RegistryManager, path: string) {
  if (!readFileSync(path)) { console.error("File not found:", path); process.exit(1); }
  const { inserted, updated, errors } = mgr.syncFromDisk(path);
  console.log(`Seed done: ${inserted} inserted, ${updated} updated`);
  if (errors.length) {
    console.log("Errors:");
    errors.forEach(e => console.log("  " + e));
  }
}

function health(mgr: RegistryManager) {
  const rows = mgr.getHealthBoard();
  if (!rows.length) { console.log("No nodes registered."); return; }
  console.log("NODE\t\t\tSTATUS\tLAST_RUN\t\t\tRISK\tADVERSARIAL");
  for (const r of rows) {
    const name = String(r.name).padEnd(20, " ");
    const status = String(r.status).padEnd(8, " ");
    const last = r.last_run ? String(r.last_run).slice(0, 19) : "never     ";
    const risk = r.last_risk != null ? ((r.last_risk as number) * 100).toFixed(1) + "%" : "N/A";
    const adv = r.last_adversarial != null ? ((r.last_adversarial as number) * 100).toFixed(1) + "%" : "N/A";
    console.log(`${name}\t${status}\t${last}\t${risk}\t${adv}`);
  }
}

function riskBoard(mgr: RegistryManager) {
  const rows = mgr.getRiskLeaderboard();
  console.log("RISK BAND\tNODE\t\t\tRISK\tADVERSARIAL\tRUNS");
  for (const r of rows) {
    const band = String(r.risk_band).padEnd(10, " ");
    const name = String(r.name).padEnd(20, " ");
    const risk = r.last_risk != null ? ((r.last_risk as number) * 100).toFixed(1) + "%" : "N/A";
    const adv = r.last_adversarial != null ? ((r.last_adversarial as number) * 100).toFixed(1) + "%" : "N/A";
    const runs = String(r.total_runs ?? 0);
    console.log(`${band}\t${name}\t${risk}\t${adv}\t\t${runs}`);
  }
}

function ledger(mgr: RegistryManager, limit: number) {
  const rows = mgr.getLedger(limit);
  console.log("ID\tTYPE\t\tHASH\t\t\t\t\t\t\t\tTIMESTAMP");
  for (const r of rows) {
    const id = String(r.id).padEnd(6, " ");
    const type = String(r.event_type).padEnd(12, " ");
    const hash = String(r.hash).slice(0, 40).padEnd(42, " ");
    const ts = String(r.timestamp);
    console.log(`${id}\t${type}\t${hash}\t${ts}`);
  }
}

function verifyLedger(mgr: RegistryManager) {
  const ok = mgr.verifyLedger();
  console.log(ok ? "✓ Ledger chain valid — every hash links" : "✗ LEDGER CORRUPTION DETECTED");
}

function omegaExport(mgr: RegistryManager, limit: number) {
  const fragments = mgr.exportToOmegaBrain({ limit });
  console.log(JSON.stringify(fragments, null, 2));
}

main();
