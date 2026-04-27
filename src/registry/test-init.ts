// src/sswp/registry/test-init.ts
import { RegistryManager } from "./manager.js";

async function main() {
  const mgr = new RegistryManager({ dbPath: "/tmp/test-sswp.db" });

  // Seed a test node
  const node = mgr.upsertNode({
    name: "veritas-test",
    repo_path: "/mnt/c/Veritas_Lab/veritas-test",
    node_type: "node",
    tags: ["test", "ci"],
    description: "Test node for validation",
  });
  console.log("Upserted node:", node.node_id, node.name);

  // Retrieve
  const found = mgr.getNode(node.node_id);
  console.log("Retrieved:", found?.name, found?.repo_path);

  // Search
  const results = mgr.searchNodes("test");
  console.log("Search hits:", results.length);

  // Health board (no attestations yet)
  const health = mgr.getHealthBoard();
  console.log("Health board rows:", health.length);

  // Ledger
  const ledger = mgr.getLedger(5);
  console.log("Ledger entries:", ledger.length);

  mgr.close();
  console.log("\n✓ Registry init OK");
}

main().catch(e => { console.error(e); process.exit(1); });
