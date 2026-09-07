# SSWP MCP

SSWP records what configured software checks actually establish. Its MCP and CLI entry points share one implementation and a persistent SQLite registry.

Version 2.1 fixes false Git PASS results, missing execution timeouts, source/bundle divergence, incomplete nested hashes and inconsistent ledger timestamps. Witness execution requires a short-lived operator-policy receipt from [Omega Brain](https://github.com/VrtxOmega/omega-brain-mcp). Caller-supplied approval strings are no longer accepted.

Use Node 22 or newer and pnpm 11. Install with `pnpm install --frozen-lockfile`, run `pnpm build`, then start `node dist/sswp.cjs`. `pnpm check` checks TypeScript. Build receipts contain source, lockfile and artifact hashes. Native SQLite and esbuild install scripts are explicitly allowed by the workspace configuration.

Configure an absolute `SSWP_DB` path and the same `VERITAS_SHARED_DIR` used by Brain and [Stenographer](https://github.com/VrtxOmega/omega-stenographer-mcp). Add the server command to persistent user MCP configuration. `sswp_check_repo` is read-only; `sswp_witness` runs only explicitly configured project commands, checks the receipt, writes an attestation and durably queues an event for Brain.

PASS, FAIL, ERROR, INCONCLUSIVE and NOT_APPLICABLE remain distinct. BUILD_SUCCESS and REPRODUCIBLE_BUILD are separate gates. Reproducibility requires nonempty matching outputs from two fresh source copies. `sswp_verify` covers nested fields in v2 attestations and reports older formats as LEGACY_UNVERIFIED; a content hash does not authenticate an author.

`sswp_registry_health` reports the latest run per node, timestamps, current path availability, pending materializations and delivery status. Registry writes, gate rows, ledger events and outbox jobs commit together. Committed attestations can be materialized and delivered again after interruption. Historical records remain historical.

See [current operating contract](docs/CURRENT_STATE.md) for exact permission boundaries, missing-evidence behavior, dependency coverage and recovery. Tests use local synthetic projects. `pnpm test` additionally exercises Python-to-Node receipts when an Omega Brain checkout and `.venv` are present as siblings, as arranged by CI.
