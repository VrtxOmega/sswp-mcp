# SSWP MCP Server

<div align="center">
  <img src="https://raw.githubusercontent.com/VrtxOmega/Gravity-Omega/master/veritas_icon.png" width="120" alt="VERITAS SSWP" />
  <h1>SSWP MCP</h1>
  <p><strong>Sovereign Software Witness Protocol — Deterministic Attestation | Adversarial Probing | Tamper-Proof Sealing</strong></p>
</div>

---

## Overview

SSWP MCP is the attestation and witness layer of the **VERITAS & Sovereign Ecosystem (Omega Universe)**. It exposes an MCP server that Hermes, Claude, or any compatible agent can call natively to:

- **Witness** any software project with deterministic attestation
- **Verify** existing `.sswp.json` attestations via SHA-256
- **Audit** the full fleet registry (131 nodes)
- **Analyze** dependencies for supply-chain risk

Every `sswp_witness` call produces a signed, sealed attestation file. Every `sswp_bulk_witness` run is logged to the audit ledger.

---

## Quickstart

### Herms Config (`~/.hermes/config.yaml`)

```yaml
mcp:
  servers:
  sswp:
    command: /mnt/c/Veritas_Lab/sswp-mcp/run_mcp.sh
```

### Claude / Cline (`cline_mcp_settings.json`)

```json
{
  "mcpServers": {
    "sswp": {
      "command": "node",
      "args": ["C:\\\\Veritas_Lab\\\\sswp-mcp\\\\dist\\\\sswp-mcp.cjs"]
    }
  }
}
```

---

## Commands

| Tool | Description |
|---|---|
| `sswp_witness` | Scan, gate-test, adversarial-probe, and seal a repo |
| `sswp_verify` | Verify SHA-256 signature of a `.sswp.json` file |
| `sswp_analyze_deps` | Kimi-powered supply-chain risk analysis |
| `sswp_bulk_witness` | Witness multiple repos sequentially, auto-save to registry |
| `sswp_check_repo` | Quick repo health check |
| `sswp_registry_health` | Show full fleet health board (131 nodes) |
| `sswp_ledger` | Query the tamper-proof audit ledger |
| `sswp_node_search` | FTS5 search across the registry |

---

## CLI

```bash
sswp witness /mnt/c/Veritas_Lab/veritas-topography-map
sswp verify veritas-topography-map.sswp.json
sswp registry list
sswp registry risky 0.3
```

---

## License

VERITAS Software License — see [LICENSE](./LICENSE)
