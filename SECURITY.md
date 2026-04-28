# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x (latest) | Yes |
| < 2.0 | No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/VrtxOmega/sswp-mcp/security/advisories/new).

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept code
- The version(s) affected
- Any suggested mitigations

## Supply Chain

SSWP is a witness tool — it does not execute arbitrary code from witnessed projects. The adversarial probes are read-only analysis. The server runs locally with no network egress except optional Kimi K2 reasoning (requires `OLLAMA_CLOUD_API_KEY`).

## Scope

The SSWP MCP server's security surface is limited to:

- **Local filesystem reads** — scanning `node_modules` and project files for analysis
- **Local SQLite writes** — the registry database (`~/.sswp_registry.sqlite`)
- **Optional Kimi API calls** — when `OLLAMA_CLOUD_API_KEY` is configured

**Out of scope:** SSWP does not execute project code, modify witnessed repos, or expose the registry over a network endpoint. It is a local-only, stdio-based MCP server.
