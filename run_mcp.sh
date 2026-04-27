#!/usr/bin/env bash
# SSWP MCP Server — stdio wrapper for Hermes/Claude/Cline
# Runs the bundled CJS via Node. Zero compile step.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NODE_NO_WARNINGS=1

exec node "${SCRIPT_DIR}/dist/sswp-mcp.cjs"
