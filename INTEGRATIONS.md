# SSWP MCP — Agent Integration Guide

SSWP tools are available to any MCP-compatible client via the stdio server.

---

## Hermes

Add to `~/.hermes/config.yaml`:

```yaml
mcp:
  servers:
    sswp:
      command: bash
      args:
        - /mnt/c/Veritas_Lab/sswp-mcp/run_mcp.sh
      env:
        OLLAMA_CLOUD_API_KEY: ${OLLAMA_CLOUD_API_KEY}
```

Restart Hermes or run `/reload-mcp` in-session. All 8 tools (`sswp_witness`, `sswp_verify`, `sswp_bulk_witness`, etc.) appear in the tool registry immediately.

## Claude Desktop / Cline

Add to `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "sswp": {
      "command": "node",
      "args": ["C:\\Veritas_Lab\\sswp-mcp\\dist\\sswp-mcp.cjs"],
      "env": {
        "OLLAMA_CLOUD_API_KEY": "your-key-here"
      }
    }
  }
}
```

Restart Claude Desktop or Cline.

## VS Code Copilot / Cursor / Windsurf

These editors discover MCP servers from the standard Claude/Cline config file. Configure as above and restart the editor.

## Direct CLI

SSWP ships with a standalone CLI — no MCP client required:

```bash
node dist/sswp.cjs witness /path/to/repo
node dist/sswp.cjs verify /path/to/repo/.sswp.json
node dist/sswp.cjs registry health
node dist/sswp.cjs registry ledger 20
```

## Programmatic Access (Node.js)

```javascript
const { spawn } = require('child_process');

const proc = spawn('node', ['dist/sswp-mcp.cjs'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

function call(tool, args) {
  const req = JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'tools/call',
    params: { name: tool, arguments: args }
  });
  proc.stdin.write(req + '\n');
}

call('sswp_witness', { repoPath: '/path/to/repo' });
```
