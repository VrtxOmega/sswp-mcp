FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_NO_WARNINGS=1

# Install Node 22 + pnpm
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g pnpm@10.14.0 && \
    node --version && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app

# Clone the repo
RUN git clone https://github.com/VrtxOmega/sswp-mcp.git . && \
    git checkout master

# Install deps (better-sqlite3 compiles native addon)
RUN pnpm config set store-dir /tmp/pnpm-store && \
    pnpm approve-builds --global better-sqlite3 && \
    pnpm install && \
    pnpm run build

# Verify the MCP server loads
RUN node -e "require('./dist/sswp.cjs')" 2>&1 || true

EXPOSE 3000

CMD ["node", "dist/sswp.cjs"]
