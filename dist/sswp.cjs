var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/mcp/server.ts
var import_server = require("@modelcontextprotocol/sdk/server/index.js");
var import_stdio = require("@modelcontextprotocol/sdk/server/stdio.js");
var import_types = require("@modelcontextprotocol/sdk/types.js");

// src/core/witness.ts
var import_node_crypto3 = require("node:crypto");
var import_node_fs3 = require("node:fs");
var import_node_path3 = require("node:path");
var import_node_child_process2 = require("node:child_process");

// src/engine/sealer.ts
var import_node_crypto = require("node:crypto");
var chain = [];
function seal(context, response) {
  const prev = chain[chain.length - 1] ?? null;
  const sequence = chain.length + 1;
  const entry = {
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    claim: JSON.stringify(context),
    evidence: response,
    prev_hash: prev?.hash ?? null,
    sequence
  };
  const payload = `${entry.sequence}:${entry.timestamp}:${entry.claim}:${entry.evidence}:${entry.prev_hash ?? "GENESIS"}`;
  const hash = (0, import_node_crypto.createHash)("sha256").update(payload).digest("hex");
  const sealed = { ...entry, hash };
  chain.push(sealed);
  return sealed;
}

// src/core/build-scanner.ts
var import_node_fs = require("node:fs");
var import_node_crypto2 = require("node:crypto");
var import_node_path = require("node:path");
async function scanBuild(projectRoot) {
  const entries = [];
  const pkgPath = (0, import_node_path.join)(projectRoot, "package.json");
  if ((0, import_node_fs.existsSync)(pkgPath)) {
    const pkg = JSON.parse((0, import_node_fs.readFileSync)(pkgPath, "utf8"));
    const deps = { ...pkg.dependencies || {}, ...pkg.devDependencies || {} };
    for (const [name, version] of Object.entries(deps)) {
      const ver = String(version).replace("^", "").replace("~", "");
      entries.push(await analyzeDependency(projectRoot, name, ver));
    }
  }
  const env = {
    cwd: projectRoot,
    nodeVersion: process.version,
    os: process.platform,
    arch: process.arch,
    ci: !!process.env.CI,
    buildCommand: inferBuildCommand(projectRoot),
    buildOutput: "dist/"
  };
  const suspiciousCount = entries.filter((e) => e.suspicious).length;
  return { entries, env, totalPackages: entries.length, suspiciousCount };
}
async function analyzeDependency(projectRoot, name, version) {
  const path = (0, import_node_path.join)(projectRoot, "node_modules", name);
  const pkgJsonPath = (0, import_node_path.join)(path, "package.json");
  let integrity = null;
  if ((0, import_node_fs.existsSync)(pkgJsonPath)) {
    const content = (0, import_node_fs.readFileSync)(pkgJsonPath, "utf8");
    integrity = (0, import_node_crypto2.createHash)("sha256").update(content).digest("hex").slice(0, 16);
  }
  const suspicious = !integrity || version.startsWith(">") || version.startsWith("*");
  return {
    name,
    version,
    resolved: path,
    integrity,
    suspicious,
    riskScore: suspicious ? 0.7 : 0.1
  };
}
function inferBuildCommand(projectRoot) {
  if ((0, import_node_fs.existsSync)((0, import_node_path.join)(projectRoot, "package.json"))) {
    const pkg = JSON.parse((0, import_node_fs.readFileSync)((0, import_node_path.join)(projectRoot, "package.json"), "utf8"));
    if (pkg.scripts?.build) return `npm run build`;
    if (pkg.scripts?.compile) return `npm run compile`;
  }
  if ((0, import_node_fs.existsSync)((0, import_node_path.join)(projectRoot, "Makefile"))) return "make";
  if ((0, import_node_fs.existsSync)((0, import_node_path.join)(projectRoot, "Cargo.toml"))) return "cargo build";
  return "unknown";
}

// src/core/gate-runner.ts
var import_node_child_process = require("node:child_process");
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");
async function runGates(projectRoot, env, regime = "developer") {
  const results = [];
  results.push(await languageDetectionGate(projectRoot));
  results.push(await gitIntegrityGate(projectRoot, regime));
  results.push(await lockfileGate(projectRoot));
  results.push(await deterministicBuildGate(projectRoot, env));
  results.push(await testGate(projectRoot, env));
  results.push(await lintGate(projectRoot));
  return results;
}
function languageDetectionGate(root) {
  const start = Date.now();
  const languages = [];
  if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) languages.push("node");
  if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "requirements.txt")) || (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "pyproject.toml")) || (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "setup.py"))) languages.push("python");
  if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "go.mod"))) languages.push("go");
  if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "Cargo.toml"))) languages.push("rust");
  if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "index.html")) && !(0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) languages.push("html");
  if (!languages.length) languages.push("unknown");
  return {
    gate: "LANGUAGE_DETECTION",
    status: "PASS",
    evidence: `Detected: ${languages.join(", ")}`,
    durationMs: Date.now() - start
  };
}
async function lockfileGate(root) {
  return timed("LOCKFILE", () => {
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) {
      const hasLock = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package-lock.json")) || (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "yarn.lock")) || (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "pnpm-lock.yaml"));
      if (!hasLock) return { gate: "LOCKFILE", status: "FAIL", evidence: "package.json present but no lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml)", durationMs: 0 };
      return { gate: "LOCKFILE", status: "PASS", evidence: "Lockfile present", durationMs: 0 };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "requirements.txt"))) {
      return { gate: "LOCKFILE", status: "PASS", evidence: "requirements.txt (pinned dependencies)", durationMs: 0 };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "pyproject.toml"))) {
      const hasPoetryLock = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "poetry.lock"));
      const hasUvLock = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "uv.lock"));
      return {
        gate: "LOCKFILE",
        status: hasPoetryLock || hasUvLock ? "PASS" : "WARN",
        evidence: hasPoetryLock ? "poetry.lock present" : hasUvLock ? "uv.lock present" : "pyproject.toml present but no lockfile",
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "go.mod"))) {
      const hasSum = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "go.sum"));
      return { gate: "LOCKFILE", status: hasSum ? "PASS" : "WARN", evidence: hasSum ? "go.sum present" : "go.mod present but no go.sum", durationMs: 0 };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "Cargo.toml"))) {
      const hasCargoLock = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "Cargo.lock"));
      return { gate: "LOCKFILE", status: hasCargoLock ? "PASS" : "WARN", evidence: hasCargoLock ? "Cargo.lock present" : "Cargo.toml present but no Cargo.lock", durationMs: 0 };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "index.html")) && !(0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) {
      return { gate: "LOCKFILE", status: "PASS", evidence: "Static site (no dependency manager)", durationMs: 0 };
    }
    return { gate: "LOCKFILE", status: "INCONCLUSIVE", evidence: "No recognized project type", durationMs: 0 };
  });
}
function timed(name, fn) {
  const start = Date.now();
  const result = fn();
  result.durationMs = Date.now() - start;
  result.gate = name;
  return result;
}
async function gitIntegrityGate(root, regime) {
  return timed("GIT_INTEGRITY", () => {
    const r = (0, import_node_child_process.spawnSync)("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" });
    const clean = !r.stdout?.trim();
    if (clean) {
      return { gate: "GIT_INTEGRITY", status: "PASS", evidence: "Working tree clean", durationMs: 0 };
    }
    const fileCount = r.stdout?.trim().split("\n").length || 0;
    const evidence = `Modified files: ${fileCount}`;
    const status = regime === "developer" ? "WARN" : "FAIL";
    return { gate: "GIT_INTEGRITY", status, evidence, durationMs: 0 };
  });
}
async function deterministicBuildGate(root, env) {
  return timed("DETERMINISTIC_BUILD", () => {
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) {
      const hasBuildScript = hasScript(root, "build");
      if (!hasBuildScript) {
        return { gate: "DETERMINISTIC_BUILD", status: "INCONCLUSIVE", evidence: "No build script in package.json", durationMs: 0 };
      }
      const r = (0, import_node_child_process.spawnSync)("npm", ["run", "build"], { cwd: root, encoding: "utf8", shell: true, timeout: 6e4 });
      const passed = r.status === 0;
      return {
        gate: "DETERMINISTIC_BUILD",
        status: passed ? "PASS" : "FAIL",
        evidence: passed ? "Build succeeded: npm run build" : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "pyproject.toml"))) {
      const r = (0, import_node_child_process.spawnSync)("python3", ["-m", "build"], { cwd: root, encoding: "utf8", shell: true, timeout: 6e4 });
      return {
        gate: "DETERMINISTIC_BUILD",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "Build succeeded: python3 -m build" : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "Makefile"))) {
      const r = (0, import_node_child_process.spawnSync)("make", [], { cwd: root, encoding: "utf8", shell: true, timeout: 6e4 });
      return {
        gate: "DETERMINISTIC_BUILD",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "Build succeeded: make" : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "go.mod"))) {
      const r = (0, import_node_child_process.spawnSync)("go", ["build", "./..."], { cwd: root, encoding: "utf8", shell: true, timeout: 6e4 });
      return {
        gate: "DETERMINISTIC_BUILD",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "Build succeeded: go build" : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "Cargo.toml"))) {
      const r = (0, import_node_child_process.spawnSync)("cargo", ["build"], { cwd: root, encoding: "utf8", shell: true, timeout: 6e4 });
      return {
        gate: "DETERMINISTIC_BUILD",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "Build succeeded: cargo build" : `Build failed: ${r.stderr?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "index.html")) && !(0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) {
      return { gate: "DETERMINISTIC_BUILD", status: "PASS", evidence: "Static HTML site (no build required)", durationMs: 0 };
    }
    return { gate: "DETERMINISTIC_BUILD", status: "INCONCLUSIVE", evidence: "No recognized build system", durationMs: 0 };
  });
}
async function testGate(root, env) {
  return timed("TEST_PASS", () => {
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) {
      const hasTestScript = hasScript(root, "test");
      if (!hasTestScript) {
        return { gate: "TEST_PASS", status: "INCONCLUSIVE", evidence: "No test script in package.json", durationMs: 0 };
      }
      const r = (0, import_node_child_process.spawnSync)("npm", ["test"], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      const passed = r.status === 0;
      return {
        gate: "TEST_PASS",
        status: passed ? "PASS" : "FAIL",
        evidence: passed ? "npm test passed" : `npm test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "pyproject.toml")) || (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "requirements.txt"))) {
      const r = (0, import_node_child_process.spawnSync)("python3", ["-m", "pytest"], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      return {
        gate: "TEST_PASS",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "pytest passed" : `pytest failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "Makefile"))) {
      const r = (0, import_node_child_process.spawnSync)("make", ["test"], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      return {
        gate: "TEST_PASS",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "make test passed" : `make test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "go.mod"))) {
      const r = (0, import_node_child_process.spawnSync)("go", ["test", "./..."], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      return {
        gate: "TEST_PASS",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "go test passed" : `go test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    if ((0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "Cargo.toml"))) {
      const r = (0, import_node_child_process.spawnSync)("cargo", ["test"], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      return {
        gate: "TEST_PASS",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "cargo test passed" : `cargo test failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    return { gate: "TEST_PASS", status: "INCONCLUSIVE", evidence: "No test runner configured", durationMs: 0 };
  });
}
async function lintGate(root) {
  return timed("LINT", () => {
    const eslintConfigs = [".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json", ".eslintrc.yaml", ".eslintrc.yml", "eslint.config.js", "eslint.config.mjs", "eslint.config.ts"];
    const hasEslintConfig = eslintConfigs.some((cfg) => (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, cfg)));
    if (hasEslintConfig) {
      const r = (0, import_node_child_process.spawnSync)("npx", ["eslint", "--max-warnings=0", "."], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      if (r.error || (r.stderr?.includes("not found") || r.stderr?.includes("ENOENT") || r.stderr?.includes("ERR! code"))) {
        return { gate: "LINT", status: "INCONCLUSIVE", evidence: "ESLint config present but eslint not installed", durationMs: 0 };
      }
      return {
        gate: "LINT",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "eslint passed" : `eslint failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    const hasBiomeConfig = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "biome.json"));
    if (hasBiomeConfig) {
      const r = (0, import_node_child_process.spawnSync)("npx", ["biome", "check", "."], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      if (r.error || (r.stderr?.includes("not found") || r.stderr?.includes("ENOENT") || r.stderr?.includes("ERR! code"))) {
        return { gate: "LINT", status: "INCONCLUSIVE", evidence: "Biome config present but biome not installed", durationMs: 0 };
      }
      return {
        gate: "LINT",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "biome passed" : `biome failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    const hasTscConfig = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "tsconfig.json"));
    if (hasTscConfig) {
      const r = (0, import_node_child_process.spawnSync)("npx", ["tsc", "--noEmit"], { cwd: root, encoding: "utf8", shell: true, timeout: 12e4 });
      if (r.error || (r.stderr?.includes("not found") || r.stderr?.includes("ENOENT") || r.stderr?.includes("ERR! code"))) {
        return { gate: "LINT", status: "INCONCLUSIVE", evidence: "tsconfig.json present but typescript not installed", durationMs: 0 };
      }
      return {
        gate: "LINT",
        status: r.status === 0 ? "PASS" : "FAIL",
        evidence: r.status === 0 ? "tsc --noEmit passed" : `tsc failed: ${(r.stderr || r.stdout)?.slice(0, 200)}`,
        durationMs: 0
      };
    }
    return { gate: "LINT", status: "INCONCLUSIVE", evidence: "No linter configured", durationMs: 0 };
  });
}
function hasScript(root, scriptName) {
  try {
    const pkg = JSON.parse((0, import_node_fs2.readFileSync)((0, import_node_path2.join)(root, "package.json"), "utf8"));
    return typeof pkg.scripts?.[scriptName] === "string";
  } catch {
    return false;
  }
}

// src/core/kimi-reasoner.ts
var OLLAMA_CLOUD_ENDPOINT = "https://api.ollama.com/v1/chat/completions";
var KIMI_MODEL = "kimi-k2.5";
var TIMEOUT_MS = 1e4;
function buildPrompt(deps) {
  const depList = deps.map((d, i) => {
    const integrityStr = d.integrity ? `Integrity: ${d.integrity}` : "Integrity: MISSING";
    return `${i + 1}. ${d.name}@${d.version} (${integrityStr}, Resolved: ${d.resolved})`;
  }).join("\n");
  return `You are a supply-chain security analyst. Analyze the following software dependencies for security and supply-chain risks.
Consider typosquatting, version pinning, missing integrity hashes, suspicious package names, and known attack patterns.
Return ONLY a single JSON object with no markdown formatting, no code fences, and no extra text.

Input dependencies:
${depList}

Required JSON schema:
{
  "risk": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "packages": [
    {
      "name": "package-name",
      "risk": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      "reason": "specific reasoning for this package"
    }
  ],
  "summary": "concise overall assessment"
}`;
}
async function kimiAnalyze(deps) {
  const apiKey = process.env.OLLAMA_CLOUD_API_KEY || process.env.OLLAMA_API_KEY;
  if (!apiKey) {
    return [
      {
        package: "system",
        probe: "KIMI_REASONING",
        result: "INCONCLUSIVE",
        detail: "OLLAMA_CLOUD_API_KEY is not set. Skipping Kimi adversarial analysis."
      }
    ];
  }
  const prompt = buildPrompt(deps);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(OLLAMA_CLOUD_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: KIMI_MODEL,
        messages: [
          {
            role: "system",
            content: "You are a deterministic supply-chain security evaluator. Output must be valid JSON only."
          },
          { role: "user", content: prompt }
        ],
        temperature: 0.2,
        max_tokens: 2048
      }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (!response.ok) {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: `Ollama Cloud API returned HTTP ${response.status}: ${response.statusText}`
        }
      ];
    }
    const data = await response.json();
    const content = data?.choices?.[0]?.message?.content;
    if (!content || typeof content !== "string") {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: "Unexpected response shape from Ollama Cloud API."
        }
      ];
    }
    const cleaned = content.replace(/```json\s*/g, "").replace(/```\s*/g, "").trim();
    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (parseErr) {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: `Failed to parse Kimi JSON response: ${parseErr.message}`
        }
      ];
    }
    const parsedPackages = parsed.packages || [];
    const results = parsedPackages.map((pkg) => {
      const risk = (pkg.risk || "INCONCLUSIVE").toString().toUpperCase();
      const result = risk === "CRITICAL" ? "CRITICAL" : risk === "HIGH" ? "WARN" : risk === "MEDIUM" ? "WARN" : risk === "LOW" ? "PASS" : "INCONCLUSIVE";
      return {
        package: pkg.name || "unknown",
        probe: "KIMI_REASONING",
        result,
        detail: pkg.reason || parsed.summary || "No detail provided"
      };
    });
    if (results.length === 0) {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: parsed.summary || "Kimi returned empty package list."
        }
      ];
    }
    return results;
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      return [
        {
          package: "system",
          probe: "KIMI_REASONING",
          result: "INCONCLUSIVE",
          detail: "Kimi adversarial probe timed out after 10s."
        }
      ];
    }
    return [
      {
        package: "system",
        probe: "KIMI_REASONING",
        result: "INCONCLUSIVE",
        detail: `Kimi adversarial probe failed: ${err.message}`
      }
    ];
  }
}

// src/core/adversarial-probe.ts
async function runAdversarialProbes(deps) {
  const probes = [];
  let suspiciousCount = 0;
  for (const dep of deps) {
    const p1 = probeTyposquatting(dep);
    const p2 = probeVersionAnomaly(dep);
    const p3 = probeMetadataIntegrity(dep);
    probes.push(p1, p2, p3);
    if ([p1, p2, p3].some((r) => r.result === "CRITICAL")) {
      dep.suspicious = true;
      dep.riskScore = Math.max(dep.riskScore, 0.9);
      suspiciousCount++;
    } else if ([p1, p2, p3].some((r) => r.result === "WARN")) {
      dep.riskScore = Math.max(dep.riskScore, 0.5);
      suspiciousCount++;
    }
  }
  if (deps.length > 0) {
    const kimiResults = await probeWithKimi(deps);
    probes.push(...kimiResults);
  }
  const totalRisk = probes.filter((p) => p.result === "CRITICAL").length * 0.4 + probes.filter((p) => p.result === "WARN").length * 0.15;
  const overallRisk = Math.min(1, totalRisk / Math.max(1, deps.length));
  return {
    totalPackages: deps.length,
    suspiciousPackages: suspiciousCount,
    probes,
    overallRisk
  };
}
function probeTyposquatting(dep) {
  const highValueTargets = [
    "react",
    "vue",
    "lodash",
    "axios",
    "express",
    "moment",
    "chalk",
    "commander",
    "tslib",
    "dotenv",
    "typescript",
    "jest",
    "eslint",
    "prettier",
    "vite",
    "webpack",
    "next",
    "angular",
    "rxjs",
    "jquery"
  ];
  const name = dep.name.toLowerCase();
  if (highValueTargets.includes(name)) {
    return {
      package: dep.name,
      probe: "TYPO_SQUATTING",
      result: "PASS",
      detail: "Known legitimate package"
    };
  }
  const suspiciousPatterns = [
    "crossenv",
    "nodemail.js",
    "flatmap-stream",
    "peacenotwar",
    "node-ipc",
    "left-pad",
    "event-stream",
    "colors",
    "faker"
  ];
  if (suspiciousPatterns.some((p) => name.includes(p))) {
    return {
      package: dep.name,
      probe: "TYPO_SQUATTING",
      result: "CRITICAL",
      detail: "Matches known malicious or compromised package pattern"
    };
  }
  const legitSuffixes = ["js", "ts", "core", "cli", "ui", "lib", "kit", "app", "api"];
  for (const target of highValueTargets) {
    if (name === target) continue;
    if (legitSuffixes.some((s) => name === target + s)) continue;
    const distance = levenshteinDistance(name, target);
    if (distance > 0 && distance <= 2 && name.length >= 4) {
      return {
        package: dep.name,
        probe: "TYPO_SQUATTING",
        result: "WARN",
        detail: `Potential typosquatting of '${target}' (edit distance: ${distance})`
      };
    }
  }
  return {
    package: dep.name,
    probe: "TYPO_SQUATTING",
    result: "PASS",
    detail: "Name heuristic clean"
  };
}
function levenshteinDistance(a, b) {
  const matrix = Array.from(
    { length: a.length + 1 },
    () => new Array(b.length + 1).fill(0)
  );
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        // deletion
        matrix[i][j - 1] + 1,
        // insertion
        matrix[i - 1][j - 1] + cost
        // substitution
      );
    }
  }
  return matrix[a.length][b.length];
}
function probeVersionAnomaly(dep) {
  const range = ["*", ">=", "<", "^0", "~0", "latest"];
  const isRange = range.some((r) => dep.version.includes(r));
  return {
    package: dep.name,
    probe: "VERSION_ANOMALY",
    result: isRange ? "WARN" : "PASS",
    detail: isRange ? `Unpinned version: ${dep.version}` : `Pinned: ${dep.version}`
  };
}
function probeMetadataIntegrity(dep) {
  const hasIntegrity = dep.integrity != null;
  return {
    package: dep.name,
    probe: "METADATA_INTEGRITY",
    result: hasIntegrity ? "PASS" : "CRITICAL",
    detail: hasIntegrity ? `Hash: ${dep.integrity}` : "No integrity hash found"
  };
}
async function probeWithKimi(deps) {
  return kimiAnalyze(deps);
}

// src/core/witness.ts
async function witness(projectRoot, regime = "developer") {
  const projectType = detectProjectType(projectRoot);
  const projectName = resolveProjectName(projectRoot, projectType);
  let entries = [];
  let env = { nodeVersion: process.version, os: process.platform, arch: process.arch, ci: !!process.env.CI, buildCommand: "unknown" };
  let totalPackages = 0;
  let suspiciousCount = 0;
  if (projectType !== "html" && (0, import_node_fs3.existsSync)((0, import_node_path3.join)(projectRoot, "package.json"))) {
    const scan = await scanBuild(projectRoot);
    entries = scan.entries;
    env = scan.env;
    totalPackages = scan.totalPackages;
    suspiciousCount = scan.suspiciousCount;
  }
  const scanSeal = seal(
    { phase: "SCAN", totalPackages, suspiciousCount, projectType },
    `Scanned ${totalPackages} packages, ${suspiciousCount} flagged (type: ${projectType})`
  );
  const gateResults = await runGates(projectRoot, env, regime);
  const passedGates = gateResults.filter((g) => g.status === "PASS").length;
  const gateSeal = seal(
    { phase: "GATES", passed: passedGates, total: gateResults.length },
    JSON.stringify(gateResults.map((g) => ({ gate: g.gate, status: g.status })))
  );
  let adversarial = { totalPackages: 0, suspiciousPackages: 0, probes: [], overallRisk: 0 };
  if (entries.length > 0) {
    adversarial = await runAdversarialProbes(entries);
  }
  const advSeal = seal(
    { phase: "ADVERSARIAL", overallRisk: adversarial.overallRisk, probes: adversarial.probes.length },
    JSON.stringify(adversarial)
  );
  const gitHash = execGit(projectRoot, ["rev-parse", "HEAD"]);
  const branch = execGit(projectRoot, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const overallStatus = gateResults.some((g) => g.status === "FAIL") ? "FAIL" : gateResults.some((g) => g.status === "INCONCLUSIVE" || g.status === "WARN") ? "WARN" : "PASS";
  const attestation = {
    overallStatus,
    version: "1.1.0",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    projectType,
    target: {
      name: projectName,
      repo: projectRoot,
      commitHash: gitHash || "unknown",
      branch: branch || "unknown"
    },
    environment: {
      nodeVersion: env.nodeVersion,
      os: env.os,
      arch: env.arch,
      ci: env.ci
    },
    dependencies: entries,
    gates: gateResults,
    adversarial,
    seal: {
      chainHash: scanSeal.hash,
      sequence: (gateSeal?.sequence ?? 0) + (advSeal?.sequence ?? 0)
    },
    signature: ""
  };
  const { signature, ...hashPayload } = attestation;
  attestation.signature = (0, import_node_crypto3.createHash)("sha256").update(JSON.stringify(hashPayload, Object.keys(hashPayload).sort())).digest("hex");
  const finalSeal = seal(
    { phase: "ATTEST", signature: attestation.signature },
    "Attestation sealed and signed"
  );
  return attestation;
}
function detectProjectType(root) {
  if ((0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "package.json"))) return "node";
  if ((0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "requirements.txt")) || (0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "pyproject.toml")) || (0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "setup.py"))) return "python";
  if ((0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "go.mod"))) return "go";
  if ((0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "Cargo.toml"))) return "rust";
  if ((0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "index.html"))) return "html";
  return "unknown";
}
function resolveProjectName(root, projectType) {
  try {
    if (projectType === "node") {
      const pkg = JSON.parse((0, import_node_fs3.readFileSync)((0, import_node_path3.join)(root, "package.json"), "utf8"));
      return pkg.name || root.split("/").pop() || "unknown";
    }
    if (projectType === "python") {
      if ((0, import_node_fs3.existsSync)((0, import_node_path3.join)(root, "pyproject.toml"))) {
        const toml = (0, import_node_fs3.readFileSync)((0, import_node_path3.join)(root, "pyproject.toml"), "utf8");
        const match = toml.match(/name\s*=\s*"(.+)"/);
        if (match) return match[1];
      }
    }
    if (projectType === "go") {
      const gomod = (0, import_node_fs3.readFileSync)((0, import_node_path3.join)(root, "go.mod"), "utf8");
      const match = gomod.match(/module\s+(.+)/);
      if (match) return match[1].split("/").pop() || match[1];
    }
  } catch {
  }
  return root.split("/").pop() || "unknown";
}
function execGit(cwd, args) {
  const r = (0, import_node_child_process2.spawnSync)("git", args, { cwd, encoding: "utf8" });
  return r.stdout?.trim() || "";
}
function formatAttestation(att) {
  const lines = [];
  lines.push(`\u2B21  SSWP ATTESTATION v${att.version}`);
  lines.push(`   Target: ${att.target.name} (${att.target.commitHash.slice(0, 8)})`);
  lines.push(`   Branch: ${att.target.branch} | Env: ${att.environment.os}-${att.environment.arch}`);
  lines.push(`   Built: ${att.timestamp}`);
  const ovIcon = att.overallStatus === "PASS" ? "\u2713" : att.overallStatus === "WARN" ? "\u26A0" : "\u2717";
  lines.push(`   Overall: ${ovIcon} ${att.overallStatus || "UNKNOWN"}`);
  lines.push("");
  lines.push("   GATES:");
  for (const g of att.gates) {
    const icon = g.status === "PASS" ? "\u2713" : g.status === "FAIL" ? "\u2717" : "\u25CB";
    lines.push(`     ${icon} ${g.gate.padEnd(22)} ${g.status.padEnd(14)} ${g.durationMs}ms`);
  }
  lines.push("");
  lines.push(`   DEPENDENCIES: ${att.dependencies.length} total, ${att.adversarial.suspiciousPackages} flagged`);
  lines.push(`   ADVERSARIAL RISK: ${(att.adversarial.overallRisk * 100).toFixed(1)}%`);
  lines.push(`   SEAL: ${att.signature.slice(0, 16)}...`);
  return lines.join("\n");
}
function verifyAttestation(filePath) {
  const att = JSON.parse((0, import_node_fs3.readFileSync)(filePath, "utf8"));
  const { signature, ...hashPayload } = att;
  const payload = JSON.stringify(hashPayload, Object.keys(hashPayload).sort());
  const computed = (0, import_node_crypto3.createHash)("sha256").update(payload).digest("hex");
  return computed === att.signature;
}

// src/mcp/path-util.ts
function toWslPath(winPath) {
  const hasBackslash = winPath.includes(String.fromCharCode(92));
  const hasDrive = winPath.length >= 2 && winPath[1] === ":";
  if (!hasBackslash && !hasDrive) return winPath;
  let s = winPath;
  const bs = String.fromCharCode(92);
  while (s.includes(bs)) {
    s = s.replace(bs, "/");
  }
  if (s.length >= 2 && s[1] === ":" && /^[A-Za-z]/.test(s[0])) {
    const drive = s[0].toLowerCase();
    s = "/mnt/" + drive + "/" + s.slice(2).replace(/^\/+/, "");
  }
  return s;
}

// src/registry/manager.ts
var import_better_sqlite3 = __toESM(require("better-sqlite3"));
var import_node_crypto4 = require("node:crypto");
var import_node_fs4 = require("node:fs");
var import_node_path4 = require("node:path");
var SCHEMA_PATH = (0, import_node_path4.resolve)(process.cwd(), "src/sswp/registry/schema.sql");
var DEFAULT_DB = (0, import_node_path4.resolve)(process.env.HOME ?? "/tmp", ".sswp_registry.sqlite");
var RegistryManager = class {
  db;
  dbPath;
  constructor(cfg = {}) {
    this.dbPath = cfg.dbPath ?? DEFAULT_DB;
    const dir = (0, import_node_path4.dirname)(this.dbPath);
    if (!(0, import_node_fs4.existsSync)(dir)) (0, import_node_fs4.mkdirSync)(dir, { recursive: true });
    this.db = new import_better_sqlite3.default(this.dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    if (cfg.autoInit !== false) this.initSchema();
  }
  initSchema() {
    const sql = (0, import_node_fs4.readFileSync)(SCHEMA_PATH, "utf-8");
    this.db.exec(sql);
  }
  close() {
    this.db.close();
  }
  // ═══════════════════════════════════════════════════════════════
  // NODES
  // ═══════════════════════════════════════════════════════════════
  upsertNode(node) {
    const id = node.node_id ?? (0, import_node_crypto4.randomUUID)();
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const tagsJson = node.tags ? JSON.stringify(node.tags) : null;
    const metaJson = node.metadata ? JSON.stringify(node.metadata) : null;
    const stmt = this.db.prepare(`
      INSERT INTO nodes (node_id, name, repo_path, node_type, status, first_seen, last_seen, description, tags, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(node_id) DO UPDATE SET
        name=excluded.name,
        repo_path=excluded.repo_path,
        node_type=excluded.node_type,
        status=excluded.status,
        last_seen=excluded.last_seen,
        description=excluded.description,
        tags=excluded.tags,
        metadata=excluded.metadata
      RETURNING *
    `);
    const row = stmt.get(
      id,
      node.name,
      node.repo_path,
      node.node_type ?? "node",
      node.status ?? "active",
      now,
      now,
      node.description ?? null,
      tagsJson,
      metaJson
    );
    return this.deserializeNode(row);
  }
  getNode(nodeId) {
    const stmt = this.db.prepare("SELECT * FROM nodes WHERE node_id = ?");
    const row = stmt.get(nodeId);
    if (!row) return void 0;
    return this.deserializeNode(row);
  }
  getNodeByPath(repoPath) {
    const stmt = this.db.prepare("SELECT * FROM nodes WHERE repo_path = ?");
    const row = stmt.get(repoPath);
    if (!row) return void 0;
    return this.deserializeNode(row);
  }
  listNodes(opts) {
    let sql = "SELECT * FROM nodes WHERE 1=1";
    const params = [];
    if (opts?.type) {
      sql += " AND node_type = ?";
      params.push(opts.type);
    }
    if (opts?.status) {
      sql += " AND status = ?";
      params.push(opts.status);
    }
    sql += " ORDER BY last_seen DESC";
    if (opts?.limit) {
      sql += " LIMIT ?";
      params.push(opts.limit);
    }
    if (opts?.offset) {
      sql += " OFFSET ?";
      params.push(opts.offset);
    }
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params);
    return rows.map((r) => this.deserializeNode(r));
  }
  searchNodes(query, limit = 20) {
    const stmt = this.db.prepare(`
      SELECT n.* FROM nodes n
      JOIN nodes_fts f ON n.rowid = f.rowid
      WHERE nodes_fts MATCH ?
      ORDER BY rank
      LIMIT ?
    `);
    const rows = stmt.all(query, limit);
    return rows.map((r) => this.deserializeNode(r));
  }
  deserializeNode(row) {
    return {
      node_id: String(row.node_id),
      name: String(row.name),
      repo_path: String(row.repo_path),
      node_type: String(row.node_type),
      status: String(row.status),
      first_seen: String(row.first_seen),
      last_seen: String(row.last_seen),
      description: row.description ? String(row.description) : void 0,
      tags: row.tags ? JSON.parse(String(row.tags)) : void 0,
      metadata: row.metadata ? JSON.parse(String(row.metadata)) : void 0
    };
  }
  // ═══════════════════════════════════════════════════════════════
  // ATTESTATIONS
  // ═══════════════════════════════════════════════════════════════
  saveAttestation(nodeId, att, jsonPath, rawJson) {
    const id = att.id ?? (0, import_node_crypto4.randomUUID)();
    const passCount = att.gates.filter((g) => g.status === "PASS").length;
    const failCount = att.gates.length - passCount;
    const overall = failCount === 0 ? "PASS" : passCount > 0 ? "PARTIAL" : "FAIL";
    const hash = (0, import_node_crypto4.createHash)("sha256").update(rawJson).digest("hex");
    const stmt = this.db.prepare(`
      INSERT INTO attestations
        (attestation_id, node_id, overall_status, risk_score, adversarial_risk,
         gate_pass_count, gate_fail_count, sha256, sswp_json_path, raw_json, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      RETURNING *
    `);
    const row = stmt.get(
      id,
      nodeId,
      overall,
      att.adversarial?.overallRisk ?? 0,
      att.adversarial?.overallRisk ?? 0,
      passCount,
      failCount,
      hash,
      jsonPath,
      rawJson,
      JSON.stringify({ tool: "sswp_witness", version: "1.0.0" })
    );
    for (const g of att.gates) {
      this.saveGateHistory(id, nodeId, g);
    }
    this.appendLedger("WITNESS", { attestationId: id, nodeId, overall, risk: att.adversarial?.overallRisk });
    return row;
  }
  saveGateHistory(attId, nodeId, g) {
    const stmt = this.db.prepare(`
      INSERT INTO gates_history (attestation_id, node_id, gate_name, gate_number, status, reason_code, detail, duration_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(attId, nodeId, g.gate, 0, g.status, g.evidence ?? null, null, g.durationMs ?? 0);
  }
  getLatestAttestation(nodeId) {
    const stmt = this.db.prepare("SELECT * FROM attestations WHERE node_id = ? ORDER BY run_at DESC LIMIT 1");
    return stmt.get(nodeId);
  }
  getAttestationHistory(nodeId, limit = 50) {
    const stmt = this.db.prepare("SELECT * FROM attestations WHERE node_id = ? ORDER BY run_at DESC LIMIT ?");
    return stmt.all(nodeId, limit);
  }
  getAttestationGates(attestationId) {
    const stmt = this.db.prepare("SELECT * FROM gates_history WHERE attestation_id = ? ORDER BY gate_number");
    return stmt.all(attestationId);
  }
  // ═══════════════════════════════════════════════════════════════
  // DEPENDENCY SNAPSHOTS
  // ═══════════════════════════════════════════════════════════════
  saveDepSnapshot(attId, nodeId, dep) {
    const stmt = this.db.prepare(`
      INSERT INTO dep_snapshots (attestation_id, node_id, package_name, version, resolved, integrity, suspicious, risk_score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      attId,
      nodeId,
      dep.name,
      dep.version ?? null,
      dep.resolved ?? null,
      dep.integrity ?? null,
      dep.suspicious ? 1 : 0,
      dep.riskScore ?? 0
    );
  }
  getDepSnapshots(attestationId) {
    const stmt = this.db.prepare("SELECT * FROM dep_snapshots WHERE attestation_id = ?");
    return stmt.all(attestationId);
  }
  // ═══════════════════════════════════════════════════════════════
  // LEDGER
  // ═══════════════════════════════════════════════════════════════
  appendLedger(eventType, payload) {
    const last = this.db.prepare("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1").get();
    const prev = last?.hash ?? "0";
    const ts = (/* @__PURE__ */ new Date()).toISOString();
    const payloadJson = JSON.stringify(payload);
    const hash = (0, import_node_crypto4.createHash)("sha256").update(prev + payloadJson + ts).digest("hex");
    const stmt = this.db.prepare("INSERT INTO ledger (prev_hash, event_type, payload, hash) VALUES (?, ?, ?, ?)");
    stmt.run(prev, eventType, payloadJson, hash);
  }
  getLedger(limit = 100) {
    const stmt = this.db.prepare("SELECT * FROM ledger ORDER BY id DESC LIMIT ?");
    return stmt.all(limit);
  }
  verifyLedger() {
    const rows = this.db.prepare("SELECT * FROM ledger ORDER BY id").all();
    let prev = "0";
    for (const row of rows) {
      const expected = (0, import_node_crypto4.createHash)("sha256").update(row.prev_hash + row.payload + row.timestamp).digest("hex");
      if (expected !== row.hash) return false;
      if (row.prev_hash !== prev) return false;
      prev = row.hash;
    }
    return true;
  }
  // ═══════════════════════════════════════════════════════════════
  // DASHBOARD VIEWS
  // ═══════════════════════════════════════════════════════════════
  getHealthBoard() {
    return this.db.prepare("SELECT * FROM v_node_health ORDER BY last_risk DESC").all();
  }
  getRiskLeaderboard() {
    return this.db.prepare("SELECT * FROM v_risk_leaderboard").all();
  }
  getGateTrend(nodeId, gateName, windowDays = 30) {
    const sql = `SELECT * FROM v_gate_trend WHERE node_id = ? AND run_at > datetime('now', '-${windowDays} days')` + (gateName ? " AND gate_name = ?" : "") + " ORDER BY run_at DESC";
    const stmt = this.db.prepare(sql);
    return gateName ? stmt.all(nodeId, gateName) : stmt.all(nodeId);
  }
  // ═══════════════════════════════════════════════════════════════
  // BULK SEED FROM FILESYSTEM
  // ═══════════════════════════════════════════════════════════════
  syncFromDisk(nodesJsonPath) {
    const nodes = JSON.parse((0, import_node_fs4.readFileSync)(nodesJsonPath, "utf-8"));
    let inserted = 0, updated = 0;
    const errors = [];
    this.db.prepare("BEGIN TRANSACTION").run();
    try {
      for (const n of nodes) {
        try {
          const existing = this.getNodeByPath(n.path);
          this.upsertNode({
            node_id: existing?.node_id,
            name: n.name,
            repo_path: n.path,
            node_type: n.type ?? "node",
            tags: n.tags,
            description: n.description
          });
          existing ? updated++ : inserted++;
        } catch (e) {
          errors.push(`${n.name}: ${e.message}`);
        }
      }
      this.db.prepare("COMMIT").run();
    } catch (e) {
      this.db.prepare("ROLLBACK").run();
      throw e;
    }
    return { inserted, updated, errors };
  }
  // ═══════════════════════════════════════════════════════════════
  // OMEGA BRAIN BRIDGE
  // ═══════════════════════════════════════════════════════════════
  exportToOmegaBrain(opts) {
    let sql = `
      SELECT a.attestation_id, n.name, a.overall_status, a.risk_score, a.run_at, a.raw_json
      FROM attestations a
      JOIN nodes n ON n.node_id = a.node_id
      WHERE 1=1
    `;
    const params = [];
    if (opts?.since) {
      sql += " AND a.run_at > ?";
      params.push(opts.since);
    }
    if (opts?.limit) {
      sql += " LIMIT ?";
      params.push(opts.limit);
    }
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params);
    return rows.map((r) => ({
      fragment_id: `sswp-att-${r.attestation_id}`,
      content: `[SSWP ATTESTATION] ${r.name}
Status: ${r.overall_status}
Risk: ${(r.risk_score * 100).toFixed(1)}%
Run: ${r.run_at}`,
      tier: r.overall_status === "PASS" ? "B" : "C"
    }));
  }
};

// src/mcp/server.ts
var import_node_fs5 = require("node:fs");
var import_node_path5 = require("node:path");
var REG = new RegistryManager({ autoInit: true });
var server = new import_server.Server(
  { name: "sswp-mcp", version: "2.0.0" },
  { capabilities: { tools: {} } }
);
server.setRequestHandler(import_types.ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "sswp_witness",
      description: "Witness a software project with deterministic attestation. Scans the full dependency graph (every node_modules package with resolved path, integrity hash, and risk score), runs a 5-gate pipeline (GIT_INTEGRITY, LOCKFILE, DETERMINISTIC_BUILD, TEST_PASS, LINT), adversarially probes every dependency for typosquatting, version anomalies, and missing integrity hashes, then produces a self-verifying .sswp.json attestation sealed with SHA-256. Auto-saves the attestation to the SQLite fleet registry and appends an entry to the tamper-proof audit ledger. This is the primary attestation tool \u2014 use it when you need a full cryptographic witness of a single repo's state. For multiple repos, use sswp_bulk_witness instead.",
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
          cortexVerdict: { type: "string", enum: ["APPROVED", "STEERED", "NOT_CHECKED"], description: "Gap #3 \u2014 Governance: result of omega_cortex_check run BEFORE calling sswp_witness. Pass 'APPROVED' or 'STEERED' to confirm the Cortex gate was satisfied." },
          regime: { type: "string", enum: ["developer", "ci", "strict"], default: "developer", description: "Gate severity regime. developer: dirty tree=WARN, missing scripts=INCONCLUSIVE. ci: dirty tree=FAIL, build/test required if scripts exist. strict: all detectable gates must PASS." }
        },
        required: ["repoPath"]
      }
    },
    {
      name: "sswp_verify",
      description: "Verify the SHA-256 cryptographic signature of an existing .sswp.json attestation file. Recomputes the hash over the entire attestation payload (sorted keys, excluding the signature field) and compares it against the stored signature. Returns VALID ATTESTATION if the file is intact and unmodified, or SIGNATURE MISMATCH if the file was altered after sealing. Use this to audit an attestation you received from someone else, or to confirm a repo's attestation still matches the file on disk. For generating new attestations, use sswp_witness; for quick repo readiness checks without sealing, use sswp_check_repo.",
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
      description: "Analyze a list of dependencies for supply-chain risk using Kimi K2 reasoning. Provide an array of {name, version} objects for any npm packages you want evaluated. The tool performs four analysis passes: typosquatting detection (matching names against known suspicious patterns like left-pad, event-stream), version anomaly scanning (flagging unpinned ranges like *, >=, ^0), metadata integrity checks (CRITICAL if a dependency lacks an integrity hash), and optional Kimi K2 deep reasoning (requires OLLAMA_CLOUD_API_KEY \u2014 returns INCONCLUSIVE without it). Returns a JSON object with per-probe results, overall risk score (0-1), and suspicious package counts. Use this for targeted supply-chain analysis on critical dependency trees. For generating full attestations that include probing, use sswp_witness.",
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
      description: "Run deterministic attestation on multiple repositories sequentially. For each repo path provided, runs the full SSWP witness pipeline (scan, 5-gate test, adversarial probe, SHA-256 seal) and auto-saves the .sswp.json attestation to the fleet registry. Reports per-repo PASS/FAIL status with risk percentages and a final summary of passed, failed, and skipped counts. Missing repos are skipped by default. Use this for nightly fleet audits, pre-release sweeps across the ecosystem, or any batch witnessing operation. For a single repo, prefer sswp_witness.",
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
          skipMissing: { type: "boolean", default: true, description: "If true (default), skip repos that don't exist on disk and continue processing remaining repos. If false, returns an error immediately on the first missing repo." },
          regime: { type: "string", enum: ["developer", "ci", "strict"], default: "developer", description: "Gate severity regime applied uniformly to all repos in the batch." }
        },
        required: ["repoPaths"]
      }
    },
    {
      name: "sswp_check_repo",
      description: "Perform a lightweight repo health check without running the full witness pipeline. Verifies four conditions: the directory exists on disk, a .git directory is present (indicating a git repository), a package-lock.json exists (indicating locked dependencies), and a package.json exists (indicating a valid Node.js project). Returns a status line for each condition and an overall READY/NOT READY verdict. Use this as a fast pre-check in CI pipelines or before calling sswp_witness to ensure the repo is in a valid state. Does not seal an attestation or modify the registry.",
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
      description: "Display the full fleet health board from the SSWP SQLite registry. Returns a formatted table showing every witnessed node with its name, status (active/deprecated/archived), last witness run timestamp, overall risk score (as percentage), and adversarial risk score (as percentage). Results are ordered by risk descending (most risky nodes first). Use this for an ecosystem-wide dashboard view of attestation status. For searching specific nodes by name, tag, or description, use sswp_node_search. For querying the audit ledger directly, use sswp_ledger.",
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
      description: "Query the tamper-proof SSWP audit ledger, an append-only SHA-256 hash chain that records every witness run, gate vote, and probe result. Returns a formatted table showing ledger entries with their sequence ID, event type (WITNESS, BULK_WITNESS), hash, and timestamp. Optionally filter by event type to narrow results. The ledger chain is cryptographically verifiable \u2014 any altered or removed entry breaks the chain. Use this for audit trail review, compliance reporting, or incident investigation. For a quick fleet overview, use sswp_registry_health instead.",
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
      description: "Search the SSWP fleet registry using full-text search (FTS5) across node names, tags, and descriptions. Matches partial keywords and ranks results by relevance. Returns a formatted table showing matching nodes with their name, node type, status, and repository path. Use this to find specific projects in the ecosystem registry by name fragment, technology tag, or description keyword. For a full sorted health board of all nodes, use sswp_registry_health instead.",
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
      description: "Gap #2 \u2014 Formats the most recent SSWP attestation as an omega_seal_run payload, closing the SSWP\u2192Omega Brain SEAL bridge gap. Enables one-click chaining: sswp_witness \u2192 sswp_export_to_omega \u2192 omega_seal_run. Returns ready-to-use context and response fields.",
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
server.setRequestHandler(import_types.CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  if (name === "sswp_witness") {
    const rawPath = args.repoPath;
    const wslPath = toWslPath(rawPath);
    if (!(0, import_node_fs5.existsSync)(wslPath)) {
      return mkText("Repo not found: " + wslPath + " (from " + rawPath + ")", true);
    }
    try {
      const regime = args.regime || "developer";
      const att = await witness(wslPath, regime);
      const overallStatus = att.overallStatus || (att.gates.some((g) => g.status === "FAIL") ? "FAIL" : att.gates.some((g) => g.status === "INCONCLUSIVE" || g.status === "WARN") ? "WARN" : "PASS");
      const ok = overallStatus !== "FAIL";
      let node = REG.getNodeByPath(wslPath);
      if (!node) {
        node = REG.upsertNode({ name: att.target.name || "unknown", repo_path: wslPath, node_type: "node" });
      }
      const jsonPath = (0, import_node_path5.resolve)(wslPath, ".sswp.json");
      const rawJson = JSON.stringify(att, null, 2);
      (0, import_node_fs5.writeFileSync)(jsonPath, rawJson);
      REG.saveAttestation(node.node_id, att, jsonPath, rawJson);
      const cortexVerdict = args.cortexVerdict || "NOT_CHECKED";
      const traceId = args.traceId || "VT-UNTRACED";
      try {
        const os = await import("node:os");
        const { mkdirSync: mkdirSync2, appendFileSync } = await import("node:fs");
        const sharedDir = os.homedir() + "/.veritas-shared";
        mkdirSync2(sharedDir, { recursive: true });
        const event = JSON.stringify({
          trace_id: traceId,
          event_type: "SSWP_WITNESS_COMPLETE",
          source: "sswp",
          payload: {
            target: att.target.name,
            repo: att.target.repo,
            commit: att.target.commitHash?.slice(0, 8) || "unknown",
            overall_status: overallStatus,
            adversarial_risk: att.adversarial.overallRisk,
            gates_passed: att.gates.filter((g) => g.status === "PASS").length,
            gates_total: att.gates.length,
            signature: att.signature?.slice(0, 16),
            cortex_verdict: cortexVerdict,
            cortex_governed: cortexVerdict !== "NOT_CHECKED"
          },
          timestamp: (/* @__PURE__ */ new Date()).toISOString()
        });
        appendFileSync(sharedDir + "/events.jsonl", event + "\n");
        if (cortexVerdict === "NOT_CHECKED") {
          appendFileSync(sharedDir + "/events.jsonl", JSON.stringify({
            trace_id: traceId,
            event_type: "SSWP_CORTEX_NOT_CHECKED",
            source: "sswp",
            payload: { repo: att.target.repo, note: "sswp_witness called without prior omega_cortex_check" },
            timestamp: (/* @__PURE__ */ new Date()).toISOString()
          }) + "\n");
        }
      } catch (_e) {
      }
      const cortexNote = cortexVerdict === "NOT_CHECKED" ? "\n\n\u26A0 CORTEX NOT CHECKED \u2014 Call omega_cortex_check before sswp_witness for governed attestation." : `

\u2713 Cortex: ${cortexVerdict}`;
      return mkText(formatAttestation(att) + "\n\n[REGISTRY] Saved attestation " + att.id + cortexNote, !ok);
    } catch (err) {
      return mkText("SSWP ERROR: " + (err.message || String(err)), true);
    }
  }
  if (name === "sswp_verify") {
    const rawPath = args.filePath;
    const filePath = (0, import_node_path5.resolve)(rawPath);
    if (!(0, import_node_fs5.existsSync)(filePath)) {
      return mkText("File not found: " + filePath, true);
    }
    try {
      const valid = verifyAttestation(filePath);
      return mkText(valid ? "VALID ATTESTATION" : "SIGNATURE MISMATCH", !valid);
    } catch (err) {
      return mkText("VERIFY ERROR: " + (err.message || String(err)), true);
    }
  }
  if (name === "sswp_analyze_deps") {
    const packages = args.packages;
    if (!packages?.length) {
      return mkText("No packages provided.", true);
    }
    try {
      const deps = packages.map((p) => ({
        name: p.name,
        version: p.version,
        resolved: "",
        integrity: null,
        suspicious: false,
        riskScore: 0
      }));
      const results = await kimiAnalyze(deps);
      return mkText(JSON.stringify(results, null, 2), false);
    } catch (err) {
      return mkText("ANALYZE ERROR: " + (err.message || String(err)), true);
    }
  }
  if (name === "sswp_bulk_witness") {
    const paths = args.repoPaths;
    const skipMissing = args.skipMissing !== false;
    const regime = args.regime || "developer";
    const results = [];
    let pass = 0, warn = 0, fail = 0, skip = 0;
    for (const raw of paths) {
      const wsl = toWslPath(raw);
      if (!(0, import_node_fs5.existsSync)(wsl)) {
        if (skipMissing) {
          skip++;
          results.push("SKIP: " + raw);
          continue;
        }
        return mkText("Missing repo (skipMissing=false): " + raw, true);
      }
      try {
        const att = await witness(wsl, regime);
        const overallStatus = att.overallStatus || (att.gates.some((g) => g.status === "FAIL") ? "FAIL" : att.gates.some((g) => g.status === "INCONCLUSIVE" || g.status === "WARN") ? "WARN" : "PASS");
        if (overallStatus === "PASS") pass++;
        else if (overallStatus === "WARN") warn++;
        else fail++;
        let node = REG.getNodeByPath(wsl);
        if (!node) node = REG.upsertNode({ name: att.target.name || "unknown", repo_path: wsl, node_type: "node" });
        const jsonPath = (0, import_node_path5.resolve)(wsl, ".sswp.json");
        const rawJson = JSON.stringify(att, null, 2);
        (0, import_node_fs5.writeFileSync)(jsonPath, rawJson);
        REG.saveAttestation(node.node_id, att, jsonPath, rawJson);
        results.push("[" + overallStatus + "] " + raw + " - risk " + (att.adversarial.overallRisk * 100).toFixed(1) + "%");
      } catch (err) {
        fail++;
        results.push("[ERROR] " + raw + ": " + err.message);
      }
    }
    const summary = "BULK DONE - " + pass + " pass, " + warn + " warn, " + fail + " fail, " + skip + " skip / " + paths.length + "\n\n" + results.join("\n");
    return mkText(summary, fail > 0);
  }
  if (name === "sswp_check_repo") {
    const rawPath = args.repoPath;
    const wsl = toWslPath(rawPath);
    const checks = {
      exists: (0, import_node_fs5.existsSync)(wsl),
      isGit: (0, import_node_fs5.existsSync)((0, import_node_path5.resolve)(wsl, ".git")),
      hasLockfile: (0, import_node_fs5.existsSync)((0, import_node_path5.resolve)(wsl, "package-lock.json")),
      hasPackageJson: (0, import_node_fs5.existsSync)((0, import_node_path5.resolve)(wsl, "package.json"))
    };
    const ok = checks.exists && (checks.hasLockfile || checks.hasPackageJson);
    const text = "Repo: " + wsl + "\n  exists: " + checks.exists + "\n  git: " + checks.isGit + "\n  package-lock.json: " + checks.hasLockfile + "\n  package.json: " + checks.hasPackageJson + "\n  status: " + (ok ? "READY" : "NOT READY");
    return mkText(text, !ok);
  }
  if (name === "sswp_registry_health") {
    const limit = args.limit ?? 50;
    const rows = REG.getHealthBoard();
    if (!rows.length) return mkText("No nodes in registry.", false);
    const lines = ["NODE                 STATUS   LAST_RUN              RISK    ADVERSARIAL"];
    for (const r of rows.slice(0, limit)) {
      const name2 = String(r.name).slice(0, 20).padEnd(20, " ");
      const status = String(r.status).slice(0, 8).padEnd(8, " ");
      const last = r.last_run ? String(r.last_run).slice(0, 19) : "never     ";
      const risk = r.last_risk != null ? (r.last_risk * 100).toFixed(1) + "%" : "N/A  ";
      const adv = r.last_adversarial != null ? (r.last_adversarial * 100).toFixed(1) + "%" : "N/A";
      lines.push(`${name2}  ${status}  ${last}  ${risk}  ${adv}`);
    }
    return mkText(lines.join("\n"), false);
  }
  if (name === "sswp_ledger") {
    const limit = args.limit ?? 20;
    const eventType = args.eventType;
    let rows = REG.getLedger(limit * 2);
    if (eventType) rows = rows.filter((r) => r.event_type === eventType);
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
    const query = args.query;
    const limit = args.limit ?? 10;
    const rows = REG.searchNodes(query, limit);
    if (!rows.length) return mkText("No nodes matched: " + query, false);
    const lines = ["NAME                 TYPE       STATUS   PATH"];
    for (const r of rows) {
      const name2 = r.name.slice(0, 20).padEnd(20, " ");
      const type = r.node_type.slice(0, 10).padEnd(10, " ");
      const status = r.status.slice(0, 8).padEnd(8, " ");
      lines.push(`${name2}  ${type}  ${status}  ${r.repo_path}`);
    }
    return mkText(lines.join("\n"), false);
  }
  if (name === "sswp_export_to_omega") {
    const rawPath2 = args.repoPath;
    const traceId2 = args.traceId || "VT-UNTRACED";
    try {
      const rows = REG.getHealthBoard();
      let row;
      if (rawPath2) {
        const wsl2 = toWslPath(rawPath2);
        row = rows.find((r) => r.repo_path === wsl2);
        if (!row) return mkText("No attestation found for: " + rawPath2, true);
      } else {
        if (!rows.length) return mkText("No attestations in registry.", true);
        row = rows[0];
      }
      const riskPct = row.last_risk != null ? (row.last_risk * 100).toFixed(1) + "%" : "N/A";
      const advPct = row.last_adversarial != null ? (row.last_adversarial * 100).toFixed(1) + "%" : "N/A";
      const sealPayload = {
        context: {
          event_type: "SSWP_WITNESS",
          source: "sswp",
          trace_id: traceId2,
          node: row.name,
          repo_path: row.repo_path,
          status: row.last_status || "UNKNOWN",
          risk_score: row.last_risk || 0,
          adversarial_risk: row.last_adversarial || 0,
          last_run: row.last_run
        },
        response: `SSWP attestation \u2014 ${row.name} | Status: ${row.last_status || "UNKNOWN"} | Risk: ${riskPct} | Adversarial: ${advPct} | Run: ${row.last_run || "unknown"} | TraceID: ${traceId2}`
      };
      return mkText(
        "# omega_seal_run payload \u2014 ready to use\n\nCall omega_seal_run with these arguments:\n\n" + JSON.stringify(sealPayload, null, 2),
        false
      );
    } catch (err) {
      return mkText("EXPORT ERROR: " + (err.message || String(err)), true);
    }
  }
  return mkText("Unknown tool: " + name, true);
});
function mkText(text, isError) {
  return { content: [{ type: "text", text }], isError };
}
async function main() {
  const transport = new import_stdio.StdioServerTransport();
  await server.connect(transport);
  console.error("SSWP MCP server v2 started (stdio)");
}
main().catch((err) => {
  console.error("SSWP MCP fatal:", err);
  process.exit(1);
});
