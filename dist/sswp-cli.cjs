#!/usr/bin/env node

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

// src/core/registry-db.ts
var import_node_crypto4 = require("node:crypto");
var import_node_fs4 = require("node:fs");
var import_node_os = require("node:os");
var import_node_path4 = require("node:path");
var REGISTRY_PATH = process.env.SSWP_REGISTRY_PATH || (0, import_node_path4.join)((0, import_node_os.homedir)(), ".sswp_registry.jsonl");
function computeAttestationHash(att) {
  return (0, import_node_crypto4.createHash)("sha256").update(JSON.stringify(att)).digest("hex");
}
function readLines() {
  if (!(0, import_node_fs4.existsSync)(REGISTRY_PATH)) return [];
  const raw = (0, import_node_fs4.readFileSync)(REGISTRY_PATH, "utf8");
  if (!raw.trim()) return [];
  return raw.split(/\r?\n/).filter((line) => line.trim() !== "");
}
function parseLine(line) {
  try {
    const obj = JSON.parse(line);
    if (!obj || typeof obj.nodeId !== "string") return null;
    return obj;
  } catch {
    return null;
  }
}
function saveAttestation(nodeId, att, attestationPath) {
  const entry = {
    nodeId,
    timestamp: att.timestamp,
    attestationHash: computeAttestationHash(att),
    attestationPath,
    risk: att.adversarial.overallRisk,
    passedGates: att.gates.filter((g) => g.status === "PASS").length,
    totalGates: att.gates.length,
    suspiciousPackages: att.adversarial.suspiciousPackages
  };
  try {
    (0, import_node_fs4.appendFileSync)(REGISTRY_PATH, JSON.stringify(entry) + "\n", { encoding: "utf8" });
    return { entry, appended: true };
  } catch (err) {
    console.error(`SSWP Registry append failed: ${err}`);
    return { entry, appended: false };
  }
}
function getAttestationHistory(nodeId) {
  return readLines().map(parseLine).filter((e) => e !== null && e.nodeId === nodeId).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}
function getRiskyNodes(threshold = 0.3) {
  const latestByNode = /* @__PURE__ */ new Map();
  for (const line of readLines()) {
    const e = parseLine(line);
    if (!e) continue;
    const existing = latestByNode.get(e.nodeId);
    if (!existing || new Date(e.timestamp) > new Date(existing.timestamp)) {
      latestByNode.set(e.nodeId, e);
    }
  }
  return Array.from(latestByNode.values()).filter((e) => e.risk > threshold).sort((a, b) => b.risk - a.risk).map((e) => ({ nodeId: e.nodeId, risk: e.risk, timestamp: e.timestamp }));
}
function getAllNodesStats() {
  const counts = /* @__PURE__ */ new Map();
  const latestByNode = /* @__PURE__ */ new Map();
  for (const line of readLines()) {
    const e = parseLine(line);
    if (!e) continue;
    counts.set(e.nodeId, (counts.get(e.nodeId) || 0) + 1);
    const existing = latestByNode.get(e.nodeId);
    if (!existing || new Date(e.timestamp) > new Date(existing.timestamp)) {
      latestByNode.set(e.nodeId, e);
    }
  }
  return Array.from(latestByNode.values()).sort((a, b) => a.nodeId.localeCompare(b.nodeId)).map((e) => ({
    nodeId: e.nodeId,
    latestRisk: e.risk,
    latestTimestamp: e.timestamp,
    witnessCount: counts.get(e.nodeId) || 0
  }));
}

// src/cli.ts
var import_node_path5 = require("node:path");
var import_node_fs5 = require("node:fs");
var import_node_crypto5 = require("node:crypto");
async function main() {
  const [, , command, ...rest] = process.argv;
  if (command === "witness") {
    let regime = "developer";
    const positional = [];
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === "--regime" && rest[i + 1]) {
        const val = rest[i + 1];
        if (val === "developer" || val === "ci" || val === "strict") {
          regime = val;
          i++;
          continue;
        }
      }
      positional.push(rest[i]);
    }
    const projectRoot = (0, import_node_path5.resolve)(positional[0] || process.cwd());
    console.error(`\u2B21  SSWP \u2014 Witnessing ${projectRoot}... (regime: ${regime})`);
    const att = await witness(projectRoot, regime);
    console.log(formatAttestation(att));
    const outPath = (0, import_node_path5.resolve)(projectRoot, `${att.target.name}.sswp.json`);
    (0, import_node_fs5.writeFileSync)(outPath, JSON.stringify(att, null, 2));
    const nodeId = att.target.name;
    const { entry, appended } = saveAttestation(nodeId, att, outPath);
    if (appended) {
      console.error(`\u2713 Attestation written: ${outPath}`);
      console.error(`\u2713 Registry entry saved: ${entry.attestationHash.slice(0, 16)}...`);
    } else {
      console.error(`\u2713 Attestation written: ${outPath}`);
      console.error(`\u26A0 Registry append failed`);
    }
    const failed = att.overallStatus === "FAIL";
    process.exit(failed ? 1 : 0);
  }
  if (command === "verify") {
    const file = rest[0];
    if (!file) {
      console.error("Usage: sswp verify <file.sswp.json>");
      process.exit(1);
    }
    const att = JSON.parse((0, import_node_fs5.readFileSync)((0, import_node_path5.resolve)(file), "utf8"));
    const { signature, ...hashPayload } = att;
    const payload = JSON.stringify(hashPayload, Object.keys(hashPayload).sort());
    const computed = (0, import_node_crypto5.createHash)("sha256").update(payload).digest("hex");
    const valid = computed === att.signature;
    console.log(valid ? "\u2713 VALID ATTESTATION" : "\u2717 SIGNATURE MISMATCH");
    process.exit(valid ? 0 : 1);
  }
  if (command === "registry") {
    const subCommand = rest[0];
    if (subCommand === "list") {
      const stats = getAllNodesStats();
      if (stats.length === 0) {
        console.log("No registry entries found.");
        process.exit(0);
      }
      console.log(`\u2B21  SSWP Registry \u2014 ${stats.length} node(s)
`);
      console.log("NODE ID".padEnd(28) + "RISK".padEnd(10) + "LAST WITNESS".padEnd(22) + "COUNT");
      console.log("-".repeat(70));
      for (const s of stats) {
        const riskStr = `${(s.latestRisk * 100).toFixed(1)}%`;
        const timeStr = new Date(s.latestTimestamp).toLocaleString();
        console.log(
          s.nodeId.padEnd(28) + riskStr.padEnd(10) + timeStr.padEnd(22) + String(s.witnessCount)
        );
      }
      process.exit(0);
    }
    if (subCommand === "history") {
      const nodeId = rest[1];
      if (!nodeId) {
        console.error("Usage: sswp registry history <nodeId>");
        process.exit(1);
      }
      const hist = getAttestationHistory(nodeId);
      if (hist.length === 0) {
        console.log(`No history found for node ${nodeId}`);
        process.exit(0);
      }
      console.log(`\u2B21  SSWP History for ${nodeId} (${hist.length} attestations)
`);
      console.log(
        "HASH".padEnd(20) + "TIMESTAMP".padEnd(24) + "RISK".padEnd(10) + "GATES PATH"
      );
      console.log("-".repeat(100));
      for (const h of hist) {
        const hash = h.attestationHash.slice(0, 16) + "...";
        const ts = new Date(h.timestamp).toLocaleString();
        const risk = `${(h.risk * 100).toFixed(1)}%`;
        const gates = `${h.passedGates}/${h.totalGates}`;
        console.log(`${hash.padEnd(20)}${ts.padEnd(24)}${risk.padEnd(10)}${gates}  ${h.attestationPath}`);
      }
      process.exit(0);
    }
    if (subCommand === "risky") {
      const threshold = rest[1] ? parseFloat(rest[1]) : 0.3;
      const risky = getRiskyNodes(threshold);
      if (risky.length === 0) {
        console.log(`No nodes exceed risk threshold ${threshold}.`);
        process.exit(0);
      }
      console.log(`\u2B21  SSWP Risky Nodes (risk > ${threshold})
`);
      console.log("NODE ID".padEnd(28) + "RISK".padEnd(10) + "LAST TIMESTAMP");
      console.log("-".repeat(60));
      for (const r of risky) {
        console.log(
          r.nodeId.padEnd(28) + `${(r.risk * 100).toFixed(1)}%`.padEnd(10) + new Date(r.timestamp).toLocaleString()
        );
      }
      process.exit(0);
    }
    console.log(`
 registry subcommands:   list | history <nodeId> | risky [threshold]
`);
    process.exit(1);
  }
  console.log(`
\u2B21  Sovereign Software Witness Protocol (SSWP) v1.0

Commands:
  sswp witness [dir]   Scan, build-test, adversarial-probe, and seal
  sswp verify <file>   Verify an existing .sswp.json attestation
  sswp registry list     List all nodes with latest risk
  sswp registry history <nodeId>   Print attestation history for a node
  sswp registry risky [threshold]  Print nodes with risk > threshold (default 0.3)

Examples:
  sswp witness /mnt/c/Veritas_Lab/veritas-topography-map
  sswp verify veritas-topography-map.sswp.json
  sswp registry list
  sswp registry risky 0.5
`);
}
main().catch((err) => {
  console.error(err);
  process.exit(1);
});
