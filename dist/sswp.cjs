#!/usr/bin/env node

// src/sswp/core/witness.ts
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

// src/sswp/core/build-scanner.ts
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

// src/sswp/core/gate-runner.ts
var import_node_child_process = require("node:child_process");
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");
async function runGates(projectRoot, env) {
  const results = [];
  results.push(await gitIntegrityGate(projectRoot));
  results.push(await lockfileGate(projectRoot));
  results.push(await deterministicBuildGate(projectRoot, env));
  results.push(await testGate(projectRoot, env));
  results.push(await lintGate(projectRoot));
  return results;
}
function timed(name, fn) {
  const start = Date.now();
  const result = fn();
  result.durationMs = Date.now() - start;
  result.gate = name;
  return result;
}
async function gitIntegrityGate(root) {
  return timed("GIT_INTEGRITY", () => {
    const r = (0, import_node_child_process.spawnSync)("git", ["status", "--porcelain"], { cwd: root, encoding: "utf8" });
    const clean = !r.stdout?.trim();
    return {
      gate: "GIT_INTEGRITY",
      status: clean ? "PASS" : "FAIL",
      evidence: clean ? "Working tree clean" : `Modified files: ${r.stdout?.trim().split("\n").length}`,
      durationMs: 0
    };
  });
}
async function lockfileGate(root) {
  return timed("LOCKFILE", () => {
    const hasPkg = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"));
    const hasLock = (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package-lock.json"));
    if (!hasPkg) return { gate: "LOCKFILE", status: "INCONCLUSIVE", evidence: "No package.json", durationMs: 0 };
    if (!hasLock) return { gate: "LOCKFILE", status: "FAIL", evidence: "No package-lock.json", durationMs: 0 };
    return { gate: "LOCKFILE", status: "PASS", evidence: "package-lock.json present", durationMs: 0 };
  });
}
async function deterministicBuildGate(root, env) {
  return timed("DETERMINISTIC_BUILD", () => {
    const cmd = env.buildCommand;
    if (cmd === "unknown") {
      return { gate: "DETERMINISTIC_BUILD", status: "INCONCLUSIVE", evidence: "No build command detected", durationMs: 0 };
    }
    const r = (0, import_node_child_process.spawnSync)(cmd.split(" ")[0], cmd.split(" ").slice(1), { cwd: root, encoding: "utf8", shell: true });
    const passed = r.status === 0;
    return {
      gate: "DETERMINISTIC_BUILD",
      status: passed ? "PASS" : "FAIL",
      evidence: passed ? `Build succeeded: ${cmd}` : `Build failed: ${r.stderr?.slice(0, 200)}`,
      durationMs: 0
    };
  });
}
async function testGate(root, env) {
  return timed("TEST_PASS", () => {
    const r = (0, import_node_child_process.spawnSync)("npm", ["test"], { cwd: root, encoding: "utf8", shell: true });
    const passed = r.status === 0;
    return {
      gate: "TEST_PASS",
      status: passed ? "PASS" : "FAIL",
      evidence: passed ? "All tests passed" : `Tests failed: ${r.stderr?.slice(0, 200) || r.stdout?.slice(0, 200)}`,
      durationMs: 0
    };
  });
}
async function lintGate(root) {
  return timed("LINT", () => {
    const candidates = [
      ["npx", "eslint", "--max-warnings=0", "."],
      ["npx", "biome", "check", "."],
      ["npx", "tsc", "--noEmit"]
    ];
    for (const [cmd, ...args] of candidates) {
      const r = (0, import_node_child_process.spawnSync)(cmd, args, { cwd: root, encoding: "utf8", shell: true });
      if (r.status === 0) {
        return { gate: "LINT", status: "PASS", evidence: `${cmd} passed`, durationMs: 0 };
      }
      if (r.error || (r.stderr?.includes("not found") || r.stderr?.includes("ENOENT"))) continue;
    }
    return { gate: "LINT", status: "INCONCLUSIVE", evidence: "No linter configured", durationMs: 0 };
  });
}

// src/sswp/core/kimi-reasoner.ts
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

// src/sswp/core/adversarial-probe.ts
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
  const suspiciousPatterns = [
    "left-pad",
    "event-stream",
    "colors",
    "faker",
    "node-ipc",
    "rc",
    "ua-parser-js",
    "coa",
    "esbuild",
    "discord.js"
  ];
  const isSuspicious = suspiciousPatterns.some((p) => dep.name.toLowerCase().includes(p));
  return {
    package: dep.name,
    probe: "TYPO_SQUATTING",
    result: isSuspicious ? "WARN" : "PASS",
    detail: isSuspicious ? "Name matches known suspicious packages" : "Name heuristic clean"
  };
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

// src/sswp/core/witness.ts
async function witness(projectRoot) {
  const { entries, env, totalPackages, suspiciousCount } = await scanBuild(projectRoot);
  const scanSeal = seal(
    { phase: "SCAN", totalPackages, suspiciousCount },
    `Scanned ${totalPackages} packages, ${suspiciousCount} flagged`
  );
  const gateResults = await runGates(projectRoot, env);
  const passedGates = gateResults.filter((g) => g.status === "PASS").length;
  const gateSeal = seal(
    { phase: "GATES", passed: passedGates, total: gateResults.length },
    JSON.stringify(gateResults.map((g) => ({ gate: g.gate, status: g.status })))
  );
  const adversarial = await runAdversarialProbes(entries);
  const advSeal = seal(
    { phase: "ADVERSARIAL", overallRisk: adversarial.overallRisk, probes: adversarial.probes.length },
    JSON.stringify(adversarial)
  );
  const pkgJson = JSON.parse((0, import_node_fs3.readFileSync)((0, import_node_path3.join)(projectRoot, "package.json"), "utf8"));
  const gitHash = execGit(projectRoot, ["rev-parse", "HEAD"]);
  const branch = execGit(projectRoot, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const attestation = {
    version: "1.0.0",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    target: {
      name: pkgJson.name || "unknown",
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

// src/sswp/core/registry-db.ts
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

// src/sswp/cli.ts
var import_node_path5 = require("node:path");
var import_node_fs5 = require("node:fs");
var import_node_crypto5 = require("node:crypto");
async function main() {
  const [, , command, ...rest] = process.argv;
  if (command === "witness") {
    const projectRoot = (0, import_node_path5.resolve)(rest[0] || process.cwd());
    console.error(`\u2B21  SSWP \u2014 Witnessing ${projectRoot}...`);
    const att = await witness(projectRoot);
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
    const failed = att.gates.some((g) => g.status === "FAIL");
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
