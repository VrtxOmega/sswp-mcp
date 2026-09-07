"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/core/witness.ts
var witness_exports = {};
__export(witness_exports, {
  dependencyInventory: () => dependencyInventory,
  formatAttestation: () => formatAttestation,
  verifyAttestation: () => verifyAttestation,
  witness: () => witness
});
module.exports = __toCommonJS(witness_exports);
var import_node_fs3 = require("node:fs");
var import_node_path3 = require("node:path");
var import_node_crypto4 = require("node:crypto");

// src/core/integrity.ts
var import_node_crypto2 = require("node:crypto");
var import_better_sqlite3 = __toESM(require("better-sqlite3"));

// src/core/source-state.ts
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var excluded = /* @__PURE__ */ new Set([".git", "node_modules", ".venv", "data", "__pycache__", ".sswp.json"]);
function sourceFiles(root) {
  const result2 = [];
  const walk = (folder) => {
    for (const name of (0, import_node_fs.readdirSync)(folder)) {
      if (excluded.has(name)) continue;
      const p = (0, import_node_path.join)(folder, name), s = (0, import_node_fs.lstatSync)(p);
      if (s.isSymbolicLink()) throw Error("Source symlinks require an explicit packaged source snapshot");
      if (s.isDirectory()) walk(p);
      else if (s.isFile()) result2.push((0, import_node_path.relative)(root, p).replaceAll("\\", "/"));
    }
  };
  walk(root);
  return result2.sort();
}
function sourceIdentity(root) {
  const hash = (0, import_node_crypto.createHash)("sha256");
  for (const f of sourceFiles(root)) hash.update(f + "\0" + (0, import_node_crypto.createHash)("sha256").update((0, import_node_fs.readFileSync)((0, import_node_path.join)(root, f))).digest("hex") + "\n");
  return hash.digest("hex");
}
function copySources(root, dest) {
  for (const f of sourceFiles(root)) {
    const target = (0, import_node_path.join)(dest, f);
    (0, import_node_fs.mkdirSync)((0, import_node_path.dirname)(target), { recursive: true });
    (0, import_node_fs.copyFileSync)((0, import_node_path.join)(root, f), target);
  }
}

// src/core/integrity.ts
function canonical(v) {
  if (v === null || typeof v !== "object") {
    const s = JSON.stringify(v);
    if (s === void 0 || typeof v === "number" && !Number.isFinite(v)) throw Error("Non-JSON value");
    return s;
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
var sha = (s) => (0, import_node_crypto2.createHash)("sha256").update(s).digest("hex");

// src/core/gate-runner.ts
var import_node_child_process = require("node:child_process");
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");
var import_node_os = require("node:os");
var import_node_crypto3 = require("node:crypto");
async function runCommand(command, args, cwd, timeout = 6e4, env = {}) {
  return new Promise((resolve2) => {
    const child = (0, import_node_child_process.spawn)(command, args, { cwd, shell: false, windowsHide: true, detached: process.platform !== "win32", env: { ...process.env, ...env } });
    let stdout = "", stderr = "", settled = false, timedOut = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve2(value);
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === "win32" && child.pid) {
        const killer = (0, import_node_child_process.spawn)("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true });
        killer.on("error", () => child.kill());
      } else if (child.pid) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          child.kill("SIGKILL");
        }
      }
    }, Math.max(50, Math.min(timeout, 3e5)));
    child.stdout?.on("data", (d) => {
      stdout = (stdout + d).slice(-65536);
    });
    child.stderr?.on("data", (d) => {
      stderr = (stderr + d).slice(-65536);
    });
    child.on("error", (e) => finish({ status: null, stdout, stderr, error: e.message }));
    child.on("close", (status) => finish({ status, stdout, stderr, ...timedOut ? { error: "TIMEOUT" } : {} }));
  });
}
var result = (gate, status, evidence, durationMs = 0) => ({ gate, status, evidence, durationMs });
async function gitIntegrityGate(root) {
  const start = Date.now();
  const r = await runCommand("git", ["status", "--porcelain=v1", "--untracked-files=all"], root, 1e4);
  if (r.error || r.status !== 0) return result("GIT_INTEGRITY", "ERROR", r.error || r.stderr || `git exit ${r.status}`, Date.now() - start);
  return result("GIT_INTEGRITY", r.stdout.trim() ? "FAIL" : "PASS", r.stdout.trim() ? "Working tree has changes" : "Git command succeeded; working tree clean", Date.now() - start);
}
function lockfileGate(root) {
  if (!(0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, "package.json"))) {
    const locks2 = ["uv.lock", "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.sum"].filter((f) => (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, f)));
    return result("LOCKFILE_PRESENT", locks2.length ? "PASS" : "NOT_APPLICABLE", locks2.length ? `${locks2.join(", ")} present; content consistency not established` : "No supported lockfile ecosystem detected");
  }
  const locks = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"].filter((f) => (0, import_node_fs2.existsSync)((0, import_node_path2.join)(root, f)));
  return result("LOCKFILE_PRESENT", locks.length === 1 ? "PASS" : locks.length ? "INCONCLUSIVE" : "FAIL", locks.length === 1 ? `${locks[0]} present; consistency not established` : locks.length ? "Multiple lockfiles; package manager selection required" : "No lockfile");
}
async function runGates(root, _env, policy = {}) {
  const output = [await gitIntegrityGate(root), lockfileGate(root)];
  const profile = policy.projects?.[(0, import_node_fs2.realpathSync)(root).replaceAll("\\", "/")] || {};
  for (const [gate, key] of [["BUILD_SUCCESS", "build"], ["TEST_PASS", "test"], ["LINT", "lint"]]) {
    const command = profile[key];
    if (!command) {
      output.push(result(gate, "INCONCLUSIVE", "No explicit operator command configured"));
      continue;
    }
    if (!Array.isArray(command.argv) || !command.argv.length || command.argv.some((a) => typeof a !== "string")) {
      output.push(result(gate, "ERROR", "Invalid operator command"));
      continue;
    }
    const start = Date.now();
    const r = await runCommand(command.argv[0], command.argv.slice(1), root, command.timeoutMs || 6e4);
    output.push(result(gate, r.error ? "ERROR" : r.status === 0 ? "PASS" : "FAIL", r.error || `exit=${r.status}; ${(r.stdout + "\n" + r.stderr).slice(-8e3)}`, Date.now() - start));
  }
  output.push(await reproducibleBuildGate(root, profile.reproducible));
  return output;
}
function outputManifest(root, outputs) {
  const manifest = {};
  const walk = (p) => {
    const stat = (0, import_node_fs2.lstatSync)(p);
    if (stat.isSymbolicLink()) throw Error("Output symlinks are not supported");
    if (stat.isDirectory()) {
      for (const name of (0, import_node_fs2.readdirSync)(p).sort()) walk((0, import_node_path2.join)(p, name));
    } else if (stat.isFile()) manifest[(0, import_node_path2.relative)(root, p).replaceAll("\\", "/")] = (0, import_node_crypto3.createHash)("sha256").update((0, import_node_fs2.readFileSync)(p)).digest("hex");
  };
  for (const output of outputs) {
    const target = (0, import_node_path2.resolve)(root, output);
    if ((0, import_node_path2.isAbsolute)(output) || !target.startsWith((0, import_node_path2.resolve)(root) + import_node_path2.sep)) throw Error("Output must be inside build directory");
    walk(target);
  }
  return Object.fromEntries(Object.entries(manifest).sort(([a], [b]) => a.localeCompare(b)));
}
async function reproducibleBuildGate(root, profile) {
  if (!profile) return result("REPRODUCIBLE_BUILD", "INCONCLUSIVE", "No independent-build profile configured");
  if (!Array.isArray(profile.outputs) || !profile.outputs.length || !Array.isArray(profile.argv) || !profile.argv.length) return result("REPRODUCIBLE_BUILD", "ERROR", "Explicit argv and output paths are required");
  const start = Date.now(), base = (0, import_node_fs2.mkdtempSync)((0, import_node_path2.join)((0, import_node_os.tmpdir)(), "sswp-repeat-")), manifests = [];
  try {
    const source = sourceIdentity(root);
    for (let i = 0; i < 2; i++) {
      const dest = (0, import_node_path2.join)(base, String(i));
      (0, import_node_fs2.mkdirSync)(dest);
      copySources(root, dest);
      for (const out of profile.outputs) {
        const target = (0, import_node_path2.resolve)(dest, out);
        if (typeof out !== "string" || (0, import_node_path2.isAbsolute)(out) || !target.startsWith((0, import_node_path2.resolve)(dest) + import_node_path2.sep)) throw Error("Output escapes isolated build");
        if ((0, import_node_fs2.existsSync)(target)) (0, import_node_fs2.rmSync)(target, { recursive: true, force: true });
      }
      const commands = [...profile.setup || [], { argv: profile.argv, timeoutMs: profile.timeoutMs }];
      for (const command of commands) {
        if (!Array.isArray(command.argv) || !command.argv.length || command.argv.some((x) => typeof x !== "string")) throw Error("Invalid independent-build command");
        const run = await runCommand(command.argv[0], command.argv.slice(1), dest, command.timeoutMs || 6e4, { TZ: "UTC", SOURCE_DATE_EPOCH: "0", ...profile.env || {} });
        if (run.error || run.status !== 0) return result("REPRODUCIBLE_BUILD", run.error ? "ERROR" : "FAIL", `Independent build ${i + 1}: ${run.error || run.stderr || run.stdout || run.status}`, Date.now() - start);
      }
      const manifest = outputManifest(dest, profile.outputs);
      if (!Object.keys(manifest).length) throw Error("No output files produced");
      manifests.push(manifest);
    }
    if (sourceIdentity(root) !== source) return result("REPRODUCIBLE_BUILD", "ERROR", "Source changed while independent builds ran", Date.now() - start);
    const match = JSON.stringify(manifests[0]) === JSON.stringify(manifests[1]);
    return result("REPRODUCIBLE_BUILD", match ? "PASS" : "FAIL", JSON.stringify({ source_sha256: source, matching: match, manifests, scope: "Two separate source copies on this host with explicit commands; not a hermetic environment or cross-host proof" }), Date.now() - start);
  } catch (e) {
    return result("REPRODUCIBLE_BUILD", "ERROR", String(e), Date.now() - start);
  } finally {
    const safe = (0, import_node_fs2.realpathSync)(base);
    if (safe.startsWith((0, import_node_fs2.realpathSync)((0, import_node_os.tmpdir)()) + import_node_path2.sep) && safe.includes("sswp-repeat-")) (0, import_node_fs2.rmSync)(safe, { recursive: true, force: true });
  }
}

// src/core/witness.ts
var import_yaml = require("yaml");
function dependencyInventory(root) {
  const lock = (0, import_node_path3.join)(root, "package-lock.json");
  if (!(0, import_node_fs3.existsSync)(lock)) {
    const pnpm = (0, import_node_path3.join)(root, "pnpm-lock.yaml");
    if ((0, import_node_fs3.existsSync)(pnpm)) {
      const data2 = (0, import_yaml.parse)((0, import_node_fs3.readFileSync)(pnpm, "utf8")), entries2 = [];
      for (const [key, value] of Object.entries(data2.packages || {})) {
        const p = value, at = key.lastIndexOf("@");
        entries2.push({ name: at > 0 ? key.slice(0, at) : key, version: at > 0 ? key.slice(at + 1) : "unknown", resolved: p.resolution?.tarball || key, integrity: p.resolution?.integrity || null, suspicious: !p.resolution?.integrity, riskScore: 0 });
      }
      return { entries: entries2, scope: "pnpm lock package entries including transitive packages; declared integrity, not independently verified installed bytes" };
    }
    return { entries: [], scope: "No supported npm/pnpm lockfile; dependency coverage unverified" };
  }
  const data = JSON.parse((0, import_node_fs3.readFileSync)(lock, "utf8"));
  const entries = [];
  for (const [location, value] of Object.entries(data.packages || {})) {
    if (!location) continue;
    const p = value;
    entries.push({ name: p.name || location.split("node_modules/").pop() || location, version: p.version || "unknown", resolved: p.resolved || location, integrity: p.integrity || null, suspicious: !p.integrity && !p.link, riskScore: 0 });
  }
  return { entries, scope: "npm lockfile package entries; integrity fields are declared metadata, not independently verified installed bytes" };
}
async function witness(root, policy = {}, taskId = "unscoped") {
  root = (0, import_node_fs3.realpathSync)(root);
  const inventory = dependencyInventory(root);
  const sourceBefore = sourceIdentity(root);
  const env = { cwd: root, nodeVersion: process.version, os: process.platform, arch: process.arch, ci: !!process.env.CI, buildCommand: "operator-profile", buildOutput: "" };
  const before = await runCommand("git", ["rev-parse", "HEAD"], root, 1e4);
  const gates = await runGates(root, env, policy);
  const after = await runCommand("git", ["rev-parse", "HEAD"], root, 1e4);
  const sourceAfter = sourceIdentity(root);
  if (sourceBefore !== sourceAfter) gates.push({ gate: "SOURCE_BYTES", status: "FAIL", evidence: "Source bytes changed while checks ran", durationMs: 0 });
  if (before.status !== 0 || after.status !== 0 || before.stdout !== after.stdout) gates.push({ gate: "SOURCE_REVISION", "status": "ERROR", evidence: "Cannot establish one stable Git revision across the checks", durationMs: 0 });
  const att = { id: (0, import_node_crypto4.randomUUID)(), version: "2.1.0", signatureAlgorithm: "sha256-canonical-json-v2", timestamp: (/* @__PURE__ */ new Date()).toISOString(), taskId, target: { name: (0, import_node_path3.basename)(root), repo: root, commitHash: before.status === 0 ? before.stdout.trim() : "unknown", branch: "recorded-by-commit" }, environment: { nodeVersion: env.nodeVersion, os: env.os, arch: env.arch, ci: env.ci }, dependencies: inventory.entries, dependencyCoverage: inventory.scope, gates, adversarial: { totalPackages: inventory.entries.length, suspiciousPackages: inventory.entries.filter((d) => d.suspicious).length, probes: [], overallRisk: 0, assessment: "NOT_PERFORMED; zero is not a safety probability" }, seal: { chainHash: "assigned-by-persistent-registry", sequence: 0 } };
  att.source = { before: sourceBefore, after: sourceAfter, scope: "Source tree; installed dependencies and runtime are host-trusted" };
  att.adversarial.probes = inventory.entries.map((d) => ({ package: d.name, probe: "LOCK_METADATA", result: !d.integrity ? "INCONCLUSIVE" : "PASS", detail: !d.integrity ? "No integrity declaration" : "Integrity declaration present; installed bytes and vulnerabilities not checked" }));
  att.adversarial.assessment = "Local metadata probes only; no adversarial execution or vulnerability feed consulted";
  att.signature = sha(canonical(att));
  return att;
}
function verifyAttestation(filePath) {
  const att = JSON.parse((0, import_node_fs3.readFileSync)(filePath, "utf8"));
  if (att.signatureAlgorithm !== "sha256-canonical-json-v2") return false;
  const { signature, ...payload } = att;
  return typeof signature === "string" && sha(canonical(payload)) === signature;
}
var formatAttestation = (att) => JSON.stringify(att, null, 2);
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  dependencyInventory,
  formatAttestation,
  verifyAttestation,
  witness
});
