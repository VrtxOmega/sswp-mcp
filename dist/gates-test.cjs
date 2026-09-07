"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/core/gate-runner.ts
var gate_runner_exports = {};
__export(gate_runner_exports, {
  gitIntegrityGate: () => gitIntegrityGate,
  lockfileGate: () => lockfileGate,
  reproducibleBuildGate: () => reproducibleBuildGate,
  runCommand: () => runCommand,
  runGates: () => runGates
});
module.exports = __toCommonJS(gate_runner_exports);
var import_node_child_process2 = require("node:child_process");
var import_node_fs2 = require("node:fs");
var import_node_path2 = require("node:path");
var import_node_os = require("node:os");
var import_node_crypto2 = require("node:crypto");

// src/core/source-state.ts
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var import_node_child_process = require("node:child_process");
var excluded = /* @__PURE__ */ new Set([".git", "node_modules", ".venv", "__pycache__", ".sswp.json"]);
function gitFiles(root, mode) {
  const args = ["-C", root, "ls-files", mode, "-z"];
  if (mode === "--others") args.push("--exclude-standard");
  args.push("--");
  const result2 = (0, import_node_child_process.spawnSync)("git", args, { env: { ...process.env, LC_ALL: "C" }, timeout: 1e4, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
  if (result2.error) {
    if (result2.error.code === "ENOENT") return null;
    throw Error("Cannot enumerate source inputs: " + result2.error.message);
  }
  if (result2.status !== 0) {
    const error = result2.stderr?.toString("utf8") || "Git source enumeration failed";
    if (error.toLowerCase().includes("not a git repository")) return null;
    throw Error("Cannot enumerate source inputs: " + error);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(result2.stdout).split("\0").filter(Boolean);
}
function sourceFiles(root) {
  root = (0, import_node_fs.realpathSync)(root);
  const tracked = gitFiles(root, "--cached");
  const candidates = /* @__PURE__ */ new Set();
  if (tracked !== null) {
    const other = gitFiles(root, "--others");
    if (other === null) throw Error("Git source enumeration became unavailable");
    for (const name of tracked) candidates.add(name);
    for (const name of other) if (!name.split("/").some((part) => excluded.has(part))) candidates.add(name);
  } else {
    const walk = (folder) => {
      for (const name of (0, import_node_fs.readdirSync)(folder)) {
        if (excluded.has(name)) continue;
        const path = (0, import_node_path.join)(folder, name), stat = (0, import_node_fs.lstatSync)(path);
        if (stat.isSymbolicLink()) throw Error("Source symlinks require an explicit packaged source snapshot");
        if (stat.isDirectory()) walk(path);
        else if (stat.isFile()) candidates.add((0, import_node_path.relative)(root, path).replaceAll("\\", "/"));
      }
    };
    walk(root);
  }
  const result2 = [];
  for (const name of [...candidates].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
    const parts = name.split("/");
    if ((0, import_node_path.isAbsolute)(name) || parts.includes("..")) throw Error("Source path escapes the approved root");
    let path = root, missing = false;
    for (const part of parts) {
      path = (0, import_node_path.join)(path, part);
      try {
        if ((0, import_node_fs.lstatSync)(path).isSymbolicLink()) throw Error("Source symlinks require an explicit packaged source snapshot");
      } catch (error) {
        if (["ENOENT", "ENOTDIR"].includes(error.code || "")) {
          missing = true;
          break;
        }
        throw error;
      }
    }
    if (missing) continue;
    const stat = (0, import_node_fs.lstatSync)(path);
    if (stat.isFile()) result2.push(name);
    else if (stat.isDirectory()) throw Error("Tracked directories/submodules require an explicit packaged source snapshot");
    else throw Error("Unsupported source file type");
  }
  return result2;
}
function sourceIdentity(root) {
  const hash = (0, import_node_crypto.createHash)("sha256");
  for (const name of sourceFiles(root)) hash.update(name + "\0" + (0, import_node_crypto.createHash)("sha256").update((0, import_node_fs.readFileSync)((0, import_node_path.join)(root, name))).digest("hex") + "\n");
  return hash.digest("hex");
}
function copySources(root, dest) {
  for (const name of sourceFiles(root)) {
    const target = (0, import_node_path.join)(dest, name);
    (0, import_node_fs.mkdirSync)((0, import_node_path.dirname)(target), { recursive: true });
    (0, import_node_fs.copyFileSync)((0, import_node_path.join)(root, name), target);
  }
}

// src/core/gate-runner.ts
async function runCommand(command, args, cwd, timeout = 6e4, env = {}) {
  return new Promise((resolve2) => {
    const child = (0, import_node_child_process2.spawn)(command, args, { cwd, shell: false, windowsHide: true, detached: process.platform !== "win32", env: { ...process.env, ...env } });
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
        const killer = (0, import_node_child_process2.spawn)("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true });
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
    } else if (stat.isFile()) manifest[(0, import_node_path2.relative)(root, p).replaceAll("\\", "/")] = (0, import_node_crypto2.createHash)("sha256").update((0, import_node_fs2.readFileSync)(p)).digest("hex");
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  gitIntegrityGate,
  lockfileGate,
  reproducibleBuildGate,
  runCommand,
  runGates
});
