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

// src/core/source-state.ts
var source_state_exports = {};
__export(source_state_exports, {
  copySources: () => copySources,
  excluded: () => excluded,
  sourceFiles: () => sourceFiles,
  sourceIdentity: () => sourceIdentity
});
module.exports = __toCommonJS(source_state_exports);
var import_node_crypto = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");
var import_node_child_process = require("node:child_process");
var excluded = /* @__PURE__ */ new Set([".git", "node_modules", ".venv", "__pycache__", ".sswp.json"]);
function gitFiles(root, mode) {
  const args = ["-C", root, "ls-files", mode, "-z"];
  if (mode === "--others") args.push("--exclude-standard");
  args.push("--");
  const result = (0, import_node_child_process.spawnSync)("git", args, { env: { ...process.env, LC_ALL: "C" }, timeout: 1e4, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
  if (result.error) {
    if (result.error.code === "ENOENT") return null;
    throw Error("Cannot enumerate source inputs: " + result.error.message);
  }
  if (result.status !== 0) {
    const error = result.stderr?.toString("utf8") || "Git source enumeration failed";
    if (error.toLowerCase().includes("not a git repository")) return null;
    throw Error("Cannot enumerate source inputs: " + error);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(result.stdout).split("\0").filter(Boolean);
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
  const result = [];
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
    if (stat.isFile()) result.push(name);
    else if (stat.isDirectory()) throw Error("Tracked directories/submodules require an explicit packaged source snapshot");
    else throw Error("Unsupported source file type");
  }
  return result;
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  copySources,
  excluded,
  sourceFiles,
  sourceIdentity
});
