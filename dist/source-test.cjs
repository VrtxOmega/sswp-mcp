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
var excluded = /* @__PURE__ */ new Set([".git", "node_modules", ".venv", "data", "__pycache__", ".sswp.json"]);
function sourceFiles(root) {
  const result = [];
  const walk = (folder) => {
    for (const name of (0, import_node_fs.readdirSync)(folder)) {
      if (excluded.has(name)) continue;
      const p = (0, import_node_path.join)(folder, name), s = (0, import_node_fs.lstatSync)(p);
      if (s.isSymbolicLink()) throw Error("Source symlinks require an explicit packaged source snapshot");
      if (s.isDirectory()) walk(p);
      else if (s.isFile()) result.push((0, import_node_path.relative)(root, p).replaceAll("\\", "/"));
    }
  };
  walk(root);
  return result.sort();
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
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  copySources,
  excluded,
  sourceFiles,
  sourceIdentity
});
