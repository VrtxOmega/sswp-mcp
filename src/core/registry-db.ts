// src/sswp/core/registry-db.ts
/** Sovereign Software Witness Protocol — JSONL Registry */

import { createHash } from 'node:crypto';
import { readFileSync, appendFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { SswpAttestation } from './types.js';

export interface RegistryEntry {
  nodeId: string;
  timestamp: string;
  attestationHash: string;
  attestationPath: string;
  risk: number;
  passedGates: number;
  totalGates: number;
  suspiciousPackages: number;
}

const REGISTRY_PATH = process.env.SSWP_REGISTRY_PATH || join(homedir(), '.sswp_registry.jsonl');

function computeAttestationHash(att: SswpAttestation): string {
  return createHash('sha256').update(JSON.stringify(att)).digest('hex');
}

function readLines(): string[] {
  if (!existsSync(REGISTRY_PATH)) return [];
  const raw = readFileSync(REGISTRY_PATH, 'utf8');
  if (!raw.trim()) return [];
  return raw.split(/\r?\n/).filter(line => line.trim() !== '');
}

function parseLine(line: string): RegistryEntry | null {
  try {
    const obj = JSON.parse(line);
    if (!obj || typeof obj.nodeId !== 'string') return null;
    return obj as RegistryEntry;
  } catch {
    return null;
  }
}

/**
 * Persist an attestation record to the JSONL registry.
 */
export function saveAttestation(
  nodeId: string,
  att: SswpAttestation,
  attestationPath: string
): { entry: RegistryEntry; appended: boolean } {
  const entry: RegistryEntry = {
    nodeId,
    timestamp: att.timestamp,
    attestationHash: computeAttestationHash(att),
    attestationPath,
    risk: att.adversarial.overallRisk,
    passedGates: att.gates.filter(g => g.status === 'PASS').length,
    totalGates: att.gates.length,
    suspiciousPackages: att.adversarial.suspiciousPackages,
  };

  try {
    appendFileSync(REGISTRY_PATH, JSON.stringify(entry) + '\n', { encoding: 'utf8' });
    return { entry, appended: true };
  } catch (err) {
    console.error(`SSWP Registry append failed: ${err}`);
    return { entry, appended: false };
  }
}

/**
 * Retrieve full attestation history for a node, ordered oldest → newest.
 */
export function getAttestationHistory(nodeId: string): RegistryEntry[] {
  return readLines()
    .map(parseLine)
    .filter((e): e is RegistryEntry => e !== null && e.nodeId === nodeId)
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

/**
 * Get the most recent attestation for a node.
 */
export function getLatestAttestation(nodeId: string): RegistryEntry | null {
  const hist = getAttestationHistory(nodeId);
  return hist.length > 0 ? hist[hist.length - 1] : null;
}

/**
 * Find nodes whose latest risk exceeds a threshold.
 */
export function getRiskyNodes(threshold: number = 0.3): { nodeId: string; risk: number; timestamp: string }[] {
  const latestByNode = new Map<string, RegistryEntry>();
  for (const line of readLines()) {
    const e = parseLine(line);
    if (!e) continue;
    const existing = latestByNode.get(e.nodeId);
    if (!existing || new Date(e.timestamp) > new Date(existing.timestamp)) {
      latestByNode.set(e.nodeId, e);
    }
  }
  return Array.from(latestByNode.values())
    .filter(e => e.risk > threshold)
    .sort((a, b) => b.risk - a.risk)
    .map(e => ({ nodeId: e.nodeId, risk: e.risk, timestamp: e.timestamp }));
}

/**
 * Summarise all known nodes from the registry.
 */
export function getAllNodesStats(): {
  nodeId: string;
  latestRisk: number;
  latestTimestamp: string;
  witnessCount: number;
}[] {
  const counts = new Map<string, number>();
  const latestByNode = new Map<string, RegistryEntry>();
  for (const line of readLines()) {
    const e = parseLine(line);
    if (!e) continue;
    counts.set(e.nodeId, (counts.get(e.nodeId) || 0) + 1);
    const existing = latestByNode.get(e.nodeId);
    if (!existing || new Date(e.timestamp) > new Date(existing.timestamp)) {
      latestByNode.set(e.nodeId, e);
    }
  }
  return Array.from(latestByNode.values())
    .sort((a, b) => a.nodeId.localeCompare(b.nodeId))
    .map(e => ({
      nodeId: e.nodeId,
      latestRisk: e.risk,
      latestTimestamp: e.timestamp,
      witnessCount: counts.get(e.nodeId) || 0,
    }));
}

/**
 * Rebuild the registry file, removing corrupted or duplicate entries
 * (keeps only the latest per node per second to avoid near-dupes).
 */
export function compactRegistry(): { before: number; after: number } {
  const lines = readLines();
  const before = lines.length;
  const dedupe = new Map<string, RegistryEntry>();
  for (const line of lines) {
    const e = parseLine(line);
    if (!e) continue;
    const key = `${e.nodeId}::${e.timestamp}`;
    dedupe.set(key, e);
  }
  const sorted = Array.from(dedupe.values()).sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const rewritten = sorted.map(e => JSON.stringify(e)).join('\n') + (sorted.length ? '\n' : '');
  import('node:fs').then(fs => fs.writeFileSync(REGISTRY_PATH, rewritten, { encoding: 'utf8' }));
  return { before, after: sorted.length };
}
