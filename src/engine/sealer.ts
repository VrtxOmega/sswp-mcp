import { createHash } from 'node:crypto';
import type { PathLike } from 'node:fs';

export interface SealedEntry {
  timestamp: string;
  claim: string;
  evidence: string;
  hash: string;
  prev_hash: string | null;
  sequence: number;
}

let chain: SealedEntry[] = [];

export function initChain(ledgerPath?: PathLike): void {
  // In full impl, would load from disk. For now, fresh chain per run.
  chain = [];
}

export function seal(context: Record<string, unknown>, response: string): SealedEntry {
  const prev = chain[chain.length - 1] ?? null;
  const sequence = chain.length + 1;
  const entry: Omit<SealedEntry, 'hash'> = {
    timestamp: new Date().toISOString(),
    claim: JSON.stringify(context),
    evidence: response,
    prev_hash: prev?.hash ?? null,
    sequence,
  };
  const payload = `${entry.sequence}:${entry.timestamp}:${entry.claim}:${entry.evidence}:${entry.prev_hash ?? 'GENESIS'}`;
  const hash = createHash('sha256').update(payload).digest('hex');
  const sealed: SealedEntry = { ...entry, hash };
  chain.push(sealed);
  return sealed;
}

export function getChain(): readonly SealedEntry[] {
  return chain;
}

export function verifyChain(): boolean {
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].prev_hash !== chain[i - 1].hash) {
      return false;
    }
  }
  return true;
}
