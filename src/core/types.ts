// src/sswp/core/types.ts
/** Sovereign Software Witness Protocol — Core Types (v1.1 polyglot) */

export interface SswpAttestation {
  id?: string;
  version: string;
  timestamp: string;
  projectType?: string; // node | python | go | rust | html | unknown
  target: {
    name: string;
    repo: string;
    commitHash: string;
    branch: string;
  };
  environment: {
    nodeVersion: string;
    os: string;
    arch: string;
    ci: boolean;
  };
  dependencies: DependencyEntry[];
  gates: GateResult[];
  /** Computed overall status: PASS (no FAILs, no INCONCLUSIVE), WARN (no FAILs, some INCONCLUSIVE), FAIL (any FAIL) */
  overallStatus?: 'PASS' | 'WARN' | 'FAIL';
  adversarial: AdversarialReport;
  seal: {
    chainHash: string;
    sequence: number;
  };
  /** Gap #4: VERITAS cross-system correlation ID (VT-YYYYMMDD-xxxxxxxx) */
  traceId?: string;
  /** Gap #3: Cortex governance state at time of witness */
  governance?: {
    cortexVerdict: 'APPROVED' | 'STEERED' | 'NOT_CHECKED';
    cortexGoverned: boolean;
  };
  signature: string; // sha256 of attestation JSON (excludes signature field itself)
}

export interface DependencyEntry {
  name: string;
  version: string;
  resolved: string;
  integrity: string | null;
  suspicious: boolean;
  riskScore: number; // 0-1
}

export interface GateResult {
  gate: string;
  status: 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'WARN';
  evidence: string;
  durationMs: number;
}

export interface AdversarialReport {
  totalPackages: number;
  suspiciousPackages: number;
  probes: ProbeResult[];
  overallRisk: number; // 0-1
}

export interface ProbeResult {
  package: string;
  probe: string;
  result: 'PASS' | 'WARN' | 'CRITICAL' | 'INCONCLUSIVE';
  detail: string;
}

export interface BuildEnvironment {
  cwd: string;
  nodeVersion: string;
  os: string;
  arch: string;
  ci: boolean;
  buildCommand: string;
  buildOutput: string;
}
