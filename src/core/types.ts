/**
 * Core domain types for the OWASP Top 10:2025 assessment platform.
 *
 * NOTE: this codebase runs via Node's native type stripping — only erasable
 * TypeScript syntax is allowed (no enums, namespaces or parameter properties).
 */

export type OwaspCategory =
  | 'A01' | 'A02' | 'A03' | 'A04' | 'A05'
  | 'A06' | 'A07' | 'A08' | 'A09' | 'A10';

/** Impact of the issue if exploited. Independent of confidence. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** How certain the detecting engine is that the observation is real. */
export type Confidence = 'high' | 'medium' | 'low';

/**
 * Human/workflow lifecycle of a finding.
 * - confirmed: deterministic evidence (the observation itself proves the issue) or human-verified
 * - probable: strong automated signal, needs verification
 * - informational: hygiene/inventory observation, not a vulnerability by itself
 * - false_positive: human triage rejected it
 * - untested: check not executed for this target/mode
 */
export type ValidationStatus =
  | 'confirmed' | 'probable' | 'informational' | 'false_positive' | 'untested';

export type ScanMode = 'passive' | 'active';

export type TargetKind = 'webapp' | 'source';

export interface Target {
  id: string;
  name: string;
  /** Approved origin, e.g. "http://127.0.0.1:3000" (no trailing slash). Empty for source targets. */
  origin: string;
  kind: TargetKind;
  /** Local filesystem path for kind === 'source'. */
  sourcePath?: string | undefined | undefined;
  approved: boolean;
  approvedAt?: string | undefined | undefined;
  approvedBy?: string | undefined | undefined;
  notes?: string | undefined | undefined;
  createdAt: string;
}

export interface HttpHeaders { [name: string]: string }

/** Redacted HTTP evidence captured by the scoped client. */
export interface HttpEvidence {
  kind: 'http';
  request: {
    method: string;
    url: string;
    headers: HttpHeaders; // redacted
  };
  response?: {
    status: number;
    headers: HttpHeaders; // redacted
    bodyExcerpt?: string; // redacted, <= 2048 chars
  };
  /** Plain-language statement of what was observed. */
  observation: string;
}

export interface FileEvidence {
  kind: 'file';
  path: string;
  lineStart?: number | undefined | undefined;
  lineEnd?: number | undefined | undefined;
  excerpt?: string | undefined | undefined;
  observation: string;
}

export interface ProcessEvidence {
  kind: 'process';
  command: string;
  exitCode?: number | undefined | undefined;
  durationMs?: number | undefined | undefined;
  stdoutExcerpt?: string | undefined | undefined;
  observation: string;
}

export interface DependencyEvidence {
  kind: 'dependency';
  ecosystem: string;
  packageName: string;
  installedVersion?: string | undefined | undefined;
  fixedVersion?: string | undefined | undefined;
  observation: string;
}

export type Evidence = HttpEvidence | FileEvidence | ProcessEvidence | DependencyEvidence;

export interface Provenance {
  engine: string;
  engineVersion?: string | undefined | undefined;
  /** Raw scanner finding id/rule, e.g. semgrep rule id or trivy vuln id. */
  rawId?: string | undefined | undefined;
  /** True when produced through an external tool adapter. */
  adapter: boolean;
}

export interface Finding {
  /** Stable content-hash ID, e.g. "FND-A05-3F9KQ2T7B8". Same issue+asset => same ID. */
  id: string;
  /** Dedup key across engines: sha256(category|cwe|asset|locator). */
  fingerprint: string;
  title: string;
  category: OwaspCategory;
  severity: Severity;
  confidence: Confidence;
  status: ValidationStatus;
  cwe?: number | undefined | undefined;
  cve?: string | undefined | undefined;
  /** Target origin or source path affected. */
  asset: string;
  /** More precise locator: URL path, file:line, package@version. */
  locator: string;
  engine: string;
  evidence: Evidence[];
  explanation: string;
  remediation: string;
  references: string[];
  detectedAt: string;
  provenance: Provenance[];
}

export type EngineStatus = 'ran' | 'unavailable' | 'failed' | 'skipped' | 'cancelled';

export interface EngineRunRecord {
  engine: string;
  status: EngineStatus;
  findingCount: number;
  durationMs: number;
  /** For unavailable: install hint. For failed: error message. */
  detail?: string | undefined | undefined;
  version?: string | undefined | undefined;
}

export type CategoryCoverage = 'covered' | 'partial' | 'manual-only';

/** Evidence-based coverage statuses (automation program Phase 13). */
export type CategoryCoverageStatus =
  | 'COVERED_WITH_EVIDENCE'
  | 'PARTIALLY_COVERED'
  | 'MANUAL_REVIEW_REQUIRED'
  | 'NOT_ASSESSED'
  | 'ASSESSMENT_FAILED';

export interface CoverageTaskResult {
  taskId: string;
  title: string;
  status: import('./tasks.ts').TaskStatus;
  findings: number;
  detail?: string | undefined;
}

export interface CoverageReport {
  category: OwaspCategory;
  /** Legacy capability-based verdict (v1) — kept for backward compatibility. */
  verdict: CategoryCoverage;
  /** Evidence-based status (v2) — derived from task execution results. */
  status?: CategoryCoverageStatus | undefined;
  /** Per-task execution evidence (v2). */
  tasks?: CoverageTaskResult[] | undefined;
  engines: string[];
  note: string;
}

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface Scan {
  id: string;
  targetId: string;
  targetName: string;
  profile: string;
  mode: ScanMode;
  status: ScanStatus;
  startedAt: string;
  finishedAt?: string | undefined | undefined;
  engines: EngineRunRecord[];
  coverage: CoverageReport[];
  stats: ScanStats;
  error?: string | undefined | undefined;
}

export interface ScanStats {
  findingsBySeverity: Record<Severity, number>;
  findingsByStatus: Record<ValidationStatus, number>;
  totalFindings: number;
  requestsSent: number;
  requestsBlocked: number;
}

/** Engine descriptor used by registry, UI and coverage computation. */
export interface EngineInfo {
  id: string;
  name: string;
  kind: 'builtin' | 'adapter';
  /** What this engine can contribute, per OWASP category, and with what limitation. */
  capabilities: Partial<Record<OwaspCategory, CategoryCapability>>;
  modes: ScanMode[];
  targetKinds: TargetKind[];
}

/** How strongly an engine covers a category — drives coverage verdicts. */
export interface CategoryCapability {
  note: string;
  strength: 'strong' | 'heuristic';
}

export interface EngineAvailability {
  available: boolean;
  version?: string | undefined | undefined;
  /** Present when not available. */
  reason?: string | undefined | undefined;
  installHint?: string | undefined | undefined;
}

export interface RawFinding {
  /** Engine-internal id (rule id, vuln id, check id). */
  rawId: string;
  title: string;
  category?: OwaspCategory | undefined;
  cwe?: number | undefined | undefined;
  cve?: string | undefined | undefined;
  severity?: Severity | undefined;
  confidence?: Confidence | undefined;
  status?: ValidationStatus | undefined;
  asset?: string | undefined;
  locator?: string | undefined;
  evidence: Evidence[];
  explanation: string;
  remediation: string;
  references?: string[] | undefined;
}

export interface AuditEntry {
  id?: number | undefined;
  ts: string;
  actor: string;
  action: string;
  details?: Record<string, unknown> | undefined;
}
