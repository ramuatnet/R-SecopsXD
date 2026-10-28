/**
 * Normalization: RawFinding (engine output) → Finding (platform model).
 * Applies stable IDs, category classification, severity/confidence defaults,
 * and stored human triage decisions.
 */
import type {
  Confidence, Finding, OwaspCategory, Provenance, RawFinding, Severity, Target,
  ValidationStatus,
} from '../core/types.ts';
import { classifyFinding } from '../core/cweMap.ts';
import { makeFingerprint, makeFindingId } from '../core/ids.ts';

export interface NormalizeOptions {
  target: Target;
  engineId: string;
  engineVersion?: string | undefined;
  adapter: boolean;
  triages: Map<string, ValidationStatus>;
  now?: Date;
}

const DEFAULT_SEVERITY: Severity = 'medium';
const DEFAULT_CONFIDENCE: Confidence = 'medium';

export function normalizeFinding(raw: RawFinding, opts: NormalizeOptions): Finding {
  const now = (opts.now ?? new Date()).toISOString();
  const category: OwaspCategory = raw.category ?? classifyFinding(raw.cwe, raw.title);
  const severity = raw.severity ?? DEFAULT_SEVERITY;
  const confidence = raw.confidence ?? DEFAULT_CONFIDENCE;
  const asset = raw.asset ?? (opts.target.kind === 'source' ? opts.target.sourcePath ?? opts.target.name : opts.target.origin);
  const locator = raw.locator ?? '/';

  const fingerprint = makeFingerprint(category, raw.cwe, asset, locator);
  let id = makeFindingId(fingerprint, raw.title, category);

  const provenance: Provenance = {
    engine: opts.engineId,
    engineVersion: opts.engineVersion,
    rawId: raw.rawId,
    adapter: opts.adapter,
  };

  // Human triage decisions survive rescans by fingerprint.
  let status: ValidationStatus = raw.status ?? 'probable';
  const triaged = opts.triages.get(fingerprint);
  if (triaged === 'false_positive') {
    status = 'false_positive';
  }

  return {
    id,
    fingerprint,
    title: raw.title,
    category,
    severity,
    confidence,
    status,
    cwe: raw.cwe,
    cve: raw.cve,
    asset,
    locator,
    engine: opts.engineId,
    evidence: raw.evidence,
    explanation: raw.explanation,
    remediation: raw.remediation,
    references: raw.references ?? [],
    detectedAt: now,
    provenance: [provenance],
  };
}
