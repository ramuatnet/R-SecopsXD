/**
 * Precision/recall measurement (v2 T11.2) — formalized ground-truth gate.
 *
 * Compare the set of actual finding fingerprints (or rawIds) against the
 * truth list. Precision = TP/(TP+FP), Recall = TP/(TP+FN).
 * Used as a CI gate: regressions fail the build.
 */
export interface PrecisionRecall {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
}

export function computePrecisionRecall(truthIds: string[], actualIds: string[]): PrecisionRecall {
  const truth = new Set(truthIds);
  const actual = new Set(actualIds);
  const tp = [...actual].filter((id) => truth.has(id)).length;
  const fp = actual.size - tp;
  const fn = truth.size - tp;
  const precision = actual.size === 0 ? 1 : tp / actual.size;
  const recall = truth.size === 0 ? 1 : tp / truth.size;
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { truePositives: tp, falsePositives: fp, falseNegatives: fn, precision, recall, f1 };
}

// ---------- G1: per-class precision/recall harness (newtask.md) ----------

export interface ClassPr {
  precision: number;
  recall: number;
  f1: number;
  tp: number;
  fp: number;
  fn: number;
}

/**
 * Per-class P/R/F1 over labeled examples. Each item is one example: its class
 * (e.g. finding rawId or OWASP category), whether the engine predicted it and
 * whether ground truth says it exists. Classes with no ground-truth positives
 * are reported with recall = 1 by convention (nothing was missed by
 * definition) — the same convention as computePrecisionRecall.
 */
export function precisionRecallByClass(
  items: Array<{ klass: string; predicted: boolean; truth: boolean }>,
): Record<string, ClassPr> {
  const out: Record<string, ClassPr> = {};
  for (const it of items) {
    const c = out[it.klass] ?? { precision: 0, recall: 0, f1: 0, tp: 0, fp: 0, fn: 0 };
    if (it.predicted && it.truth) c.tp += 1;
    else if (it.predicted && !it.truth) c.fp += 1;
    else if (!it.predicted && it.truth) c.fn += 1;
    out[it.klass] = c;
  }
  for (const c of Object.values(out)) {
    const predicted = c.tp + c.fp;
    const truth = c.tp + c.fn;
    c.precision = predicted === 0 ? 1 : c.tp / predicted;
    c.recall = truth === 0 ? 1 : c.tp / truth;
    c.f1 = c.precision + c.recall === 0 ? 0 : (2 * c.precision * c.recall) / (c.precision + c.recall);
  }
  return out;
}

// ---------- I3 (hardtask.md): per-scan recall/precision against ground truth ----------

export interface TruthItem {
  id?: string;
  category?: string;
  match?: { cwe?: number; locatorContains?: string; titleContains?: string; port?: number };
}

export interface ScanQuality {
  recall: number;
  precision: number;
  matchedTruth: string[];
  totalTruth: number;
  totalFindings: number;
  basis: string;
}

/**
 * Recall/precision of a scan against a ground-truth file (fixtures/<app>/truth.json).
 * A truth item matches when any finding satisfies ALL of its match rules
 * (cwe equality, locator/title substring, port suffix). Precision counts
 * findings that match at least one truth item — meaningful only where every
 * real issue is planted (fixtures).
 */
export function scoreAgainstTruth(findings: Array<{ category?: string; cwe?: number | undefined; locator?: string; title?: string }>, truth: TruthItem[]): ScanQuality {
  const matched: string[] = [];
  const matchedFindingIdx = new Set<number>();
  for (const item of truth) {
    const m = item.match ?? {};
    let hit = false;
    findings.forEach((f, idx) => {
      if (hit) return;
      const cweOk = m.cwe === undefined || f.cwe === m.cwe;
      const locOk = m.locatorContains === undefined || (f.locator ?? '').includes(m.locatorContains);
      const titleOk = m.titleContains === undefined || (f.title ?? '').toLowerCase().includes(m.titleContains.toLowerCase());
      const portOk = m.port === undefined || (f.locator ?? '').endsWith(':' + String(m.port));
      if (cweOk && locOk && titleOk && portOk) { hit = true; matchedFindingIdx.add(idx); }
    });
    if (hit && item.id !== undefined) matched.push(item.id);
  }
  const recall = truth.length === 0 ? 1 : matched.length / truth.length;
  const precision = findings.length === 0 ? 1 : matchedFindingIdx.size / findings.length;
  return { recall, precision, matchedTruth: matched, totalTruth: truth.length, totalFindings: findings.length, basis: 'ground-truth-fixture' };
}
