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
