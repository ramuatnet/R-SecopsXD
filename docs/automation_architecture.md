# Automation Architecture — Assessment-Task Registry & Evidence-Based Coverage

Design for converting capability-based coverage (v1) into task-evidence-based
coverage (v2), per the automation program requirements. Additive and
backward-compatible: the canonical JSON report keeps every v1 field.

## Concepts

```
Profile (quick-passive, standard-active, source-review, …)
   └── selects AssessmentTasks (registry) + engines
AssessmentTask   = one automatable or manual check with its own identity
TaskResult       = per-scan execution record for one task
CategoryCoverage = aggregated from TaskResults (not from engine labels)
```

## Task registry (`src/core/tasks.ts`)

```ts
interface AssessmentTask {
  id: string;                 // 'A02-T01'
  category: OwaspCategory;
  title: string;
  description: string;
  engine: string;             // implementing engine id
  mode: ScanMode;             // 'passive' | 'active' — must match scan mode to execute
  targetKinds: TargetKind[];
  strength: 'strong' | 'heuristic';
  rawIdPattern?: string;      // substring match on finding provenance rawId → FINDING_DETECTED
  manual?: boolean;           // true = by-design human task; always MANUAL_REVIEW_REQUIRED
  requires?: ('authenticated' | 'external-tool')[];
  refs: string[];             // WSTG / cheat-sheet references
  evidenceExpectation: string;
}
```

Tasks are data, not code: new checks register themselves by adding an entry and (if
new) an engine. `mandatoryForProfile(profileId, task)` derives from mode+targetKinds:
a task is *required* when its engine is in the profile's engine plan for the scan's
mode and the target kind matches.

## Task states (spec Phase 2) and derivation

| State | Derived when |
|---|---|
| `FINDING_DETECTED` | engine ran AND ≥1 finding matched this task (engine + rawIdPattern) |
| `AUTOMATED_PASS` | engine ran, no matched findings |
| `ENGINE_UNAVAILABLE` | engine record status = `unavailable` |
| `ERROR` | engine record status = `failed` |
| `NOT_EXECUTED` | engine skipped (mode/target-kind mismatch) or scan cancelled before it ran |
| `MANUAL_REVIEW_REQUIRED` | task is `manual: true` (by design), or future: check reported inconclusive |
| `BLOCKED_BY_SAFETY` | future: payload/scope guard refused the task (none currently blocked by default) |

An unexecuted check is never a pass; an unavailable engine never implies absence.

## Coverage statuses (spec Phase 13) and derivation

Per category, over its tasks that are required for the profile:

- `COVERED_WITH_EVIDENCE` — all required tasks executed (AUTOMATED_PASS or
  FINDING_DETECTED) and none manual. Still reports scope limits in the note.
- `PARTIALLY_COVERED` — some required tasks executed, others NOT_EXECUTED /
  ENGINE_UNAVAILABLE / ERROR / manual.
- `MANUAL_REVIEW_REQUIRED` — all required tasks are manual, or none executed.
- `NOT_ASSESSED` — category has no tasks required by this profile (e.g. source-only
  tasks in a webapp scan).
- `ASSESSMENT_FAILED` — ≥1 required task ERROR and none executed successfully.

Legacy `verdict` mapping for backward compatibility:
`COVERED_WITH_EVIDENCE→covered`, `PARTIALLY_COVERED→partial`,
`MANUAL_REVIEW_REQUIRED`/`NOT_ASSESSED`/`ASSESSMENT_FAILED→manual-only`.

`CoverageReport` gains `status?` and `tasks?: Array<{ taskId, title, status,
findings, detail? }>`; `verdict`, `engines`, `note` unchanged. The orchestrator now
calls `computeCoverage(ranEngines, profileId, findings, targetKind, mode)`.

## Engine wiring (existing engines, no behavior change)

Engines keep producing RawFindings exactly as before; the task layer only *observes*
engine records + findings. `rawIdPattern` ties findings to tasks (e.g. task A08-T01
SRI matches rawId `sri-external-script`).

## Safety

Nothing in the task layer sends requests — it derives from engine execution. Active
tasks execute only in active scans (existing profile plan behavior), so the
passive-by-default guarantee is unchanged. A blocked future task must surface
`BLOCKED_BY_SAFETY`, never a pass.

## Rollback

`computeCoverage` v1 is retained as `computeCoverageV1` (used by a regression test
that asserts v2 only *adds* fields). Deleting the `status`/`tasks` fields from the
report (or reverting the orchestrator call) restores v1 output byte-for-byte.
