/**
 * Engagement / Rules-of-Enforcement gate (newtasks.md E1).
 *
 * I19: state-changing is opt-in — a target with no engagement (or an
 * engagement with no permitted classes) runs read-only; exploit steps are
 * gated per class, default off.
 * I20: authorization before action — no exploit step outside an active
 * engagement window.
 * Violations produce explicit `blocked_by_roe` reasons — never a silent skip.
 */
import type { Engagement, ExploitClass } from '../core/types.ts';

export const EXPLOIT_CLASSES: ExploitClass[] = ['sqli', 'ssrf', 'traversal', 'idor', 'xss-reflection', 'open-redirect'];

/** E1 risk note: read-only default engagement — used when none is registered. */
export function readOnlyDefaultEngagement(origin: string): Engagement {
  return {
    id: 'readonly-default',
    name: `Read-only default engagement (no signed engagement for ${origin})`,
    scope: [origin],
    windowStart: '1970-01-01T00:00:00Z',
    windowEnd: '9999-12-31T23:59:59Z',
    contactsTechnical: 'unassigned',
    contactsEmergency: 'unassigned',
    emergencyStop: false,
    rateCeiling: 0,
    permittedClasses: [],
    signer: 'unassigned',
    attestationRef: 'none',
    active: true,
    createdAt: new Date().toISOString(),
  };
}

/** E1.2: window check — an active engagement must cover `now`. */
export function checkWindow(e: Engagement, now = new Date()): { allowed: boolean; reason?: string } {
  if (!e.active) return { allowed: false, reason: `blocked_by_roe: engagement ${e.id} is stopped or inactive` };
  if (e.emergencyStop) return { allowed: false, reason: `blocked_by_roe: emergency stop engaged on ${e.id}` };
  const t = now.getTime();
  const start = Date.parse(e.windowStart);
  const end = Date.parse(e.windowEnd);
  if (Number.isFinite(start) && t < start) {
    return { allowed: false, reason: `blocked_by_roe: outside engagement window (starts ${e.windowStart})` };
  }
  if (Number.isFinite(end) && t > end) {
    return { allowed: false, reason: `blocked_by_roe: outside engagement window (ended ${e.windowEnd})` };
  }
  return { allowed: true };
}

/** I19: exploit class check — an empty/absent list means read-only. */
export function classPermitted(e: Engagement | undefined, klass: ExploitClass): { allowed: boolean; reason?: string } {
  if (e === undefined || !e.active || e.emergencyStop) {
    return { allowed: false, reason: 'blocked_by_roe: read-only default engagement (no permitted exploit classes)' };
  }
  if (!e.permittedClasses.includes(klass)) {
    return { allowed: false, reason: `blocked_by_roe: exploit class '${klass}' not in engagement permitted_classes` };
  }
  return { allowed: true };
}

/** E1.2: the engagement's rate ceiling overrides the profile ceiling when lower. */
export function effectiveRateCeiling(e: Engagement | undefined, profileRps: number): number {
  if (e === undefined || e.rateCeiling === 0) return profileRps;
  return Math.min(e.rateCeiling, profileRps);
}
