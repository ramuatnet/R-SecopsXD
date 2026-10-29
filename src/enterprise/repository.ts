/**
 * Postgres driver interface (v2 T10.1) — behind a repository interface so
 * SQLite stays the default; Postgres for team/scale deployments.
 * T10.2 RBAC: roles, per-target authz chains. Single-operator SQLite skips RBAC.
 *
 * v2: the interface is defined and the SQLite adapter implements it; Postgres
 * adapter is a drop-in when DATABASE_URL is set.
 */
export interface ScanRepository {
  listTargets(opts?: { orgId?: string; role?: string }): Promise<unknown[]>;
  getTarget(id: string): Promise<unknown | undefined>;
  listScans(targetId?: string, opts?: { orgId?: string; role?: string }): Promise<unknown[]>;
  getFindings(scanId: string): Promise<unknown[]>;
  canAccess(userId: string, targetId: string, action: 'read' | 'scan' | 'approve' | 'admin'): Promise<boolean>;
}

/** T10.2 RBAC role definitions. */
export const ROLES = {
  viewer: { canRead: true, canScan: false, canApprove: false, canAdmin: false },
  scanner: { canRead: true, canScan: true, canApprove: false, canAdmin: false },
  approver: { canRead: true, canScan: true, canApprove: true, canAdmin: false },
  admin: { canRead: true, canScan: true, canApprove: true, canAdmin: true },
} as const;

export type Role = keyof typeof ROLES;

export function canPerform(role: Role, action: 'read' | 'scan' | 'approve' | 'admin'): boolean {
  return ROLES[role]?.[action === 'read' ? 'canRead' : action === 'scan' ? 'canScan' : action === 'approve' ? 'canApprove' : 'canAdmin'] ?? false;
}
