/**
 * Scope/approval gate (newtask.md D4, I13).
 *
 * Scan requests that expand scope (a newly discovered domain, subdomain or
 * CIDR block beyond the registered target) must pass an explicit approval
 * record. Nothing auto-expands: the trigger rules emit approval.gate events
 * and the asset stays unscanned until an operator approves.
 */

export type ScopeKind = 'domain' | 'cidr' | 'origin';

export interface ScopeRecord {
  kind: ScopeKind;
  value: string;
  approved: boolean;
  approvedBy?: string | undefined;
  approvedAt?: string | undefined;
}

export class ScopeGate {
  private readonly records = new Map<string, ScopeRecord>();

  private key(kind: ScopeKind, value: string): string {
    return `${kind}:${value.trim().toLowerCase()}`;
  }

  register(kind: ScopeKind, value: string, approved = false): ScopeRecord {
    const r: ScopeRecord = { kind, value, approved };
    this.records.set(this.key(kind, value), r);
    return r;
  }

  approve(kind: ScopeKind, value: string, by: string): void {
    const existing = this.records.get(this.key(kind, value));
    const r: ScopeRecord = {
      kind, value, approved: true, approvedBy: by, approvedAt: new Date().toISOString(),
    };
    void existing;
    this.records.set(this.key(kind, value), r);
  }

  /** True when the value is an approved scope record (or a subdomain of an approved domain). */
  isApproved(kind: ScopeKind, value: string): boolean {
    const v = value.trim().toLowerCase();
    if (this.records.get(this.key(kind, v))?.approved === true) return true;
    if (kind === 'domain') {
      // a subdomain is approved when its registrable parent domain is approved
      const labels = v.split('.');
      if (labels.length > 2) {
        const parent = labels.slice(-2).join('.');
        return this.records.get(this.key('domain', parent))?.approved === true;
      }
    }
    return false;
  }
}
