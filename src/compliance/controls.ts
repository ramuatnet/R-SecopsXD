/**
 * Compliance control mapping (newtasks.md E5) — chapter-level mapping from
 * OWASP Top 10:2025 categories to ASVS v4 chapters, WSTG chapters and PCI DSS
 * requirement families. Chapter-level by design (fine-grained control ids need
 * per-task context); unmapped categories surface as gaps, never omissions.
 */
export interface ControlSet { asvs: string[]; wstg: string[]; pci: string[]; }

export const CATEGORY_CONTROLS: Record<string, ControlSet> = {
  A01: { asvs: ['ASVS-4.1', 'ASVS-4.2', 'ASVS-4.3'], wstg: ['WSTG-ATHZ-01', 'WSTG-ATHZ-02', 'WSTG-ATHZ-04'], pci: ['PCI-7.1', 'PCI-7.2'] },
  A02: { asvs: ['ASVS-14.4', 'ASVS-3.3', 'ASVS-3.4'], wstg: ['WSTG-CONF-04', 'WSTG-SESS-02'], pci: ['PCI-6.6', 'PCI-4.2'] },
  A03: { asvs: ['ASVS-1.9', 'ASVS-14.1'], wstg: ['WSTG-CONF-01'], pci: ['PCI-6.3.2'] },
  A04: { asvs: ['ASVS-6.1', 'ASVS-6.2', 'ASVS-9.1'], wstg: ['WSTG-CRYP-01', 'WSTG-CRYP-04'], pci: ['PCI-4.1'] },
  A05: { asvs: ['ASVS-5.1', 'ASVS-5.3', 'ASVS-5.4'], wstg: ['WSTG-INPV-01', 'WSTG-INPV-02'], pci: ['PCI-6.5.1'] },
  A06: { asvs: ['ASVS-1.14', 'ASVS-14.1'], wstg: ['WSTG-CONF-01', 'WSTG-CONF-02'], pci: ['PCI-2.2'] },
  A07: { asvs: ['ASVS-2.1', 'ASVS-2.5', 'ASVS-3.1'], wstg: ['WSTG-ATHN-03', 'WSTG-SESS-01'], pci: ['PCI-8.1', 'PCI-8.3'] },
  A08: { asvs: ['ASVS-1.14', 'ASVS-14.2'], wstg: ['WSTG-CLNT-12'], pci: ['PCI-6.4.3'] },
  A09: { asvs: ['ASVS-7.1', 'ASVS-7.2', 'ASVS-7.3'], wstg: ['WSTG-ERR-01', 'WSTG-LOGG-01'], pci: ['PCI-10.1'] },
  A10: { asvs: ['ASVS-7.4'], wstg: ['WSTG-ERR-02'], pci: ['PCI-6.5.5'] },
};

export interface ControlMapping { category: string; asvs: string[]; wstg: string[]; pci: string[]; }

export function controlsForCategory(category: string): ControlMapping {
  const c = CATEGORY_CONTROLS[category];
  if (c === undefined) {
    // E5: unmapped = a GAP, never an omission.
    return { category, asvs: [], wstg: [], pci: [] };
  }
  return { category, ...c };
}
