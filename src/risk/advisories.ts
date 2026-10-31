/**
 * Offline advisory snapshot (hardtask.md L1) — CVE → CVSS/EPSS values for risk
 * base enrichment. Sourced from NVD + FIRST.org EPSS; this is an OFFLINE
 * snapshot (values current as of the snapshot date, EPSS shifts daily) —
 * refresh by replacing this file. Findings with a CVE not in the snapshot fall
 * back to severity-derived base with base_source: 'severity' (explicit).
 */
export interface AdvisoryEntry { cvss?: number; epss?: number; name?: string; }

export interface AdvisorySnapshot {
  snapshotDate: string;
  source: string;
  entries: Record<string, AdvisoryEntry>;
}

export const ADVISORY_SNAPSHOT: AdvisorySnapshot = {
  snapshotDate: '2026-10-31',
  source: 'NVD CVSS v3.1 + FIRST.org EPSS (offline snapshot — refresh periodically)',
  entries: {
    'CVE-2021-41773': { cvss: 9.8, epss: 0.966, name: 'Apache path traversal + RCE (2.4.49/2.4.50)' },
    'CVE-2021-42013': { cvss: 9.8, epss: 0.925, name: 'Apache path traversal bypass' },
    'CVE-2021-44228': { cvss: 10.0, epss: 0.976, name: 'Log4Shell JNDI RCE' },
    'CVE-2014-6271': { cvss: 10.0, epss: 0.874, name: 'Shellshock bash RCE' },
    'CVE-2017-0144': { cvss: 8.1, epss: 0.974, name: 'MS17-010 EternalBlue SMBv1' },
    'CVE-2019-0708': { cvss: 9.8, epss: 0.694, name: 'BlueKeep RDP RCE' },
    'CVE-2022-22965': { cvss: 9.8, epss: 0.945, name: 'Spring4Shell RCE' },
    'CVE-2015-3306': { cvss: 10.0, epss: 0.583, name: 'ProFTPD mod_copy arbitrary file copy' },
    'CVE-2018-15473': { cvss: 5.3, epss: 0.076, name: 'OpenSSH user enumeration' },
    'CVE-2020-14882': { cvss: 9.8, epss: 0.969, name: 'Oracle WebLogic console RCE' },
    'CVE-2023-44487': { cvss: 7.5, epss: 0.612, name: 'HTTP/2 Rapid Reset DoS' },
    'CVE-2019-11043': { cvss: 9.8, epss: 0.511, name: 'PHP-FPM buffer underflow RCE' },
  },
};

export interface BaseEnrichment { base: number; baseSource: 'epss' | 'cvss' | 'severity'; cve?: string | undefined; }

/**
 * L1: real base for CVE-bearing findings — max(CVSS/10, EPSS×1.4) from the
 * snapshot; falls back to the severity-derived base with base_source:
 * 'severity'. The spec's floor (0.05) and ceiling (1) apply to all paths.
 */
export function enrichBase(
  cve: string | undefined,
  severityBase: number,
  compute: (b: { cvss?: number | undefined; epss?: number | undefined }) => number = () => 0,
): BaseEnrichment {
  if (cve === undefined) return { base: severityBase, baseSource: 'severity' };
  const entry = ADVISORY_SNAPSHOT.entries[cve];
  if (entry === undefined) return { base: severityBase, baseSource: 'severity', cve };
  const real = compute({ cvss: entry.cvss, epss: entry.epss });
  return { base: real, baseSource: entry.epss !== undefined ? 'epss' : 'cvss', cve };
}
