/**
 * Report format registry.
 */
import type { Finding, Scan } from '../core/types.ts';
import { buildJsonReport } from './json.ts';
import { buildHtmlReport } from './html.ts';
import { buildPdfReport } from './pdf.ts';

export const SUPPORTED_FORMATS = ['json', 'html', 'pdf'] as const;
export type ReportFormat = (typeof SUPPORTED_FORMATS)[number];

export function renderReport(scan: Scan, findings: Finding[], format: string, generatedAt = new Date().toISOString(), opts: { fanoutOf?: (f: Finding) => number; quality?: import('../verify/metrics.ts').ScanQuality | undefined } = {}): string | Uint8Array {
  switch (format) {
    case 'json': return JSON.stringify(buildJsonReport(scan, findings, generatedAt, opts), null, 2);
    case 'html': return buildHtmlReport(scan, findings, generatedAt);
    case 'pdf': return buildPdfReport(scan, findings, generatedAt);
    default: throw new Error(`unsupported format: ${format}`);
  }
}
