import test from 'node:test';
import assert from 'node:assert/strict';
import { buildJsonReport } from '../../src/reports/json.ts';
import { buildHtmlReport } from '../../src/reports/html.ts';
import { buildPdfReport } from '../../src/reports/pdf.ts';
import { renderReport } from '../../src/reports/registry.ts';
import type { Finding, Scan } from '../../src/core/types.ts';
import { makeFingerprint, makeFindingId } from '../../src/core/ids.ts';

function fakeScan(): Scan {
  return {
    id: 'scan-1234', targetId: 't1', targetName: 'Test App', profile: 'standard-active',
    mode: 'active', status: 'completed',
    startedAt: '2026-10-26T10:00:00Z', finishedAt: '2026-10-26T10:03:00Z',
    engines: [
      { engine: 'builtin.crawler-lite', status: 'ran', findingCount: 0, durationMs: 100 },
      { engine: 'builtin.http-observation', status: 'ran', findingCount: 2, durationMs: 50 },
      { engine: 'adapter.zap', status: 'unavailable', findingCount: 0, durationMs: 0, detail: 'not installed' },
    ],
    coverage: [
      { category: 'A02', verdict: 'covered', engines: ['builtin.http-observation'], note: 'observable' },
      { category: 'A09', verdict: 'manual-only', engines: [], note: 'requires log access' },
    ],
    stats: {
      findingsBySeverity: { critical: 0, high: 1, medium: 1, low: 0, info: 0 },
      findingsByStatus: { confirmed: 2, probable: 0, informational: 0, false_positive: 0, untested: 0 },
      totalFindings: 2, requestsSent: 42, requestsBlocked: 3,
    },
  };
}

function fakeFinding(title: string, over: Partial<Finding> = {}): Finding {
  const fp = makeFingerprint('A02', 693, 'http://127.0.0.1:3000', '/');
  return {
    id: makeFindingId(fp, title, 'A02'),
    fingerprint: fp,
    title,
    category: 'A02',
    severity: 'high',
    confidence: 'high',
    status: 'confirmed',
    asset: 'http://127.0.0.1:3000',
    locator: '/',
    engine: 'builtin.http-observation',
    evidence: [{
      kind: 'http',
      request: { method: 'GET', url: 'http://127.0.0.1:3000/', headers: { Authorization: 'Bearer secret-token-value' } },
      response: { status: 200, headers: {}, bodyExcerpt: 'token=supersecretvalue123' },
      observation: 'observed',
    }],
    explanation: 'explanation text',
    remediation: 'remediation text',
    references: ['https://example.com/ref'],
    detectedAt: '2026-10-26T10:01:00Z',
    provenance: [{ engine: 'builtin.http-observation', rawId: 'missing-security-headers', adapter: false }],
    ...over,
  };
}

test('json report round-trips and contains scan + findings + coverage', () => {
  const scan = fakeScan();
  const findings = [fakeFinding('Missing headers'), fakeFinding('Other issue', { severity: 'medium' })];
  const report = buildJsonReport(scan, findings, '2026-10-26T11:00:00Z');
  assert.equal(report.schema, 'owasp-assessment-platform/report');
  assert.equal(report.scan.id, 'scan-1234');
  assert.equal(report.findings.length, 2);
  assert.equal(report.coverage.length, 2);
  assert.equal(report.summary.totalFindings, 2);
  assert.ok(report.disclaimer.includes('not proof'));
});

test('json report redacts secrets in evidence', () => {
  const report = JSON.stringify(buildJsonReport(fakeScan(), [fakeFinding('X')], '2026-10-26T11:00:00Z'));
  assert.ok(!report.includes('secret-token-value'), 'bearer token leaked into report');
  assert.ok(!report.includes('supersecretvalue123'), 'password assignment leaked into report');
});

test('html report is self-contained and includes findings and coverage', () => {
  const html = buildHtmlReport(fakeScan(), [fakeFinding('Missing headers')], '2026-10-26T11:00:00Z');
  assert.ok(html.startsWith('<!doctype html>'));
  assert.ok(html.includes('Missing headers'));
  assert.ok(html.includes('manual-only'));
  assert.ok(html.includes('Honest-limitations notice'));
  assert.ok(!html.includes('secret-token-value'));
});

test('pdf report has valid structure', () => {
  const bytes = buildPdfReport(fakeScan(), [fakeFinding('Missing headers'), fakeFinding('Verbose errors', { category: 'A10', cwe: 209 })]);
  const text = Buffer.from(bytes).toString('latin1');
  assert.ok(text.startsWith('%PDF-1.4'));
  assert.ok(text.trimEnd().endsWith('%%EOF'));
  assert.ok(text.includes('/Type /Catalog'));
  assert.ok(text.includes('startxref'));
  // xref entries are 10-digit offsets
  assert.match(text, /xref\n0 \d+\n0000000000 65535 f \n\d{10} 00000 n /);
  // metadata text present (pdf-escaped)
  assert.ok(text.includes('Executive summary'));
  assert.ok(text.includes('Missing headers'));
  assert.ok(!text.includes('secret-token-value'));
});

test('pdf xref offsets point at the right objects', () => {
  const bytes = buildPdfReport(fakeScan(), []);
  const text = Buffer.from(bytes).toString('latin1');
  const xrefStart = Number(/startxref\n(\d+)/.exec(text)![1]!);
  assert.equal(text.slice(xrefStart, xrefStart + 4), 'xref');
  // first object offset
  const m = /0000000000 65535 f \n(\d{10})/.exec(text)!;
  const objOffset = Number(m[1]);
  assert.equal(text.slice(objOffset, objOffset + 8), '1 0 obj\n');
});

test('renderReport dispatches and rejects unknown formats', () => {
  const scan = fakeScan();
  const findings = [fakeFinding('X')];
  assert.ok((renderReport(scan, findings, 'json') as string).length > 100);
  assert.ok((renderReport(scan, findings, 'html') as string).includes('<!doctype'));
  assert.ok((renderReport(scan, findings, 'pdf') as Uint8Array).byteLength > 1000);
  assert.throws(() => renderReport(scan, findings, 'xml'));
});
