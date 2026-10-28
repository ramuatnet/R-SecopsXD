import test from 'node:test';
import assert from 'node:assert/strict';
import { categoryForCwe, categoryForTitle, classifyFinding, severityFromCvss } from '../../src/core/cweMap.ts';

test('CWE mapping covers key cases', () => {
  assert.equal(categoryForCwe(79), 'A05'); // XSS → injection family 2025
  assert.equal(categoryForCwe(89), 'A05'); // SQLi
  assert.equal(categoryForCwe(918), 'A01'); // SSRF filed under A01 in the 2025 final
  assert.equal(categoryForCwe(22), 'A01'); // path traversal
  assert.equal(categoryForCwe(352), 'A01'); // CSRF (official 2025 A01 list)
  assert.equal(categoryForCwe(327), 'A04'); // broken crypto
  assert.equal(categoryForCwe(798), 'A07'); // hardcoded creds → auth
  assert.equal(categoryForCwe(502), 'A08'); // deserialization
  assert.equal(categoryForCwe(1321), 'A08'); // prototype pollution
  assert.equal(categoryForCwe(532), 'A09'); // secrets in logs
  assert.equal(categoryForCwe(209), 'A10'); // error disclosure
  assert.equal(categoryForCwe(undefined), undefined);
});

test('2021 OWASP tags translated to 2025 numbering', () => {
  assert.equal(classifyFinding(undefined, 'x', 'owasp-top-ten:a03'), 'A05'); // 2021 A03 injection → A05
  assert.equal(classifyFinding(undefined, 'x', 'A05:2021'), 'A02'); // 2021 A05 misconfig → A02
  assert.equal(classifyFinding(undefined, 'x', 'A02:2021'), 'A04'); // 2021 A02 crypto → A04
  assert.equal(classifyFinding(undefined, 'x', 'A01:2021'), 'A01');
});

test('2025-tagged codes are not translated', () => {
  assert.equal(classifyFinding(undefined, 'x', 'A05:2025'), 'A05');
  assert.equal(classifyFinding(undefined, 'x', 'A10:2025'), 'A10');
});

test('title fallback classification', () => {
  assert.equal(categoryForTitle('SQL Injection in search'), 'A05');
  assert.equal(categoryForTitle('Missing Content-Security-Policy header'), 'A02');
  assert.equal(categoryForTitle('Stack trace disclosed in response'), 'A10');
  assert.equal(categoryForTitle('something unrelated'), undefined);
});

test('classifyFinding defaults to A02 when nothing matches', () => {
  assert.equal(classifyFinding(undefined, 'unknown odd issue'), 'A02');
});

test('CVSS to severity', () => {
  assert.equal(severityFromCvss(9.8), 'critical');
  assert.equal(severityFromCvss(7.2), 'high');
  assert.equal(severityFromCvss(5.0), 'medium');
  assert.equal(severityFromCvss(2.1), 'low');
  assert.equal(severityFromCvss(undefined), 'medium');
});
