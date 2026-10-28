import test from 'node:test';
import assert from 'node:assert/strict';
import { redactHeaders, redactText, redactValue } from '../../src/core/redact.ts';

test('auth-ish headers are redacted', () => {
  const out = redactHeaders({
    'Content-Type': 'text/html',
    Authorization: 'Bearer eyJhbGciOi.eyJzdWIi.SflKxwRJSMeKKF2QT4',
    Cookie: 'session=abc123; theme=dark',
    'Set-Cookie': 'sid=deadbeef; Path=/',
  });
  assert.equal(out['Content-Type'], 'text/html');
  assert.match(out.Authorization!, /REDACTED/);
  assert.ok(!out.Authorization!.includes('eyJhbGciOi'));
  assert.match(out.Cookie!, /REDACTED/);
  assert.match(out['Set-Cookie']!, /REDACTED/);
});

test('known token shapes redacted in free text', () => {
  const t = redactText(
    'key=AKIAIOSFODNN7EXAMPLE gh=ghp_abc123def456ghi789jklm sk-proj-abcdef1234567890abcdef',
  );
  assert.ok(!t.includes('AKIAIOSFODNN7EXAMPLE'));
  assert.ok(!t.includes('ghp_abc'));
  assert.ok(!t.includes('sk-proj-abcdef'));
  assert.ok(t.includes('REDACTED'));
});

test('JWTs redacted in body excerpts', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnopqrstuvwxyz012345';
  const t = redactText(`token: ${jwt}`);
  assert.ok(!t.includes(jwt));
});

test('private keys redacted', () => {
  const t = redactText('-----BEGIN RSA PRIVATE KEY-----\nMIIEpA\n-----END RSA PRIVATE KEY-----');
  assert.ok(!t.includes('MIIEpA'));
  assert.match(t, /REDACTED-PRIVATE-KEY/);
});

test('password assignments redacted', () => {
  const t = redactText('DB_PASSWORD=Sup3rS3cretValue!2026');
  assert.ok(!t.includes('Sup3rS3cret'));
});

test('long text truncated with marker', () => {
  const t = redactText('x'.repeat(5000), 2048);
  assert.ok(t.length < 2200);
  assert.match(t, /truncated/);
});

test('redactValue passes through ordinary header values', () => {
  assert.equal(redactValue('Content-Type', 'text/html'), 'text/html');
});
