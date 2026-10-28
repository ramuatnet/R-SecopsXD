import test from 'node:test';
import assert from 'node:assert/strict';
import { validateOutbound, REFLECTION_MARKER } from '../../src/safety/payloadGuard.ts';

test('plain GET passes', () => {
  assert.deepEqual(validateOutbound('GET', 'http://127.0.0.1:3000/'), { ok: true });
});

test('benign reflection marker passes', () => {
  const r = validateOutbound('GET', `http://127.0.0.1:3000/search?q=${REFLECTION_MARKER}`);
  assert.deepEqual(r, { ok: true });
});

test('destructive commands refused', () => {
  for (const body of [
    'q=; rm -rf /',
    'q=; DROP TABLE users',
    'q=../../etc/passwd',
    'q={{7*7}}',
    'q=<!ENTITY xxe SYSTEM "file:///etc/passwd">',
    'cmd=shutdown /s',
  ]) {
    const r = validateOutbound('POST', 'http://127.0.0.1:3000/x', body);
    assert.equal(r.ok, false, body);
  }
});

test('destructive payload in URL refused too', () => {
  const r = validateOutbound('GET', 'http://127.0.0.1:3000/download?f=../../etc/shadow');
  assert.equal(r.ok, false);
});

test('non-permitted methods refused', () => {
  assert.equal(validateOutbound('DELETE', 'http://127.0.0.1:3000/x').ok, false);
  assert.equal(validateOutbound('PUT', 'http://127.0.0.1:3000/x').ok, false);
});

test('oversized body refused', () => {
  const r = validateOutbound('POST', 'http://127.0.0.1:3000/', 'q=' + 'a'.repeat(9 * 1024));
  assert.equal(r.ok, false);
});

test('ordinary POST body under limit passes', () => {
  const r = validateOutbound('POST', 'http://127.0.0.1:3000/login', 'username=probe&password=probe');
  assert.deepEqual(r, { ok: true });
});
