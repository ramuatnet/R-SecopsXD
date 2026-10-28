import test from 'node:test';
import assert from 'node:assert/strict';
import { ScopeGuard, ScopeError, isPrivateHost, parseOrigin } from '../../src/safety/guard.ts';

const OPTS = { allowPublicTargets: false, maxRedirectHops: 5 };

test('loopback origin accepted; matching URL in scope', () => {
  const g = new ScopeGuard('http://127.0.0.1:3000', OPTS);
  g.checkUrl('http://127.0.0.1:3000/search?q=x');
  g.checkUrl('http://127.0.0.1:3000/a/b/c');
  assert.ok(g.inScope('http://127.0.0.1:3000/'));
});

test('wrong port and wrong host are out of scope', () => {
  const g = new ScopeGuard('http://127.0.0.1:3000', OPTS);
  assert.throws(() => g.checkUrl('http://127.0.0.1:8080/'), ScopeError);
  assert.throws(() => g.checkUrl('http://localhost:3000/'), ScopeError);
  assert.throws(() => g.checkUrl('http://evil.example:3000/'), ScopeError);
});

test('non-http schemes and embedded credentials blocked', () => {
  const g = new ScopeGuard('http://127.0.0.1:3000', OPTS);
  assert.throws(() => g.checkUrl('file:///etc/passwd'), ScopeError);
  assert.throws(() => g.checkUrl('ftp://127.0.0.1:3000/'), ScopeError);
  assert.throws(() => g.checkUrl('http://admin:x@127.0.0.1:3000/'), ScopeError);
});

test('public target refused by default, allowed when opted in', () => {
  assert.throws(() => new ScopeGuard('https://example.com', OPTS), ScopeError);
  const g = new ScopeGuard('https://example.com', { ...OPTS, allowPublicTargets: true });
  g.checkUrl('https://example.com/x');
});

test('redirect hop validated: in-scope ok, off-scope blocked', () => {
  const g = new ScopeGuard('http://127.0.0.1:3000', OPTS);
  const next = g.checkRedirect('http://127.0.0.1:3000/login', '/dashboard', 0);
  assert.equal(next.toString(), 'http://127.0.0.1:3000/dashboard');
  g.checkRedirect('http://127.0.0.1:3000/login', 'http://127.0.0.1:3000/x', 1);
  assert.throws(
    () => g.checkRedirect('http://127.0.0.1:3000/login', 'http://evil.example/', 1),
    ScopeError,
  );
});

test('redirect hop cap enforced', () => {
  const g = new ScopeGuard('http://127.0.0.1:3000', { ...OPTS, maxRedirectHops: 2 });
  g.checkRedirect('http://127.0.0.1:3000/a', '/b', 1);
  assert.throws(() => g.checkRedirect('http://127.0.0.1:3000/a', '/c', 5), ScopeError);
});

test('isPrivateHost classification', () => {
  for (const h of ['127.0.0.1', '10.0.0.5', '192.168.1.2', '172.16.0.1', '172.31.255.255', '169.254.1.1', 'localhost', '::1']) {
    assert.ok(isPrivateHost(h), `${h} should be private`);
  }
  for (const h of ['example.com', '8.8.8.8', '172.32.0.1', '1.2.3.4']) {
    assert.ok(!isPrivateHost(h), `${h} should be public`);
  }
});

test('parseOrigin defaults ports by scheme', () => {
  assert.equal(parseOrigin('http://127.0.0.1').port, 80);
  assert.equal(parseOrigin('https://127.0.0.1').port, 443);
  assert.equal(parseOrigin('http://127.0.0.1:3000').port, 3000);
  assert.throws(() => parseOrigin('notaurl'), ScopeError);
  assert.throws(() => parseOrigin('ftp://x/'), ScopeError);
});
