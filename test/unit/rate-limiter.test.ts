import test from 'node:test';
import assert from 'node:assert/strict';
import { RateLimiter } from '../../src/safety/rateLimiter.ts';

test('burst allowed then throttled', async () => {
  const rl = new RateLimiter(50, 3); // fast for the test
  const t0 = Date.now();
  await rl.acquire('k'); await rl.acquire('k'); await rl.acquire('k'); // burst 3
  await rl.acquire('k'); // 4th must wait ~20ms at 50rps
  const dt = Date.now() - t0;
  assert.ok(dt >= 15, `4th acquire should have waited, dt=${dt}`);
});

test('independent keys do not interfere', async () => {
  const rl = new RateLimiter(1000, 2);
  await rl.acquire('a'); await rl.acquire('a');
  const t0 = Date.now();
  await rl.acquire('b'); await rl.acquire('b'); // b has full bucket
  assert.ok(Date.now() - t0 < 15);
});

test('tokens refill over time', async () => {
  const rl = new RateLimiter(200, 1);
  await rl.acquire('k');
  await new Promise((r) => setTimeout(r, 30)); // ~6 tokens refill, capped at 1... rate 200rps -> 6 tokens but burst 1
  const t0 = Date.now();
  await rl.acquire('k');
  assert.ok(Date.now() - t0 < 15, 'refilled token available immediately');
});

test('abort rejects pending acquire', async () => {
  const rl = new RateLimiter(1, 1);
  await rl.acquire('k');
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 10);
  await assert.rejects(() => rl.acquire('k', ac.signal), /aborted/);
});
