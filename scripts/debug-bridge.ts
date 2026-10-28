// Minimal repro: bridge + DELETE rejection
import { createServer as createHttpServer } from 'node:http';
import { EngineBridge } from '../src/engine-bridge/bridge.ts';

const server = createHttpServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://x');
  if (url.pathname === '/x') { res.writeHead(200); res.end('ok'); return; }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ ok: true }));
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

const bridge = new EngineBridge();
bridge.start();
const base = { scan_id: 's', action_id: 'a', scope: { origins: [origin], allow_public: true }, safety: { rate_per_sec: 200, burst: 50 }, budget: { max_requests: 50 } };

try {
  const r = await bridge.call('http.delete', { ...base, args: { url: `${origin}/x` } });
  console.log('DELETE RESOLVED (bad):', JSON.stringify(r));
} catch (e) {
  console.log('DELETE rejected (good):', (e as { code?: string }).code, '-', (e as Error).message);
}

bridge.stop();
server.close();
process.exit(0);
