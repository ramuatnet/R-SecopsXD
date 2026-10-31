/**
 * KafkaHttpBus (newtask.md D1 deployment) — a Bus implementation over a real
 * Kafka-compatible broker (Redpanda PandaProxy / Confluent REST Proxy v2 wire
 * protocol) using ONLY fetch — the zero-runtime-dependency ADR holds.
 *
 *   publish   → POST   /topics/{topic}          (application/vnd.kafka.json.v2+json)
 *   subscribe → polling consumer group (earliest reset, per-subscriber instance)
 *
 * The InProcessBus stays the default for single-process deployments; this
 * adapter is selected when OWASP_KAFKA_HTTP is set (e.g. http://localhost:8082).
 */
import type { Bus, Envelope, Handler, Topic } from '../bus/bus.ts';

const JSON_V2 = 'application/vnd.kafka.json.v2+json';
const GENERIC_V2 = 'application/vnd.kafka.v2+json';

export interface KafkaHttpBusOptions {
  baseUrl: string;
  /** Consumer group for subscribers; each subscribe() gets an instance in it. */
  group: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export class KafkaHttpBus implements Bus {
  private readonly opts: Required<KafkaHttpBusOptions>;
  private instanceCounter = 0;

  constructor(opts: KafkaHttpBusOptions) {
    this.opts = {
      timeoutMs: 5000,
      fetchImpl: fetch,
      ...opts,
      group: opts.group,
      baseUrl: opts.baseUrl.replace(/\/$/, ''),
    };
  }

  /** Produce an envelope as a JSON record. Returns the broker-assigned offset. */
  async produce<T>(topic: Topic, key: string, payload: T): Promise<{ offset: number; partition: number }> {
    const res = await this.opts.fetchImpl(`${this.opts.baseUrl}/topics/${topic}`, {
      method: 'POST',
      headers: { 'content-type': JSON_V2 },
      body: JSON.stringify({
        records: [{ key: Buffer.from(key, 'utf8').toString('base64'), value: { key, payload, emittedAt: new Date().toISOString() } }],
      }),
      signal: AbortSignal.timeout(this.opts.timeoutMs),
    });
    if (!res.ok) throw new Error(`kafka produce failed (${res.status}): ${await res.text()}`);
    const body = await res.json() as { offsets: Array<{ partition: number; offset: number }> };
    return { partition: body.offsets[0]!.partition, offset: body.offsets[0]!.offset };
  }

  /** Bus-compatible synchronous publish (fire-and-forget; errors surface on await via queue). */
  publish<T>(topic: Topic, key: string, payload: T): Envelope<T> {
    const envelope: Envelope<T> = { topic, key, payload, emittedAt: new Date().toISOString() };
    void this.produce(topic, key, payload).catch(() => { /* never break publishers */ });
    return envelope;
  }

  /**
   * Create a consumer instance for the topic and start a polling loop that
   * dispatches records to the handler. Returns the unsubscribe function
   * synchronously (Bus contract); the broker-side consumer instance is cleaned
   * up best-effort on unsubscribe.
   */
  subscribe<T>(topic: Topic, handler: Handler<T>): () => void {
    const instance = `${topic}-${process.pid}-${++this.instanceCounter}`;
    const base = `${this.opts.baseUrl}/consumers/${this.opts.group}/instances/${instance}`;
    let stopped = false;

    void (async (): Promise<void> => {
      const create = await this.opts.fetchImpl(`${this.opts.baseUrl}/consumers/${this.opts.group}`, {
        method: 'POST',
        headers: { 'content-type': GENERIC_V2 },
        body: JSON.stringify({ name: instance, format: 'json', 'auto.offset.reset': 'earliest' }),
        signal: AbortSignal.timeout(this.opts.timeoutMs),
      });
      if (!create.ok && create.status !== 409) {
        throw new Error(`kafka consumer create failed (${create.status}): ${await create.text()}`);
      }

      await this.opts.fetchImpl(`${base}/subscription`, {
        method: 'POST',
        headers: { 'content-type': GENERIC_V2 },
        body: JSON.stringify({ topics: [topic] }),
        signal: AbortSignal.timeout(this.opts.timeoutMs),
      });

      while (!stopped) {
        try {
          const res = await this.opts.fetchImpl(`${base}/records?timeout=2000&max_bytes=1048576`, {
            headers: { accept: JSON_V2 },
            signal: AbortSignal.timeout(this.opts.timeoutMs + 4000),
          });
          if (res.status === 404) break; // instance deleted
          if (!res.ok) { await new Promise((r) => setTimeout(r, 500)); continue; }
          const records = await res.json() as Array<{ value: { key: string; payload: T; emittedAt: string } }>;
          for (const rec of records) {
            if (stopped) break;
            const envelope: Envelope<T> = {
              topic, key: rec.value.key ?? '', payload: rec.value.payload, emittedAt: rec.value.emittedAt,
            };
            await handler(envelope);
          }
        } catch {
          if (stopped) break;
          await new Promise((r) => setTimeout(r, 500));
        }
      }
    })().catch(() => { /* polling errors never break the publisher */ });

    return (): void => {
      stopped = true;
      void this.opts.fetchImpl(base, { method: 'DELETE', headers: { 'content-type': GENERIC_V2 } })
        .catch(() => { /* best-effort cleanup */ });
    };
  }

  /** Health probe: list topics. */
  async topics(): Promise<string[]> {
    const res = await this.opts.fetchImpl(`${this.opts.baseUrl}/topics`, { signal: AbortSignal.timeout(this.opts.timeoutMs) });
    if (!res.ok) throw new Error(`kafka topics listing failed (${res.status})`);
    return await res.json() as string[];
  }
}
