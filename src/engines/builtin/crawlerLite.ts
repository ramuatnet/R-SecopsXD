/**
 * Built-in crawler-lite: bounded same-origin crawl using plain GETs.
 * Passive mode: only follows discovered links (no wordlists). Fills the
 * shared crawl corpus for observer engines; produces no findings itself.
 */
import type { Engine, EngineAvailability, EngineRunResult, ScanContext, CrawlPage } from '../types.ts';
import { cap } from '../types.ts';
import type { EngineInfo } from '../../core/types.ts';

const INFO: EngineInfo = {
  id: 'builtin.crawler-lite',
  name: 'Bounded Crawler',
  kind: 'builtin',
  capabilities: {},
  modes: ['passive', 'active'],
  targetKinds: ['webapp'],
};

const MAX_BODY = 64 * 1024;

export class CrawlerLiteEngine implements Engine {
  info = INFO;
  private readonly maxPages: number;

  constructor(maxPages: number) {
    this.maxPages = maxPages;
  }

  async availability(): Promise<EngineAvailability> {
    return { available: true, version: 'builtin' };
  }

  async run(ctx: ScanContext): Promise<EngineRunResult> {
    const origin = ctx.target.origin;
    const corpus = ctx.crawl ?? { pages: [], robots: { disallow: [], fetched: false } };
    ctx.crawl = corpus;

    const seen = new Set<string>();
    const queue: string[] = [];

    const enqueue = (url: string): void => {
      try {
        const u = new URL(url);
        u.hash = '';
        const norm = u.toString();
        if (!ctx.guard.inScope(norm)) return;
        if (/\.(png|jpe?g|gif|svg|ico|css|zip|pdf|woff2?|mp4)$/i.test(u.pathname)) return;
        if (!seen.has(norm) && queue.length + seen.size < this.maxPages * 4) {
          seen.add(norm);
          queue.push(norm);
        }
      } catch { /* ignore malformed links */ }
    };

    enqueue(new URL('/', origin).toString());

    // Fallback landing paths — enqueued ONLY if the root 404s (checked after
    // the root page is processed). This preserves page budget for real links
    // on healthy targets while still discovering content on dead-root targets.
    const FALLBACK_PATHS = ['/index.jsp', '/index.html', '/login.jsp', '/login', '/home',
      '/portal', '/welcome', '/start', '/main', '/app', '/web', '/dashboard'];
    let rootProcessed = false;
    let rootSucceeded = false;

    // robots.txt (informational; passive GET)
    const robotsUrl = new URL('/robots.txt', origin).toString();
    const robotsRes = await ctx.client.get(robotsUrl);
    if (robotsRes.ok && robotsRes.status === 200) {
      corpus.robots.fetched = true;
      for (const line of robotsRes.body.split('\n')) {
        const m = /^\s*Disallow:\s*(\S+)/i.exec(line);
        if (m?.[1] && m[1] !== '/') corpus.robots.disallow.push(m[1]);
      }
    }

    while (queue.length > 0 && corpus.pages.length < this.maxPages && !ctx.signal.aborted) {
      const url = queue.shift()!;
      const res = await ctx.client.get(url);
      if (!rootProcessed) {
        rootProcessed = true;
        rootSucceeded = res.ok && res.status === 200 && (res.headers['content-type'] ?? '').includes('text/html') && res.body.length > 0;
        if (!rootSucceeded) {
          // Root 404 or empty: enqueue fallback paths so discovery continues
          for (const fp of FALLBACK_PATHS) {
            enqueue(new URL(fp, origin).toString());
          }
        }
      }
      // Error pages are captured too — observers need them (e.g. verbose stack traces).
      const contentType = res.ok ? (res.headers['content-type'] ?? '') : '';
      const isText = contentType.includes('text/html') || contentType.includes('text/plain') || contentType.includes('json');
      const page = parsePage(url, res.ok && isText ? res.body : '');
      page.status = res.ok ? res.status : 0;
      page.headers = res.ok ? res.headers : {};
      corpus.pages.push(page);
      for (const link of page.links) enqueue(link);
    }

    ctx.log('crawl finished', { pages: corpus.pages.length, robotsDisallow: corpus.robots.disallow.length });
    return { findings: [], version: 'builtin', detail: `${corpus.pages.length} pages crawled (cap ${this.maxPages})` };
  }
}

/** Parse links and forms out of an HTML body (regex-based, bounded). */
export function parsePage(url: string, body: string): CrawlPage {
  const links: string[] = [];
  const linkRe = /<a\s[^>]*href\s*=\s*["']([^"'#\s]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(body)) !== null && links.length < 200) {
    try { links.push(new URL(m[1]!, url).toString()); } catch { /* skip */ }
  }

  const forms: CrawlPage['forms'] = [];
  const formRe = /<form\s[^>]*>/gi;
  while ((m = formRe.exec(body)) !== null && forms.length < 20) {
    const tag = m[0];
    const actionM = /action\s*=\s*["']([^"']*)["']/i.exec(tag);
    const methodM = /method\s*=\s*["']([^"']*)["']/i.exec(tag);
    let action = actionM?.[1] ?? '';
    try { action = new URL(action || url, url).toString(); } catch { action = url; }
    const formEnd = body.indexOf('</form>', m.index);
    const inner = formEnd >= 0 ? body.slice(m.index, formEnd) : body.slice(m.index, m.index + 2000);
    const fields: string[] = [];
    const inputRe = /<input\s[^>]*name\s*=\s*["']([^"']+)["'][^>]*>/gi;
    let hasPassword = false;
    let im: RegExpExecArray | null;
    while ((im = inputRe.exec(inner)) !== null && fields.length < 30) {
      fields.push(im[1]!);
      if (/type\s*=\s*["']password["']/i.test(im[0])) hasPassword = true;
    }
    forms.push({ action, method: (methodM?.[1] ?? 'get').toLowerCase(), fields, hasPasswordField: hasPassword });
  }

  return { url, status: 200, headers: {}, body, truncated: false, forms, links };
}
