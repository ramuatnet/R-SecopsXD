/** Global concurrency semaphore for outbound requests and subprocesses. */
export class Semaphore {
  private active = 0;
  private readonly limit: number;
  private readonly waiters: Array<() => void> = [];

  constructor(limit: number) {
    this.limit = limit;
  }

  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) throw new Error('aborted');
    if (this.active < this.limit) {
      this.active++;
      return this.release.bind(this);
    }
    await new Promise<void>((resolve, reject) => {
      const w = () => {
        cleanup();
        resolve();
      };
      const onAbort = () => {
        const i = this.waiters.indexOf(w);
        if (i >= 0) this.waiters.splice(i, 1);
        cleanup();
        reject(new Error('aborted'));
      };
      const cleanup = () => signal?.removeEventListener('abort', onAbort);
      signal?.addEventListener('abort', onAbort, { once: true });
      this.waiters.push(w);
    });
    this.active++;
    return this.release.bind(this);
  }

  private release(): void {
    this.active--;
    const next = this.waiters.shift();
    if (next) next();
  }

  get inFlight(): number {
    return this.active;
  }
}
