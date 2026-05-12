// In-memory replay-protection cache. Pass `cache.check.bind(cache)` as the
// `checkNonce` callback to `rfc9421.verify()`.
//
// Designed for single-process verifiers. Production deployments behind a
// load balancer should plug in a shared backend (Redis, etc.) by providing
// their own `checkNonce` implementation; this class is the reference.

export interface ReplayCacheOptions {
  /** Max entries retained before LRU eviction. Defaults to 4096. */
  capacity?: number;
  /** Entries are dropped after this many seconds. Defaults to 600 (10 min). */
  ttlSeconds?: number;
  /** Injected clock; defaults to `Date.now() / 1000`. */
  now?: () => number;
}

interface Entry {
  expiresAt: number;
}

export class ReplayCache {
  private readonly capacity: number;
  private readonly ttl: number;
  private readonly now: () => number;
  private readonly entries: Map<string, Entry> = new Map();

  constructor(options: ReplayCacheOptions = {}) {
    this.capacity = options.capacity ?? 4096;
    this.ttl = options.ttlSeconds ?? 600;
    this.now = options.now ?? (() => Date.now() / 1000);
  }

  /**
   * Returns `true` if the nonce is first-seen (and records it); `false` if
   * we have a live record from a previous check. Suitable as the
   * `checkNonce` callback on `rfc9421.verify`.
   */
  check(nonce: string): boolean {
    this.evictExpired();
    if (this.entries.has(nonce)) return false;
    if (this.entries.size >= this.capacity) {
      // Map iteration is insertion-ordered — first key is oldest.
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    this.entries.set(nonce, { expiresAt: this.now() + this.ttl });
    return true;
  }

  size(): number {
    this.evictExpired();
    return this.entries.size;
  }

  private evictExpired(): void {
    const now = this.now();
    for (const [k, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(k);
      else break; // insertion-ordered + monotonic expiry → first non-expired is the cutoff
    }
  }
}
