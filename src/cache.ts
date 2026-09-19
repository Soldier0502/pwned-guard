/** Minimal TTL + LRU cache. No dependencies, no background timers. */
export class TtlCache<K, V> {
  private readonly entries = new Map<K, { value: V; expiresAt: number }>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  private hitCount = 0;
  private missCount = 0;

  constructor(options: { ttlMs: number; maxEntries: number; now?: () => number }) {
    this.ttlMs = options.ttlMs;
    this.maxEntries = Math.max(0, options.maxEntries);
    this.now = options.now ?? (() => Date.now());
  }

  get(key: K): V | undefined {
    const entry = this.entries.get(key);
    if (!entry) {
      this.missCount += 1;
      return undefined;
    }
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      this.missCount += 1;
      return undefined;
    }
    // Touch the key so it becomes the most recently used one.
    this.entries.delete(key);
    this.entries.set(key, entry);
    this.hitCount += 1;
    return entry.value;
  }

  set(key: K, value: V): void {
    if (this.maxEntries === 0 || this.ttlMs <= 0) return;
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAt: this.now() + this.ttlMs });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }

  get stats(): { hits: number; misses: number; size: number } {
    return { hits: this.hitCount, misses: this.missCount, size: this.entries.size };
  }
}
