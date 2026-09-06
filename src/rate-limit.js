/**
 * Sliding-window rate limiting.
 *
 * The default store is per-process memory, which is the honest default
 * for a single container: it is not shared between instances and it
 * resets on deploy. That is usually fine for a contact form, where the
 * goal is blunting a flood rather than exact accounting. Pass your own
 * `store` (Redis, Upstash, Durable Object) when you run more than one
 * instance and want the limit to actually hold across them.
 *
 * Refused attempts count toward the window as much as accepted ones. A
 * caller that keeps hammering therefore keeps its own window full and
 * cannot batter its way back in; recovering takes a full window of
 * silence. That is the right trade for a contact form, where the traffic
 * that hits the limit is nearly always automated.
 */

export function createMemoryStore({ maxKeys = 10_000 } = {}) {
  const hits = new Map();

  return {
    /** @returns {Promise<number[]>} timestamps still inside the window */
    async take(key, windowMs, now) {
      const cutoff = now - windowMs;
      const kept = (hits.get(key) ?? []).filter((t) => t > cutoff);
      kept.push(now);
      hits.set(key, kept);

      // Bound the map so a spray across many IPs cannot grow it
      // without limit. Oldest-inserted keys go first; Map iterates
      // in insertion order, so this is just a walk from the front.
      if (hits.size > maxKeys) {
        const excess = hits.size - maxKeys;
        let dropped = 0;
        for (const existing of hits.keys()) {
          if (dropped >= excess) break;
          if (existing !== key) {
            hits.delete(existing);
            dropped += 1;
          }
        }
      }
      return kept;
    },
    async reset(key) {
      if (key === undefined) hits.clear();
      else hits.delete(key);
    },
  };
}

export function createRateLimiter({
  max = 5,
  windowMs = 60 * 60 * 1000,
  store = createMemoryStore(),
} = {}) {
  return {
    /** @returns {Promise<{ok:boolean, count:number, retryAfterMs:number}>} */
    async check(key, now = Date.now()) {
      if (!key) return { ok: true, count: 0, retryAfterMs: 0 };
      const window = await store.take(key, windowMs, now);
      const count = window.length;
      if (count <= max) return { ok: true, count, retryAfterMs: 0 };
      const oldest = window[0] ?? now;
      return { ok: false, count, retryAfterMs: Math.max(0, oldest + windowMs - now) };
    },
    reset: (key) => store.reset(key),
  };
}
