/**
 * Campaign detection for listing / directory submissions.
 *
 * The token, honeypot and fill-time checks judge ONE request. A submission
 * campaign passes all of them: it renders the form, fills it at human speed
 * and sends something plausible. What gives it away is the run -- one caller
 * posting a different product every minute, alphabetically through a list of
 * domains it registered, each with a fresh `hello@<that-domain>` contact so a
 * per-email limit never fires (saasrow.com, 2026-10-04: 153 listings in seven
 * hours).
 *
 * The rule this module keeps: SHAPE NEVER ACTS ALONE. `hello@mycompany.com`
 * submitting `mycompany.com` is how real founders list their product, and a
 * shape rule used as a block turns real people away (ugig.net learned that
 * three times). The role-address match is only a signal; what acts is volume:
 *
 *  - ban   one address submitting `ipDomains` or more different domains inside
 *          the window, or repeating the pattern while a campaign is running.
 *          Answer it with a 4xx your edge can see (ThreatCrush bans on those).
 *  - hold  a campaign is running across many addresses (a proxy rotation) and
 *          this request matches it, but this address has no history. Accept
 *          it and keep it out of any auto-approval; a real founder caught in
 *          the middle is not refused.
 *  - ok    everything else.
 *
 * The default store is per-process memory. Pass a shared `store` to make the
 * window hold across instances.
 */

export const ROLE_LOCAL_PARTS = Object.freeze([
  'hello', 'hi', 'hey', 'enquiries', 'enquiry', 'inquiries', 'inquiry', 'info',
  'contact', 'support', 'team', 'sales', 'admin', 'office', 'founders', 'founder',
]);

/** A windowed log per key, bounded so a spray across many keys cannot grow it without limit. */
export function createCampaignMemoryStore({ maxKeys = 10_000 } = {}) {
  const logs = new Map();
  return {
    /** Append `value` under `key` and return the entries still inside the window. */
    async push(key, value, windowMs, now) {
      const cutoff = now - windowMs;
      const kept = (logs.get(key) ?? []).filter((e) => e.t > cutoff);
      kept.push({ t: now, v: value });
      logs.delete(key);
      logs.set(key, kept);
      while (logs.size > maxKeys) logs.delete(logs.keys().next().value);
      return kept;
    },
    async reset(key) {
      if (key === undefined) logs.clear();
      else logs.delete(key);
    },
  };
}

/** Lowercased host of a URL or bare domain, without a leading `www.`. Empty when unparseable. */
export function hostOf(url) {
  if (!url) return '';
  const raw = String(url).trim();
  try {
    const host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`).hostname;
    return host.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}

/**
 * Whether the contact is a role address at the listed product's own domain.
 * A signal, never a verdict on its own.
 */
export function isOwnDomainRoleAddress(email, url, roles = ROLE_LOCAL_PARTS) {
  const at = String(email ?? '').toLowerCase().trim().lastIndexOf('@');
  if (at < 1) return false;
  const local = String(email).toLowerCase().trim().slice(0, at);
  const domain = String(email).toLowerCase().trim().slice(at + 1).replace(/^www\./, '');
  const host = hostOf(url);
  if (!host || !domain || !roles.includes(local)) return false;
  return host === domain || host.endsWith(`.${domain}`);
}

/** Whether the last `n` names are in ascending alphabetical order (a list being worked through). */
function alphabeticalRun(names, n) {
  const tail = names.slice(-n);
  if (tail.length < n) return false;
  for (let i = 1; i < tail.length; i++) {
    if (tail[i - 1].localeCompare(tail[i]) > 0) return false;
  }
  return true;
}

export function createCampaignDetector({
  windowMs = 30 * 60 * 1000,
  /** Distinct domains from one address inside the window that mean a run. */
  ipDomains = 5,
  /** Pattern matches across all addresses inside the window that mean a campaign. */
  campaignThreshold = 8,
  roles = ROLE_LOCAL_PARTS,
  store = createCampaignMemoryStore(),
} = {}) {
  return {
    /**
     * Record one submission and judge it.
     * @param {{ip?: string, email?: string, url?: string, name?: string}} s
     */
    async observe({ ip = '', email = '', url = '', name = '' } = {}, now = Date.now()) {
      const host = hostOf(url);
      const pattern = isOwnDomainRoleAddress(email, url, roles);
      const signals = [];
      if (pattern) signals.push('own_domain_role_address');

      const mine = ip ? await store.push(`ip:${ip}`, { host, pattern, name: name || host }, windowMs, now) : [];
      const domains = new Set(mine.map((e) => e.v.host).filter(Boolean));
      const minePattern = mine.filter((e) => e.v.pattern).length;

      const global = pattern ? await store.push('campaign', ip || '?', windowMs, now) : [];
      const campaign = global.length >= campaignThreshold;
      if (campaign) signals.push('campaign_active');

      if (domains.size >= ipDomains) signals.push('ip_many_domains');
      if (alphabeticalRun(mine.map((e) => e.v.name), Math.min(ipDomains, 4))) signals.push('alphabetical_run');

      let level = 'ok';
      if (domains.size >= ipDomains || (campaign && pattern && minePattern >= 2)) level = 'ban';
      else if (campaign && pattern) level = 'hold';

      return {
        level,
        signals,
        ipSubmissions: mine.length,
        ipDomains: domains.size,
        campaignCount: global.length,
      };
    },
    store,
  };
}
