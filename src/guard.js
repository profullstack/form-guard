import { scoreSubmission } from './heuristics.js';
import { createRateLimiter } from './rate-limit.js';
import { clientIp, userAgent } from './request.js';
import { issueToken, verifyToken } from './token.js';

/**
 * Actions a guard can return.
 *
 *   accept  — send it
 *   flag    — send it, tagged; a human decides
 *   drop    — discard it and tell the sender it worked
 *   retry   — a real person whose token went stale; ask them to resend
 *   limited — too many from one address
 *
 * `drop` is deliberately indistinguishable from `accept` to the caller.
 * Telling a bot which check caught it is free tuning information for
 * whoever is running it.
 */
export const ACTIONS = Object.freeze({
  ACCEPT: 'accept',
  FLAG: 'flag',
  DROP: 'drop',
  RETRY: 'retry',
  LIMITED: 'limited',
});

const DEFAULTS = {
  tokenField: 'fg_token',
  honeypotField: 'website',
  binding: '',
  minAgeMs: 3000,
  maxAgeMs: 2 * 60 * 60 * 1000,
  flagAt: 3,
  brandTerms: [],
  requireToken: true,
};

/**
 * Build a guard for one form.
 *
 * @param {object} options
 * @param {string} options.secret        HMAC secret. Any stable server-side string.
 * @param {string} [options.binding]     Ties a token to one form; must match at check time.
 * @param {string} [options.tokenField]  Hidden field carrying the token.
 * @param {string} [options.honeypotField] Hidden field bots fill and humans cannot see.
 * @param {number} [options.minAgeMs]    Floor on human fill time.
 * @param {number} [options.maxAgeMs]    Token lifetime.
 * @param {boolean}[options.requireToken] Set false to score-only during a soft rollout.
 * @param {object|false} [options.rateLimit] `{max, windowMs, store}`, or false to disable.
 * @param {string[]}[options.brandTerms] Brand words a scraper is likely to echo back.
 */
export function createFormGuard(options = {}) {
  const config = { ...DEFAULTS, ...options };
  if (!config.secret || typeof config.secret !== 'string') {
    throw new TypeError('form-guard: `secret` is required and must be a string');
  }

  const limiter = config.rateLimit === false ? null : createRateLimiter(config.rateLimit ?? {});

  /** Mint a token. Call this where the form is rendered, per render. */
  async function issue(now = Date.now()) {
    return issueToken(config.secret, { binding: config.binding, now });
  }

  /**
   * The hidden inputs a form needs, as data.
   *
   * Returned rather than rendered so this works in React, Svelte, a
   * template string, or anything else — the package renders no markup
   * it does not have to.
   */
  function fields(token) {
    return {
      token: { name: config.tokenField, value: token },
      honeypot: { name: config.honeypotField },
    };
  }

  /** The same inputs as an HTML fragment, for template-string views. */
  function hiddenHTML(token) {
    const escapeHtml = (s) =>
      String(s).replace(
        /[&<>"']/g,
        (c) =>
          ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
          })[c],
      );
    return [
      `<input type="hidden" name="${escapeHtml(config.tokenField)}" value="${escapeHtml(token)}">`,
      `<div aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">`,
      `<label>Website<input type="text" name="${escapeHtml(config.honeypotField)}" tabindex="-1" autocomplete="off"></label>`,
      `</div>`,
    ].join('');
  }

  /**
   * Judge a submission.
   *
   * @param {object} input
   * @param {object} input.fields   The parsed body.
   * @param {Headers|object} [input.headers] For IP and user-agent.
   * @param {string} [input.ip]     Overrides the header-derived address.
   * @returns {Promise<object>} verdict
   */
  async function check({ fields: body = {}, headers = null, ip = null, now = Date.now() } = {}) {
    const address = ip ?? (headers ? clientIp(headers) : null);
    const ua = headers ? userAgent(headers) : null;

    const base = {
      ip: address,
      userAgent: ua,
      score: 0,
      signals: [],
      suspicious: false,
      fillMs: null,
      reason: null,
    };

    // 1. Honeypot. No human sees this field, so anything in it settles
    //    the question on its own.
    const honeypot = String(body[config.honeypotField] ?? '').trim();
    if (honeypot) {
      return { ...base, allow: false, action: ACTIONS.DROP, reason: 'honeypot' };
    }

    // 2. Proof of render. This is the check that catches the bots that
    //    never loaded the page, which is most of them.
    const token = body[config.tokenField];
    const verified = await verifyToken(config.secret, token, {
      binding: config.binding,
      minAgeMs: config.minAgeMs,
      maxAgeMs: config.maxAgeMs,
      now,
    });
    base.fillMs = verified.ageMs ?? null;

    if (!verified.ok && config.requireToken) {
      // Stale or hurried tokens belong to real people often enough
      // that they get a second chance; a missing or forged one does
      // not, and gets the silent treatment.
      const retryable = verified.reason === 'token_expired' || verified.reason === 'too_fast';
      return {
        ...base,
        allow: false,
        action: retryable ? ACTIONS.RETRY : ACTIONS.DROP,
        reason: verified.reason,
      };
    }
    if (!verified.ok) base.signals.push(`token_${verified.reason}`);

    // 3. Rate limit, keyed on address. Runs after the cheap checks so
    //    a bot flood does not consume the window a human might need.
    if (limiter && address) {
      const limit = await limiter.check(address, now);
      if (!limit.ok) {
        return {
          ...base,
          allow: false,
          action: ACTIONS.LIMITED,
          reason: 'rate_limited',
          retryAfterMs: limit.retryAfterMs,
        };
      }
    }

    // 4. Content scoring. Advisory only — nothing below this line can
    //    stop a message from being delivered.
    const scored = scoreSubmission(body, {
      flagAt: config.flagAt,
      brandTerms: config.brandTerms,
    });

    return {
      ...base,
      score: scored.score,
      signals: [...base.signals, ...scored.signals],
      suspicious: scored.suspicious,
      allow: true,
      action: scored.suspicious ? ACTIONS.FLAG : ACTIONS.ACCEPT,
      reason: null,
    };
  }

  return { issue, fields, hiddenHTML, check, config: Object.freeze({ ...config }) };
}
