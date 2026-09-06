/**
 * Proof-of-render tokens.
 *
 * The premise: a public form that anyone can POST to directly is not a
 * form, it is an open mail relay with extra steps. Nearly all contact-form
 * spam skips the page entirely and POSTs straight at the handler, so it
 * never sees a honeypot and cannot be slowed down by one.
 *
 * A token is minted when the form is *rendered* and verified when it is
 * submitted. No token, no send. That single check removes the whole
 * class of direct-to-endpoint bots, and because the token carries the
 * moment it was issued, it also gives us the fill time for free.
 *
 * WebCrypto rather than node:crypto so the same code runs on Node, Bun,
 * Deno, Cloudflare Workers and the Next.js edge runtime.
 */

const VERSION = '1';
const encoder = new TextEncoder();
const keyCache = new Map();

async function hmacKey(secret) {
  if (!secret || typeof secret !== 'string') {
    throw new TypeError('form-guard: a non-empty string secret is required');
  }
  const cached = keyCache.get(secret);
  if (cached) return cached;
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  keyCache.set(secret, key);
  return key;
}

function base64url(bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sign(secret, payload) {
  const key = await hmacKey(secret);
  return base64url(await crypto.subtle.sign('HMAC', key, encoder.encode(payload)));
}

/** Compare without leaking where two strings diverge. */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function randomNonce() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

/**
 * Mint a token for a form about to be rendered.
 *
 * `binding` ties the token to something about the render — a form id, a
 * route, a session — so a token minted for one form cannot be replayed
 * against another. It must match at verify time.
 */
export async function issueToken(secret, { binding = '', now = Date.now() } = {}) {
  const head = `${VERSION}.${now.toString(36)}.${randomNonce()}`;
  return `${head}.${await sign(secret, `${head}.${binding}`)}`;
}

/**
 * Verify a submitted token.
 *
 * Returns `{ ok, reason, issuedAt, ageMs, nonce }`. `reason` is a stable
 * machine-readable string, never a sentence — callers decide what the
 * visitor is told, and the answer should usually be nothing specific.
 */
export async function verifyToken(
  secret,
  token,
  { binding = '', minAgeMs = 3000, maxAgeMs = 2 * 60 * 60 * 1000, now = Date.now() } = {},
) {
  if (typeof token !== 'string' || token.length === 0) {
    return { ok: false, reason: 'token_missing' };
  }
  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== VERSION) {
    return { ok: false, reason: 'token_malformed' };
  }
  const [, issuedAt36, nonce, presented] = parts;
  const expected = await sign(secret, `${VERSION}.${issuedAt36}.${nonce}.${binding}`);
  if (!safeEqual(presented, expected)) {
    return { ok: false, reason: 'token_bad_signature' };
  }

  const issuedAt = Number.parseInt(issuedAt36, 36);
  if (!Number.isFinite(issuedAt)) return { ok: false, reason: 'token_malformed' };

  const ageMs = now - issuedAt;
  // A token minted in the future means a clock skew we cannot reason
  // about, so treat it the same as one we cannot age.
  if (ageMs < -60_000) return { ok: false, reason: 'token_from_future' };
  if (ageMs > maxAgeMs) return { ok: false, reason: 'token_expired', issuedAt, ageMs, nonce };
  if (ageMs < minAgeMs) return { ok: false, reason: 'too_fast', issuedAt, ageMs, nonce };

  return { ok: true, reason: null, issuedAt, ageMs, nonce };
}
