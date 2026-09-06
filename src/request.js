/**
 * Reading the caller's address behind a proxy.
 *
 * Every header here is trivially forged by the client, so this is only
 * meaningful when something you trust — Railway, Vercel, Cloudflare, your
 * own nginx — sets it and overwrites whatever the client sent. Treat the
 * result as a rate-limit bucket and a note for the inbox, never as
 * identity or as an authorisation input.
 */

const FORWARD_HEADERS = ['cf-connecting-ip', 'true-client-ip', 'fly-client-ip', 'x-real-ip'];

export function clientIp(headers) {
  const get =
    typeof headers?.get === 'function'
      ? (name) => headers.get(name)
      : (name) => headers?.[name] ?? headers?.[name.toLowerCase()];

  const forwardedFor = get('x-forwarded-for');
  if (forwardedFor) {
    // Left-most entry is the original client; the rest are proxies.
    const first = String(forwardedFor).split(',')[0]?.trim();
    if (first) return first;
  }
  for (const name of FORWARD_HEADERS) {
    const value = get(name);
    if (value) return String(value).trim();
  }
  return null;
}

export function userAgent(headers) {
  const get =
    typeof headers?.get === 'function'
      ? (name) => headers.get(name)
      : (name) => headers?.[name] ?? headers?.[name.toLowerCase()];
  return get('user-agent') ?? null;
}
