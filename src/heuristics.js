/**
 * Content heuristics.
 *
 * These SCORE a submission. They never reject one. Every signal here has
 * a plausible innocent explanation — real people write short messages,
 * real people have mail.ru addresses, real people paste links — so the
 * output is an annotation for the human reading the inbox and a subject
 * tag they can filter on, not a verdict.
 *
 * Rejection is the job of the token and honeypot checks, which key on
 * things no human visitor ever does.
 */

/**
 * Free-mail hosts that show up far more often in form spam than in real
 * mail. Deliberately excludes gmail/outlook/icloud: the false-positive
 * cost there is enormous and the signal is close to zero.
 */
const NOISY_MAIL_HOSTS = new Set([
  'mail.ru',
  'bk.ru',
  'inbox.ru',
  'list.ru',
  'internet.ru',
  'yandex.ru',
  'yandex.com',
  'ya.ru',
  'rambler.ru',
  'mailinator.com',
  'guerrillamail.com',
  '10minutemail.com',
  'tempmail.com',
  'throwawaymail.com',
  'sharklasers.com',
]);

/** Phrasing that carries no information about why someone is writing. */
const CONTENTLESS_PATTERNS = [
  /\bi would like (?:to know )?more information\b/i,
  /\bplease (?:contact|email|write to) me\b/i,
  /\bsend me (?:more )?(?:info|information|details)\b/i,
  /\bi am interested in your (?:services|offer|company|website)\b/i,
  /\bcan you (?:tell|give) me more\b/i,
];

const URL_PATTERN = /\b(?:https?:\/\/|www\.)\S+/i;
const CYRILLIC = /[Ѐ-ӿ]/;
const CJK = /[぀-ヿ一-鿿]/;

function localPart(email) {
  return (
    String(email ?? '')
      .split('@')[0]
      ?.toLowerCase() ?? ''
  );
}

function mailHost(email) {
  return (
    String(email ?? '')
      .split('@')[1]
      ?.toLowerCase() ?? ''
  );
}

/**
 * Does the claimed name appear anywhere in the email address?
 *
 * "Isabella Thompson <madamtaisia@mail.ru>" shares nothing, which is
 * weakly suspicious. Plenty of legitimate senders fail this too, hence
 * the low weight.
 */
function nameMatchesEmail(name, email) {
  const local = localPart(email).replace(/[^a-z]/g, '');
  if (local.length < 3) return false;
  const parts = String(name ?? '')
    .toLowerCase()
    .split(/\s+/)
    .filter((p) => p.length >= 3);
  if (parts.length === 0) return false;
  return parts.some((part) => local.includes(part) || part.includes(local));
}

/**
 * Score one submission.
 *
 * @returns {{score:number, signals:string[], suspicious:boolean}}
 */
export function scoreSubmission(
  { name = '', email = '', subject = '', message = '' } = {},
  { flagAt = 3, brandTerms = [] } = {},
) {
  const signals = [];
  let score = 0;

  const add = (signal, weight) => {
    signals.push(signal);
    score += weight;
  };

  const body = String(message ?? '');
  const trimmed = body.trim();

  if (NOISY_MAIL_HOSTS.has(mailHost(email))) add('noisy_mail_host', 2);
  if (name && email && !nameMatchesEmail(name, email)) add('name_email_mismatch', 1);

  if (CONTENTLESS_PATTERNS.some((re) => re.test(trimmed))) add('contentless_request', 3);
  if (trimmed.length > 0 && trimmed.length < 120) add('very_short', 1);
  if (URL_PATTERN.test(trimmed)) add('contains_url', 2);

  const mixedScript = /[a-z]/i.test(trimmed) && (CYRILLIC.test(trimmed) || CJK.test(trimmed));
  if (mixedScript) add('mixed_script', 1);

  // A bot that scraped the page often echoes the brand back at you,
  // sometimes mangled by whatever stripped the markup out.
  const haystack = `${subject} ${trimmed}`.toLowerCase().replace(/[^a-z0-9]+/g, ' ');
  if (brandTerms.length > 0) {
    const echoed = brandTerms.some((term) => {
      const normalised = String(term)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();
      return normalised.length > 0 && haystack.includes(normalised);
    });
    if (echoed) add('echoes_brand', 1);
  }

  const letters = trimmed.replace(/[^A-Za-z]/g, '');
  if (letters.length >= 20 && letters === letters.toUpperCase()) add('all_caps', 1);
  if ((trimmed.match(/!/g) ?? []).length >= 4) add('exclamation_spam', 1);

  return { score, signals, suspicious: score >= flagAt };
}
