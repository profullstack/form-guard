import { describe, expect, test } from 'bun:test';
import {
  ACTIONS,
  createFormGuard,
  createRateLimiter,
  provenanceBlock,
  scoreSubmission,
  tagSubject,
} from '../index.js';

/**
 * The case that motivated this package: a submission arrived at a contact
 * form that already had a honeypot, because the sender never rendered the
 * page. It POSTed at the handler directly, so there was no honeypot field
 * in its body to fill in and nothing to catch it.
 *
 * So the tests are mostly about the token -- the only check that keys on
 * something a bot cannot skip -- and about the promise that the scoring
 * layer can tag a message but never silently eat one.
 */

const SECRET = 'test-secret-value';
const SECOND = 1000;
const MINUTE = 60 * SECOND;

const guard = (overrides = {}) =>
  createFormGuard({ secret: SECRET, binding: 'contact', ...overrides });

const human = {
  name: 'Dana Okafor',
  email: 'dana@okafor.dev',
  subject: 'Question about operator payouts',
  message:
    'We run four A100 nodes and want to understand how settlement timing works before we commit more hardware. Is there a doc on the payout cadence?',
};

/** The real message, verbatim apart from the address. */
const realSpam = {
  name: 'Isabella Thompson',
  email: 'madamtaisia@mail.ru',
  subject: 'Newsletter subscription',
  message:
    'I would like more information. Please contact me by email — contact · infernet protocol.',
};

describe('proof-of-render token', () => {
  test('a direct POST with no token is dropped, not delivered', async () => {
    // The exact shape of the incident: every visible field present,
    // honeypot absent because the page was never rendered.
    const verdict = await guard().check({ fields: realSpam });

    expect(verdict.allow).toBe(false);
    expect(verdict.action).toBe(ACTIONS.DROP);
    expect(verdict.reason).toBe('token_missing');
  });

  test('a rendered form submitted at human speed is accepted', async () => {
    const g = guard();
    const issuedAt = Date.now() - 40 * SECOND;
    const token = await g.issue(issuedAt);

    const verdict = await g.check({
      fields: { ...human, [g.config.tokenField]: token },
    });

    expect(verdict.allow).toBe(true);
    expect(verdict.action).toBe(ACTIONS.ACCEPT);
    expect(verdict.fillMs).toBeGreaterThan(30 * SECOND);
  });

  test('a token forged with the wrong secret is dropped', async () => {
    const attacker = createFormGuard({ secret: 'not-the-secret', binding: 'contact' });
    const token = await attacker.issue(Date.now() - 40 * SECOND);

    const verdict = await guard().check({ fields: { ...human, fg_token: token } });

    expect(verdict.action).toBe(ACTIONS.DROP);
    expect(verdict.reason).toBe('token_bad_signature');
  });

  test('a token minted for another form does not work here', async () => {
    const newsletter = createFormGuard({ secret: SECRET, binding: 'newsletter' });
    const token = await newsletter.issue(Date.now() - 40 * SECOND);

    const verdict = await guard().check({ fields: { ...human, fg_token: token } });

    expect(verdict.action).toBe(ACTIONS.DROP);
    expect(verdict.reason).toBe('token_bad_signature');
  });

  test('a tampered token is dropped', async () => {
    const g = guard();
    const token = await g.issue(Date.now() - 40 * SECOND);
    const tampered = `${token.slice(0, -2)}xy`;

    const verdict = await g.check({ fields: { ...human, fg_token: tampered } });

    expect(verdict.action).toBe(ACTIONS.DROP);
  });
});

describe('fill time', () => {
  test('an instant submission is asked to retry rather than dropped', async () => {
    const g = guard();
    const token = await g.issue();

    const verdict = await g.check({ fields: { ...human, fg_token: token } });

    // Retry, not drop: a real person on a fast autofill lands here and
    // deserves to be told, where a bot simply will not come back.
    expect(verdict.action).toBe(ACTIONS.RETRY);
    expect(verdict.reason).toBe('too_fast');
  });

  test('a stale token is asked to retry', async () => {
    const g = guard({ maxAgeMs: 30 * MINUTE });
    const token = await g.issue(Date.now() - 90 * MINUTE);

    const verdict = await g.check({ fields: { ...human, fg_token: token } });

    expect(verdict.action).toBe(ACTIONS.RETRY);
    expect(verdict.reason).toBe('token_expired');
  });

  test('minAgeMs is configurable for forms people fill in fast', async () => {
    const g = guard({ minAgeMs: 0 });
    const token = await g.issue();

    const verdict = await g.check({ fields: { ...human, fg_token: token } });

    expect(verdict.allow).toBe(true);
  });
});

describe('honeypot', () => {
  test('a filled honeypot is dropped silently', async () => {
    const g = guard();
    const token = await g.issue(Date.now() - 40 * SECOND);

    const verdict = await g.check({
      fields: { ...human, fg_token: token, website: 'http://example.com' },
    });

    expect(verdict.action).toBe(ACTIONS.DROP);
    expect(verdict.reason).toBe('honeypot');
  });

  test('the honeypot is checked before the token, so bots learn nothing', async () => {
    // No token at all AND a filled honeypot: the caller cannot tell from
    // the outside which check fired, because both look like success.
    const verdict = await guard().check({ fields: { ...human, website: 'x' } });
    expect(verdict.action).toBe(ACTIONS.DROP);
  });
});

describe('rate limiting', () => {
  test('holds a per-address window and then refuses', async () => {
    const g = guard({ rateLimit: { max: 2, windowMs: MINUTE }, minAgeMs: 0 });
    const send = async () =>
      g.check({ fields: { ...human, fg_token: await g.issue() }, ip: '203.0.113.9' });

    expect((await send()).allow).toBe(true);
    expect((await send()).allow).toBe(true);

    const third = await send();
    expect(third.allow).toBe(false);
    expect(third.action).toBe(ACTIONS.LIMITED);
    expect(third.retryAfterMs).toBeGreaterThan(0);
  });

  test('separate addresses hold separate windows', async () => {
    const g = guard({ rateLimit: { max: 1, windowMs: MINUTE }, minAgeMs: 0 });
    const send = async (ip) => g.check({ fields: { ...human, fg_token: await g.issue() }, ip });

    expect((await send('203.0.113.1')).allow).toBe(true);
    expect((await send('203.0.113.2')).allow).toBe(true);
    expect((await send('203.0.113.1')).allow).toBe(false);
  });

  test('the window slides rather than resetting on a fixed boundary', async () => {
    const limiter = createRateLimiter({ max: 1, windowMs: MINUTE });
    const start = Date.now();

    expect((await limiter.check('k', start)).ok).toBe(true);
    expect((await limiter.check('k', start + 30 * SECOND)).ok).toBe(false);
    // Quiet for a full window and the slot is free again.
    expect((await limiter.check('k', start + 91 * SECOND)).ok).toBe(true);
  });

  test('hammering the limit keeps it shut', async () => {
    // Refused attempts count too, so a flood cannot outlast its own
    // window by continuing to knock.
    const limiter = createRateLimiter({ max: 1, windowMs: MINUTE });
    const start = Date.now();

    expect((await limiter.check('k', start)).ok).toBe(true);
    for (let t = 10; t <= 120; t += 10) {
      expect((await limiter.check('k', start + t * SECOND)).ok).toBe(false);
    }
  });

  test('reads the address from proxy headers when one is not passed', async () => {
    const g = guard({ rateLimit: { max: 1, windowMs: MINUTE }, minAgeMs: 0 });
    const headers = new Headers({ 'x-forwarded-for': '198.51.100.4, 10.0.0.1' });
    const send = async () => g.check({ fields: { ...human, fg_token: await g.issue() }, headers });

    const first = await send();
    expect(first.ip).toBe('198.51.100.4');
    expect((await send()).action).toBe(ACTIONS.LIMITED);
  });
});

describe('content scoring', () => {
  test('scores the real message as suspicious', () => {
    const scored = scoreSubmission(realSpam, { brandTerms: ['infernet protocol'] });

    expect(scored.suspicious).toBe(true);
    expect(scored.signals).toContain('contentless_request');
    expect(scored.signals).toContain('noisy_mail_host');
    expect(scored.signals).toContain('name_email_mismatch');
  });

  test('leaves a genuine enquiry alone', () => {
    const scored = scoreSubmission(human, { brandTerms: ['infernet protocol'] });

    expect(scored.suspicious).toBe(false);
    expect(scored.score).toBe(0);
  });

  test('does not punish gmail, which real people use', () => {
    const scored = scoreSubmission({ ...human, email: 'dana.okafor@gmail.com' });
    expect(scored.signals).not.toContain('noisy_mail_host');
  });

  test('a flagged message is still delivered', async () => {
    const g = guard({ brandTerms: ['infernet protocol'] });
    const token = await g.issue(Date.now() - 40 * SECOND);

    const verdict = await g.check({ fields: { ...realSpam, fg_token: token } });

    // It got a token somehow, so it goes through -- tagged, never eaten.
    expect(verdict.allow).toBe(true);
    expect(verdict.action).toBe(ACTIONS.FLAG);
    expect(verdict.suspicious).toBe(true);
  });
});

describe('soft rollout', () => {
  test('requireToken:false scores without ever blocking', async () => {
    const g = guard({ requireToken: false, brandTerms: ['infernet protocol'] });

    const verdict = await g.check({ fields: realSpam });

    expect(verdict.allow).toBe(true);
    expect(verdict.suspicious).toBe(true);
    expect(verdict.signals).toContain('token_token_missing');
  });
});

describe('rendering', () => {
  test('hands back field names rather than markup', async () => {
    const g = guard();
    const token = await g.issue();
    const { token: tokenField, honeypot } = g.fields(token);

    expect(tokenField).toEqual({ name: 'fg_token', value: token });
    expect(honeypot.name).toBe('website');
  });

  test('the HTML fragment escapes what it interpolates', () => {
    const g = guard({ tokenField: 'fg_token' });
    const html = g.hiddenHTML('"><script>alert(1)</script>');

    expect(html).not.toContain('<script>');
    expect(html).toContain('&quot;&gt;&lt;script&gt;');
  });

  test('the honeypot is hidden off-canvas, not with the hidden attribute', () => {
    // Screen readers skip aria-hidden, and off-canvas positioning still
    // gets filled by bots that only read the DOM. `display:none` is the
    // one thing some of them do skip.
    const html = guard().hiddenHTML('t');
    expect(html).toContain('left:-9999px');
    expect(html).not.toContain('display:none');
  });
});

describe('inbox annotation', () => {
  test('tags a flagged subject and leaves a clean one', () => {
    const flagged = { suspicious: true, score: 6 };
    expect(tagSubject('[contact] Newsletter subscription', flagged)).toBe(
      '[contact] Newsletter subscription [spam? 6]',
    );
    expect(tagSubject('[contact] Hello', { suspicious: false })).toBe('[contact] Hello');
  });

  test('the provenance block carries what the headers do not', () => {
    const block = provenanceBlock({
      ip: '198.51.100.4',
      userAgent: 'curl/8.4.0',
      verdict: { score: 6, suspicious: true, signals: ['contentless_request'], fillMs: 41000 },
      submittedAt: new Date('2026-09-06T09:11:13Z'),
    });

    expect(block).toContain('ip: 198.51.100.4');
    expect(block).toContain('curl/8.4.0');
    expect(block).toContain('fill-time: 41.0s');
    expect(block).toContain('signals: contentless_request');
  });
});

describe('configuration', () => {
  test('refuses to build without a secret', () => {
    expect(() => createFormGuard({})).toThrow(/secret/);
  });

  test('field names are configurable so the honeypot is not guessable', async () => {
    const g = guard({ tokenField: 'x_t', honeypotField: 'company_url', minAgeMs: 0 });
    const token = await g.issue();

    const verdict = await g.check({ fields: { ...human, x_t: token, company_url: 'bot' } });
    expect(verdict.reason).toBe('honeypot');
  });
});
