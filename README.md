# @profullstack/form-guard

Contact-form spam control that keys on what bots actually do, not on what
they write. No dependencies, no third-party service, no captcha, no
markup of its own. Runs on Node, Bun, Deno, Cloudflare Workers and the
Next.js edge runtime.

```
npm i @profullstack/form-guard
```

## Why the honeypot you already have is not catching anything

A honeypot is a hidden field that humans cannot see and bots fill in.
It works only against a bot that renders your page.

Most contact-form spam does not. It POSTs at your handler directly, which
means the hidden field is never in the request body at all, and a check
of the form "is this field empty?" answers yes. The submission sails
through a defence that is working exactly as designed.

The message that prompted this package arrived at a form with a
functioning honeypot. Every header passed — SPF, DKIM, DMARC, ARC — because
the site was mailing *itself* through its own provider. The cryptography
was never the question. Nothing in the request had touched the page.

So the first check here is a **proof-of-render token**: a signed,
timestamped value minted when the form renders and required when it
submits. Skip the page, have no token, go nowhere. It also carries the
moment it was issued, which gives you the fill time for free.

## Layers

| Layer | Catches | On failure |
|---|---|---|
| Proof-of-render token | Direct-to-endpoint bots | `drop` — silently discarded |
| Fill-time floor | Instant submits | `retry` — a human is asked to resend |
| Honeypot | DOM-filling bots | `drop` |
| Per-IP rate limit | Floods | `limited` — 429 |
| Content scoring | Low-effort lead bait | `flag` — **delivered**, tagged |

The split matters. The first four key on things no human visitor does, so
they can block. Content scoring only ever tags, because every signal it
reads has an innocent explanation — real people write short messages, use
mail.ru, and paste links. **Nothing in the scoring layer can stop a
message from reaching you.**

`drop` reports success to the caller. Telling a bot which check caught it
is free tuning information for whoever runs it.

## Use

```js
import { createFormGuard, tagSubject, provenanceBlock } from '@profullstack/form-guard';

export const guard = createFormGuard({
  secret: process.env.FORM_GUARD_SECRET,
  binding: 'contact',              // ties tokens to this one form
  brandTerms: ['acme corp'],       // words a scraper echoes back
  rateLimit: { max: 5, windowMs: 60 * 60 * 1000 },
});
```

Render the form with a token:

```jsx
const token = await guard.issue();
const { token: t, honeypot } = guard.fields(token);

<form action="/api/contact" method="post">
  {/* your real fields */}
  <input type="hidden" name={t.name} value={t.value} />
  <div aria-hidden="true" style={{ position: 'absolute', left: '-9999px' }}>
    <label>Website<input type="text" name={honeypot.name} tabIndex={-1} autoComplete="off" /></label>
  </div>
  <button type="submit">Send</button>
</form>
```

Not using JSX? `guard.hiddenHTML(token)` returns both inputs as an
escaped HTML fragment.

Check on submit:

```js
const verdict = await guard.check({ fields: body, headers: request.headers });

switch (verdict.action) {
  case 'drop':
    return ok();                       // tell the bot it worked
  case 'retry':
    return error('Please try again.'); // stale or too fast
  case 'limited':
    return error('Too many messages. Try later.', 429);
  default:
    await send({
      subject: tagSubject(`[contact] ${subject}`, verdict),
      text: `${message}\n\n${provenanceBlock({ ...verdict, verdict })}`,
    });
    return ok();
}
```

A flagged message arrives with `[spam? 6]` in the subject — filter on it —
and a provenance block naming the IP, user-agent, fill time and the
signals that fired.

## Rolling it out without breaking anything

Ship with `requireToken: false` first. Every submission is scored and
annotated, nothing is ever blocked. Watch the flagged mail for a few days,
confirm no real enquiry is being tagged, then flip it to `true`.

```js
createFormGuard({ secret, requireToken: process.env.FORM_GUARD_ENFORCE === '1' });
```

## The secret

Any stable server-side string. It never reaches the client — only the
signature does — so it does not need to be a managed secret, but it does
need to be the same across every instance that serves the form, or a
token minted by one box will be rejected by the next.

Rotating it invalidates tokens on pages currently open. Those users get
`retry`, not a lost message.

## Options

| Option | Default | |
|---|---|---|
| `secret` | — | required |
| `binding` | `''` | ties a token to one form |
| `tokenField` | `'fg_token'` | rename to be less guessable |
| `honeypotField` | `'website'` | rename to be less guessable |
| `minAgeMs` | `3000` | fill-time floor |
| `maxAgeMs` | `7200000` | token lifetime |
| `flagAt` | `3` | score at which a message is tagged |
| `brandTerms` | `[]` | words a scraper echoes back |
| `requireToken` | `true` | `false` to score without blocking |
| `rateLimit` | `{max:5, windowMs:3600000}` | `false` to disable |

### Rate limiting across instances

The default store is per-process memory: not shared between containers,
reset on deploy. Fine for one box. Refused attempts count toward the
window, so a flood keeps its own window full and recovering takes a full
window of silence.

Pass a `store` with `take(key, windowMs, now)` and `reset(key)` to back it
with Redis or a Durable Object when you run more than one instance.

## Submission campaigns (directories, listings, sign-up sheets)

Everything above judges one request. A submission campaign passes all of it: it
renders the form, fills it at human speed and sends something plausible. What
gives it away is the run: one caller posting a different product a minute,
alphabetically through domains it registered, each with a fresh
`hello@<that-domain>` contact so a per-email limit never fires.

```js
import { createCampaignDetector } from '@profullstack/form-guard';

const campaigns = createCampaignDetector(); // 30 min window, 5 domains/IP, 8 global

const verdict = await campaigns.observe({ ip, email, url, name });
if (verdict.level === 'ban') return new Response('Forbidden', { status: 403 }); // let ThreatCrush see it
if (verdict.level === 'hold') markForReview(); // accept, keep out of auto-approval
```

**Shape never acts alone.** A role address at the listed domain
(`hello@mycompany.com` listing `mycompany.com`) is how real founders sign up, so
it is only a signal. What acts is volume:

| level | when |
|---|---|
| `ban` | one address submits `ipDomains` (5) different domains inside the window, or repeats the pattern while a campaign is running |
| `hold` | `campaignThreshold` (8) pattern matches across all addresses inside the window (a proxy rotation) and this address has no history |
| `ok` | everything else |

Answer `ban` with a 4xx your edge logs: a 200 "silent drop" is invisible to a
log-reading banner like ThreatCrush. Pass a shared `store`
(`{ push(key, value, windowMs, now), reset(key?) }`) to hold the window across
instances.

### Banning with ThreatCrush

ThreatCrush reads the nginx log, so the 403 is what it bans on. Drop a rule like
this in `/etc/threatcrush/rules.d/` and restart the daemon
(`systemctl restart threatcrushd`; rules load only at start). Match the method
too: a 403 on GET/PATCH of the same path may be a person with a stale link.

```json
[{
  "id": "submission-campaign-403",
  "title": "Listing Submission Campaign Refused",
  "description": "POST to a submission endpoint refused with 403 by form-guard's campaign detector",
  "version": "1.0.0", "category": "web", "severity": "high",
  "source_types": ["log-watcher", "web"],
  "match": {
    "field": "message", "operator": "regex",
    "value": "^Client error 403: POST /api/fn/submissions\\b",
    "and": [{ "field": "host", "operator": "regex", "value": "^(www\\.)?saasrow\\.com$" }]
  },
  "threshold": 1, "window_seconds": 3600, "cooldown_seconds": 3600,
  "tags": ["web", "abuse", "submission-campaign", "form-guard"],
  "remediation": { "action": "block", "description": "Ban an address running a submission campaign" },
  "enabled": true
}]
```

Add a site by widening the `host` and path regexes. Do not test it from a box
the rule protects: five probes ban your own address.

## What this does not do

It does not stop a human being paid to fill in your form, and it does not
stop a headless browser that renders the page — both get a valid token.
Those land in the scoring layer, tagged rather than blocked, which is the
correct place for a judgement call a machine should not be making alone.

MIT © Profullstack, Inc.
