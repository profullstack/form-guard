import { describe, expect, test } from 'bun:test';
import { createCampaignDetector, hostOf, isOwnDomainRoleAddress } from '../index.js';

const MIN = 60_000;

// The shape of the saasrow.com run on 2026-10-04: one domain a minute,
// alphabetical, a fresh hello@ / enquiries@ at each listed domain.
const RUN = ['abutly', 'amortlane', 'attestroom', 'attestvio', 'batesio', 'binstockly', 'breakerdesk', 'burdenrateledger', 'cafmlane', 'calibvo'];
const bot = (d, local = 'hello') => ({ email: `${local}@${d}.com`, url: `https://${d}.com`, name: d });

describe('signals', () => {
  test('hostOf normalises scheme, www and path', () => {
    expect(hostOf('https://www.Example.com/pricing?x=1')).toBe('example.com');
    expect(hostOf('example.com')).toBe('example.com');
    expect(hostOf('not a url')).toBe('');
  });

  test('role address at the listed domain is the pattern', () => {
    expect(isOwnDomainRoleAddress('hello@capanix.com', 'https://capanix.com')).toBe(true);
    expect(isOwnDomainRoleAddress('enquiries@sopvo.com', 'https://www.sopvo.com/')).toBe(true);
    expect(isOwnDomainRoleAddress('hello@acme.com', 'https://app.acme.com')).toBe(true);
  });

  test('a person, or another domain, is not the pattern', () => {
    expect(isOwnDomainRoleAddress('jane@capanix.com', 'https://capanix.com')).toBe(false);
    expect(isOwnDomainRoleAddress('hello@gmail.com', 'https://capanix.com')).toBe(false);
    expect(isOwnDomainRoleAddress('hello@capanix.com', '')).toBe(false);
  });
});

describe('shape never acts alone', () => {
  test('one founder listing their own product with hello@ is ok', async () => {
    const d = createCampaignDetector();
    const v = await d.observe({ ip: '1.1.1.1', ...bot('mycompany') });
    expect(v.level).toBe('ok');
    expect(v.signals).toContain('own_domain_role_address');
  });

  test('a founder listing three of their products in an hour is ok', async () => {
    const d = createCampaignDetector();
    let v;
    for (const [i, p] of ['one', 'two', 'three'].entries()) {
      v = await d.observe({ ip: '1.1.1.1', ...bot(p) }, i * 20 * MIN);
    }
    expect(v.level).toBe('ok');
  });
});

describe('one address working through a list', () => {
  test('is banned at the fifth distinct domain inside the window', async () => {
    const d = createCampaignDetector();
    const levels = [];
    for (const [i, name] of RUN.slice(0, 5).entries()) {
      levels.push((await d.observe({ ip: '6.6.6.6', ...bot(name) }, i * MIN)).level);
    }
    expect(levels).toEqual(['ok', 'ok', 'ok', 'ok', 'ban']);
  });

  test('is caught even without the role-address shape', async () => {
    const d = createCampaignDetector();
    let v;
    for (const [i, name] of RUN.slice(0, 5).entries()) {
      v = await d.observe({ ip: '6.6.6.6', email: `${name}@gmail.com`, url: `https://${name}.com`, name }, i * MIN);
    }
    expect(v.level).toBe('ban');
    expect(v.signals).toContain('ip_many_domains');
    expect(v.signals).toContain('alphabetical_run');
  });

  test('the window forgets a slow, legitimate submitter', async () => {
    const d = createCampaignDetector();
    let v;
    for (const [i, name] of RUN.slice(0, 6).entries()) {
      v = await d.observe({ ip: '2.2.2.2', ...bot(name) }, i * 31 * MIN);
    }
    expect(v.level).toBe('ok');
  });
});

describe('a campaign behind rotating addresses', () => {
  test('holds the pattern, never a person, and bans a repeat address', async () => {
    const d = createCampaignDetector();
    for (const [i, name] of RUN.slice(0, 8).entries()) {
      await d.observe({ ip: `10.0.0.${i}`, ...bot(name) }, i * MIN);
    }
    // Campaign is now active (8 pattern hits). A fresh address with the pattern is held.
    const fresh = await d.observe({ ip: '10.0.1.1', ...bot('cafmlane') }, 9 * MIN);
    expect(fresh.level).toBe('hold');
    expect(fresh.signals).toContain('campaign_active');

    // A real person mid-campaign is untouched.
    const person = await d.observe({ ip: '10.0.1.2', email: 'jane@realco.com', url: 'https://realco.com' }, 9 * MIN);
    expect(person.level).toBe('ok');

    // The held address comes back with the pattern again: ban.
    const again = await d.observe({ ip: '10.0.1.1', ...bot('calibvo', 'enquiries') }, 10 * MIN);
    expect(again.level).toBe('ban');
  });

  test('a caller with no address is never banned', async () => {
    const d = createCampaignDetector();
    let v;
    for (const [i, name] of RUN.entries()) v = await d.observe({ ...bot(name) }, i * MIN);
    expect(v.level).not.toBe('ban');
  });
});
