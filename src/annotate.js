/**
 * Turning a verdict into something useful in the inbox.
 *
 * A flagged message is still delivered, so the person reading it needs to
 * see why it was flagged and where it came from without opening headers.
 */

/** `[contact]` → `[contact][spam? 5]` when the verdict warrants it. */
export function tagSubject(subject, verdict, { tag = 'spam?' } = {}) {
  if (!verdict?.suspicious) return subject;
  return `${subject} [${tag} ${verdict.score}]`;
}

/**
 * A short provenance block to append to the message body.
 *
 * Written as plain text because it lands in a plain-text mail; keep it
 * greppable so an inbox rule can act on it.
 */
export function provenanceBlock({ ip, userAgent: ua, verdict, submittedAt = new Date() } = {}) {
  const lines = ['--', 'form-guard:'];
  lines.push(`  submitted: ${submittedAt.toISOString()}`);
  if (ip) lines.push(`  ip: ${ip}`);
  if (ua) lines.push(`  user-agent: ${String(ua).slice(0, 200)}`);
  if (typeof verdict?.fillMs === 'number') {
    lines.push(`  fill-time: ${(verdict.fillMs / 1000).toFixed(1)}s`);
  }
  if (verdict) {
    lines.push(`  score: ${verdict.score}${verdict.suspicious ? ' (flagged)' : ''}`);
    lines.push(`  signals: ${verdict.signals?.length ? verdict.signals.join(', ') : 'none'}`);
  }
  return lines.join('\n');
}
