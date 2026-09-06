export type GuardAction = 'accept' | 'flag' | 'drop' | 'retry' | 'limited';

/**
 * Anything the guard can read a header from: a real `Headers`, a plain
 * object of header values, or any structural getter -- which is what a
 * framework's own request type usually narrows to.
 */
export type HeaderSource =
  | Headers
  | { get(name: string): string | null }
  | Record<string, string | undefined>;

export declare const ACTIONS: Readonly<{
  ACCEPT: 'accept';
  FLAG: 'flag';
  DROP: 'drop';
  RETRY: 'retry';
  LIMITED: 'limited';
}>;

export interface RateLimitStore {
  take(key: string, windowMs: number, now: number): Promise<number[]>;
  reset(key?: string): Promise<void>;
}

export interface RateLimitOptions {
  max?: number;
  windowMs?: number;
  store?: RateLimitStore;
}

export interface FormGuardOptions {
  /** HMAC secret. Any stable server-side string; never ship it to the client. */
  secret: string;
  /** Ties a token to one form. Must match between issue and check. */
  binding?: string;
  tokenField?: string;
  honeypotField?: string;
  /** Floor on human fill time, in ms. Default 3000. */
  minAgeMs?: number;
  /** Token lifetime, in ms. Default 2 hours. */
  maxAgeMs?: number;
  /** Score at or above which a submission is flagged. Default 3. */
  flagAt?: number;
  /** Brand words a scraper is likely to echo back at you. */
  brandTerms?: string[];
  /** Set false to score without blocking, for a soft rollout. Default true. */
  requireToken?: boolean;
  /** Per-address limiting, or false to disable. */
  rateLimit?: RateLimitOptions | false;
}

export interface Verdict {
  /** Whether the submission should be acted on at all. */
  allow: boolean;
  action: GuardAction;
  /** Stable machine-readable cause; null when accepted. */
  reason: string | null;
  score: number;
  signals: string[];
  suspicious: boolean;
  /** Time between render and submit, in ms, where a token was present. */
  fillMs: number | null;
  ip: string | null;
  userAgent: string | null;
  retryAfterMs?: number;
}

export interface CheckInput {
  fields: Record<string, unknown>;
  headers?: HeaderSource | null;
  ip?: string | null;
  now?: number;
}

export interface FormGuard {
  issue(now?: number): Promise<string>;
  fields(token: string): {
    token: { name: string; value: string };
    honeypot: { name: string };
  };
  hiddenHTML(token: string): string;
  check(input: CheckInput): Promise<Verdict>;
  readonly config: Readonly<
    Required<Omit<FormGuardOptions, 'rateLimit'>> & {
      rateLimit?: RateLimitOptions | false;
    }
  >;
}

export declare function createFormGuard(options: FormGuardOptions): FormGuard;

export declare function issueToken(
  secret: string,
  options?: { binding?: string; now?: number },
): Promise<string>;

export declare function verifyToken(
  secret: string,
  token: string,
  options?: { binding?: string; minAgeMs?: number; maxAgeMs?: number; now?: number },
): Promise<{
  ok: boolean;
  reason: string | null;
  issuedAt?: number;
  ageMs?: number;
  nonce?: string;
}>;

export declare function createRateLimiter(options?: RateLimitOptions): {
  check(key: string, now?: number): Promise<{ ok: boolean; count: number; retryAfterMs: number }>;
  reset(key?: string): Promise<void>;
};

export declare function createMemoryStore(options?: { maxKeys?: number }): RateLimitStore;

export declare function scoreSubmission(
  submission: { name?: string; email?: string; subject?: string; message?: string },
  options?: { flagAt?: number; brandTerms?: string[] },
): { score: number; signals: string[]; suspicious: boolean };

export declare function clientIp(headers: HeaderSource): string | null;
export declare function userAgent(headers: HeaderSource): string | null;

export declare function tagSubject(
  subject: string,
  verdict: { suspicious?: boolean; score?: number },
  options?: { tag?: string },
): string;

export declare function provenanceBlock(input?: {
  ip?: string | null;
  userAgent?: string | null;
  verdict?: Partial<Verdict> | null;
  submittedAt?: Date;
}): string;
