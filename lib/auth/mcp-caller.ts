import { createHash, timingSafeEqual } from 'node:crypto';
import { getClientIp } from '@/lib/api/rate-limit';
import type { McpTier } from '@/lib/mcp/rate-limit';

/**
 * Who is calling the hosted MCP endpoint (#2209).
 *
 * Until now the endpoint counted every call against the caller's IP, which is
 * the wrong unit for an agent: cloud egress means many agents share one
 * address, and one agent can appear as many. A caller that presents an API key
 * is now counted as that key, with the limits of its tier.
 *
 * Keys are configured on the deployment, not issued here: `MCP_API_KEYS` is a
 * JSON object mapping each raw key to its identity.
 *
 *   MCP_API_KEYS='{"sk_live_abc":{"id":"agent-1","tier":"standard",
 *     "scopes":["tools:read"],"maxIntentAmount":"100"}}'
 *
 * `id` is the public identity the caller is counted and logged as; it is never
 * the key itself. `tier` is `standard` or `anonymous` (the default when
 * omitted). A deployment with no `MCP_API_KEYS` has no keyed callers, so every
 * request is anonymous and behaves exactly as before.
 *
 * A request with no `Authorization` header stays anonymous rather than being
 * rejected: the hosted endpoint is public by design, and requiring a key would
 * break every existing client. A request that does present a key is
 * authenticated, so a bad one is rejected rather than silently downgraded.
 */

export interface McpCaller {
  kind: 'key' | 'anonymous';
  /** Public identity, safe to log. Never the raw key. */
  id: string;
  tier: McpTier;
  scopes: string[];
  /** Key the caller is rate limited under, e.g. `key:agent-1` or `ip:…`. */
  rateLimitKey: string;
  maxIntentAmount?: string;
}

export type ResolveCallerResult = { ok: true; caller: McpCaller } | { ok: false; message: string };

interface KeyedCallerConfig {
  id: string;
  tier: McpTier;
  scopes: string[];
  maxIntentAmount?: string;
}

const INVALID_KEY_MESSAGE = 'Invalid API key';

/** Digest-then-compare, so the comparison is constant-time for any key length. */
function constantTimeEqual(a: string, b: string): boolean {
  const digestA = createHash('sha256').update(a).digest();
  const digestB = createHash('sha256').update(b).digest();
  return timingSafeEqual(digestA, digestB);
}

function isTier(value: unknown): value is McpTier {
  return value === 'anonymous' || value === 'standard';
}

/**
 * Parses `MCP_API_KEYS`. Returns an empty map when it is unset or malformed —
 * a malformed store grants nothing, which is the safe direction.
 */
function readKeyStore(): Map<string, KeyedCallerConfig> {
  const raw = process.env.MCP_API_KEYS?.trim();
  if (!raw) return new Map();

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return new Map();
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return new Map();

  const store = new Map<string, KeyedCallerConfig>();
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!key || !value || typeof value !== 'object' || Array.isArray(value)) continue;
    const entry = value as Record<string, unknown>;
    if (typeof entry.id !== 'string' || entry.id.trim() === '') continue;

    const tier = isTier(entry.tier) ? entry.tier : 'anonymous';
    const scopes = Array.isArray(entry.scopes)
      ? entry.scopes.filter((scope): scope is string => typeof scope === 'string')
      : [];

    store.set(key, {
      id: entry.id.trim(),
      tier,
      scopes,
      ...(typeof entry.maxIntentAmount === 'string'
        ? { maxIntentAmount: entry.maxIntentAmount }
        : {}),
    });
  }
  return store;
}

function bearerToken(headers: Headers): string | undefined {
  const authorization = headers.get('authorization')?.trim();
  if (!authorization) return undefined;
  const [scheme, ...rest] = authorization.split(/\s+/);
  if (!scheme || scheme.toLowerCase() !== 'bearer') return '';
  return rest.join(' ').trim();
}

/**
 * Resolves the caller from the request headers.
 *
 * No `Authorization` header → anonymous, counted by IP exactly as before.
 * Any `Authorization` header that is not a configured key → failure, so the
 * route can answer 401 instead of quietly applying anonymous limits.
 */
export function resolveCaller(headers: Headers): ResolveCallerResult {
  const token = bearerToken(headers);

  if (token === undefined) {
    return {
      ok: true,
      caller: {
        kind: 'anonymous',
        id: 'anonymous',
        tier: 'anonymous',
        scopes: [],
        rateLimitKey: `ip:${getClientIp(headers)}`,
      },
    };
  }

  if (token) {
    for (const [key, config] of readKeyStore()) {
      if (!constantTimeEqual(key, token)) continue;
      return {
        ok: true,
        caller: {
          kind: 'key',
          id: config.id,
          tier: config.tier,
          scopes: [...config.scopes],
          rateLimitKey: `key:${config.id}`,
          ...(config.maxIntentAmount ? { maxIntentAmount: config.maxIntentAmount } : {}),
        },
      };
    }
  }

  return { ok: false, message: INVALID_KEY_MESSAGE };
}
