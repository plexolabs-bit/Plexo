// StellarHub ZK reference · https://stellarhub.io
/**
 * ZK pre-flight check — probes `/api/v1/zk/health` before attempting a ZK send.
 *
 * The backend exposes a network-mode selector (`ZK_NETWORK`:
 * `testnet_only | mainnet | off`).
 * This helper caches the result for 30s to avoid hammering the health endpoint
 * when the user toggles the ZK button repeatedly.
 *
 * See the backend ZK health route for the response shape (see project docs).
 */
export type ZkAvailabilityMode = 'testnet_only' | 'mainnet' | 'off';

export interface ZkAvailability {
  ok: boolean;
  mode: ZkAvailabilityMode;
  ready: boolean;
  protocol25Live: string;
  reason?: string;
}

interface CacheEntry {
  value: ZkAvailability;
  expiresAt: number;
}

const CACHE_TTL_MS = 30_000;
let cache: CacheEntry | null = null;

function resolveBaseUrl(): string {
  // Mirrors resolveBaseUrl in client.ts — ZK endpoints are proxied by
  // Express at `/api/v1/zk/*` (was `/api/v1/v1` — a double-v1 typo that 404'd).
  return '/api/v1';
}

function parseMode(raw: string | undefined): ZkAvailabilityMode {
  switch (raw) {
    case 'testnet_only':
    case 'mainnet':
      return raw;
    default:
      return 'off';
  }
}

/**
 * Check if the ZK subsystem is reachable and what mode it is in.
 *
 * `ok: false` means the send UI should short-circuit and fall back to the
 * standard (non-ZK) path. A transient network error also yields `ok: false`
 * with `mode: 'off'` and a populated `reason`.
 *
 * Result cached for 30s in module scope; pass `{force: true}` to bypass.
 */
export async function checkZkAvailable(
  opts?: { force?: boolean; fetchImpl?: typeof fetch },
): Promise<ZkAvailability> {
  const now = Date.now();
  if (!opts?.force && cache && cache.expiresAt > now) {
    return cache.value;
  }

  const fetchImpl = opts?.fetchImpl ?? fetch;
  let result: ZkAvailability;

  try {
    const res = await fetchImpl(`${resolveBaseUrl()}/zk/health`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!res.ok) {
      result = {
        ok: false,
        mode: 'off',
        ready: false,
        protocol25Live: 'off',
        reason: `ZK health returned ${res.status}`,
      };
    } else {
      const body = (await res.json()) as {
        ready?: boolean;
        dependencies?: Record<string, string>;
        warnings?: string[];
      };
      const deps = body.dependencies || {};
      const networkMode = parseMode(deps.zk_network_mode);
      const protocol25Live = deps.protocol25_live || 'off';
      const ok = networkMode !== 'off' && protocol25Live !== 'off';

      result = {
        ok,
        mode: networkMode,
        ready: Boolean(body.ready),
        protocol25Live,
        reason: ok ? undefined : `zk_network=${networkMode}, protocol25=${protocol25Live}`,
      };
    }
  } catch (err) {
    result = {
      ok: false,
      mode: 'off',
      ready: false,
      protocol25Live: 'off',
      reason: err instanceof Error ? err.message : 'ZK health probe failed',
    };
  }

  cache = { value: result, expiresAt: now + CACHE_TTL_MS };
  return result;
}

/** Drop the cached health result (used by tests / forced refresh). */
export function clearZkAvailabilityCache(): void {
  cache = null;
}
