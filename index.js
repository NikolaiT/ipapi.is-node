'use strict';

// ipapi.is for Node.js: look up an IP address, and guard() an Express or
// Connect route against VPN, proxy, Tor and datacenter traffic.
// API docs: https://ipapi.is/docs.html

const API = 'https://api.ipapi.is/';
const BULK_LIMIT = 100;
const FLAGS = {
  vpn: 'is_vpn',
  proxy: 'is_proxy',
  tor: 'is_tor',
  datacenter: 'is_datacenter',
  abuser: 'is_abuser',
  crawler: 'is_crawler',
  mobile: 'is_mobile',
  satellite: 'is_satellite',
};
const DEFAULT_BLOCK = ['vpn', 'proxy', 'tor'];

// Addresses never worth a lookup: private, loopback, link-local, CGNAT, unspecified.
const PRIVATE = [
  /^10\./, /^127\./, /^0\./, /^169\.254\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, /^::1?$/, /^f[cd][0-9a-f]{0,2}:/i, /^fe[89ab][0-9a-f]?:/i,
];

/** The address as the API wants it: trimmed, IPv4-mapped IPv6 unwrapped. */
function normalize(ip) {
  const s = String(ip || '').trim();
  return /^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(s) ? s.slice(7) : s;
}

const isPrivate = (ip) => PRIVATE.some((re) => re.test(ip));

function createClient(options = {}) {
  const env = typeof process !== 'undefined' && process.env ? process.env : {};
  const key = options.key !== undefined ? options.key : env.IPAPI_KEY;
  const fetchImpl = options.fetch || globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 2000;
  const ttlMs = options.cacheTtlMs ?? 6 * 3600 * 1000;
  const maxEntries = options.cacheSize ?? 10000;
  const cache = new Map();
  let warned = false;

  if (typeof fetchImpl !== 'function') throw new Error('ipapi.is: no fetch available (Node.js 18+ or pass options.fetch)');

  async function post(body) {
    const res = await fetchImpl(API, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      // The key goes in the body: a URL ends up in logs.
      body: JSON.stringify(key ? { ...body, key } : body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || data.error) {
      const err = new Error(`ipapi.is: ${(data && data.error) || `HTTP ${res.status}`}`);
      err.status = res.status;
      err.code = data && data.error_code;
      throw err;
    }
    return data;
  }

  const cached = (ip) => {
    const hit = cache.get(ip);
    if (hit && Date.now() - hit.at < ttlMs) return hit.value;
    cache.delete(ip);
    return undefined;
  };
  const remember = (ip, value) => {
    if (cache.size >= maxEntries) cache.delete(cache.keys().next().value);
    cache.set(ip, { at: Date.now(), value });
    return value;
  };

  /** The API's full answer for one IP address or AS number ("AS15169"). Cached. */
  function lookup(ip) {
    const q = normalize(ip);
    const hit = cached(q);
    if (hit) return hit;
    // The promise is cached, so concurrent requests from one address cost one lookup.
    const pending = post({ q }).catch((err) => {
      cache.delete(q);
      throw err;
    });
    return remember(q, pending);
  }

  /** Several addresses at once, 100 per request (needs a key). An object keyed by address. */
  async function lookupMany(ips) {
    const wanted = [...new Set(ips.map(normalize))];
    const out = {};
    const missing = [];
    for (const ip of wanted) {
      const hit = cached(ip);
      if (hit) out[ip] = await hit;
      else missing.push(ip);
    }
    for (let i = 0; i < missing.length; i += BULK_LIMIT) {
      const batch = missing.slice(i, i + BULK_LIMIT);
      const data = await post({ ips: batch });
      for (const ip of batch) {
        if (data[ip]) out[ip] = await remember(ip, Promise.resolve(data[ip]));
      }
    }
    return out;
  }

  /**
   * Whether an address should be blocked: { ip, blocked, reasons, vpn, datacenter, data }.
   * `block` lists what counts: vpn, proxy, tor, datacenter, abuser, crawler, mobile, satellite.
   */
  async function check(ip, { block = DEFAULT_BLOCK } = {}) {
    const address = normalize(ip);
    if (!address || isPrivate(address)) return { ip: address, blocked: false, reasons: [], private: true };
    if (!key && !warned) {
      warned = true;
      console.warn('ipapi.is: no API key (set IPAPI_KEY). Keyless lookups return location and network owner '
        + 'only, so nothing is flagged. A free key: https://ipapi.is/app/signup?ref=npm');
    }
    const data = await lookup(address);
    const reasons = block.filter((flag) => FLAGS[flag] && data[FLAGS[flag]] === true);
    return {
      ip: address,
      blocked: reasons.length > 0,
      reasons,
      vpn: data.vpn ? data.vpn.service : null,
      datacenter: data.datacenter ? data.datacenter.datacenter : null,
      data,
    };
  }

  return { lookup, lookupMany, check };
}

/**
 * Express / Connect middleware. Puts the verdict on req.ipapi and, in the
 * default mode 'block', answers 403 for what `block` lists. If the API cannot
 * be reached the request goes through (failOpen), so an outage never locks
 * your users out.
 */
function guard(options = {}) {
  const client = options.client || createClient(options);
  const block = options.block || DEFAULT_BLOCK;
  const mode = options.mode || 'block';
  const failOpen = options.failOpen !== false;
  const ipOf = options.ip || ((req) => req.ip || (req.socket && req.socket.remoteAddress));
  const onError = options.onError || (() => {});
  const onBlocked = options.onBlocked || ((req, res) => {
    res.statusCode = 403;
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ error: 'Requests from VPNs, proxies and Tor are not accepted here.' }));
  });

  return async function ipapiGuard(req, res, next) {
    let verdict;
    try {
      verdict = await client.check(ipOf(req), { block });
    } catch (err) {
      onError(err, req);
      if (!failOpen) return next(err);
      verdict = { ip: normalize(ipOf(req)), blocked: false, reasons: [], error: err.message };
    }
    req.ipapi = verdict;
    if (verdict.blocked && mode === 'block') return onBlocked(req, res, verdict);
    return next();
  };
}

let defaultClient;
const shared = () => (defaultClient = defaultClient || createClient());

module.exports = {
  createClient,
  guard,
  lookup: (ip) => shared().lookup(ip),
  check: (ip, options) => shared().check(ip, options),
  FLAGS: Object.keys(FLAGS),
};
