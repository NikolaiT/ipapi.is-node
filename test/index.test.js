'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createClient, guard } = require('..');

const VPN = {
  ip: '85.203.46.163', is_vpn: true, is_proxy: false, is_tor: false, is_datacenter: false, is_abuser: true,
  vpn: { service: 'Private Internet Access', type: 'exit_node' },
};
const HOME = { ip: '94.139.28.254', is_vpn: false, is_proxy: false, is_tor: false, is_datacenter: false };
const HOSTING = { ip: '45.33.32.156', is_datacenter: true, datacenter: { datacenter: 'Linode' } };

/** A fetch that answers from a table and records every request. */
function fakeFetch(answers) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body });
    if (body.ips) {
      return { ok: true, status: 200, json: async () => Object.fromEntries(body.ips.map((ip) => [ip, answers[ip]])) };
    }
    const answer = answers[body.q];
    if (answer instanceof Error) throw answer;
    if (answer && answer.error) return { ok: false, status: 429, json: async () => answer };
    return { ok: true, status: 200, json: async () => answer };
  };
  return { fetch, calls };
}

test('the key travels in the JSON body, never in the URL', async () => {
  const { fetch, calls } = fakeFetch({ [VPN.ip]: VPN });
  await createClient({ key: 'secret', fetch }).lookup(VPN.ip);
  assert.equal(calls[0].url, 'https://api.ipapi.is/');
  assert.deepEqual(calls[0].body, { q: VPN.ip, key: 'secret' });
});

test('without a key no key field is sent', async () => {
  const { fetch, calls } = fakeFetch({ [HOME.ip]: HOME });
  await createClient({ key: '', fetch }).lookup(HOME.ip);
  assert.deepEqual(calls[0].body, { q: HOME.ip });
});

test('lookups are cached, concurrent ones included', async () => {
  const { fetch, calls } = fakeFetch({ [VPN.ip]: VPN });
  const client = createClient({ key: 'k', fetch });
  await Promise.all([client.lookup(VPN.ip), client.lookup(VPN.ip), client.lookup(`::ffff:${VPN.ip}`)]);
  await client.lookup(VPN.ip);
  assert.equal(calls.length, 1);
});

test('a failed lookup is not cached', async () => {
  let fail = true;
  const fetch = async () => {
    if (fail) { fail = false; throw new Error('network down'); }
    return { ok: true, status: 200, json: async () => HOME };
  };
  const client = createClient({ key: 'k', fetch });
  await assert.rejects(client.lookup(HOME.ip), /network down/);
  assert.equal((await client.lookup(HOME.ip)).ip, HOME.ip);
});

test('API errors reject with the message and code', async () => {
  const { fetch } = fakeFetch({ '1.2.3.4': { error: 'Daily limit reached', error_code: 'ERR_QUOTA' } });
  await assert.rejects(createClient({ key: 'k', fetch }).lookup('1.2.3.4'), (err) => err.code === 'ERR_QUOTA' && err.status === 429);
});

test('check names the VPN and blocks what is listed', async () => {
  const { fetch } = fakeFetch({ [VPN.ip]: VPN, [HOSTING.ip]: HOSTING });
  const client = createClient({ key: 'k', fetch });
  const vpn = await client.check(VPN.ip);
  assert.equal(vpn.blocked, true);
  assert.deepEqual(vpn.reasons, ['vpn']);
  assert.equal(vpn.vpn, 'Private Internet Access');
  assert.equal((await client.check(HOSTING.ip)).blocked, false, 'datacenter is not blocked by default');
  const dc = await client.check(HOSTING.ip, { block: ['datacenter'] });
  assert.equal(dc.blocked, true);
  assert.equal(dc.datacenter, 'Linode');
});

test('private and loopback addresses are never looked up', async () => {
  const { fetch, calls } = fakeFetch({});
  const client = createClient({ key: 'k', fetch });
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.10', '172.20.0.1', '100.64.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1']) {
    const verdict = await client.check(ip);
    assert.equal(verdict.private, true, ip);
  }
  assert.equal(calls.length, 0);
});

test('bulk lookups go 100 per request and use the cache', async () => {
  const answers = {};
  const ips = Array.from({ length: 150 }, (_, i) => `198.51.${Math.floor(i / 250)}.${i}`);
  for (const ip of ips) answers[ip] = { ip };
  const { fetch, calls } = fakeFetch(answers);
  const client = createClient({ key: 'k', fetch });
  const out = await client.lookupMany(ips);
  assert.equal(Object.keys(out).length, 150);
  assert.deepEqual(calls.map((c) => c.body.ips.length), [100, 50]);
  await client.lookupMany(ips.slice(0, 10));
  assert.equal(calls.length, 2);
});

/** Runs the middleware once and reports what it did. */
async function run(middleware, ip) {
  const req = { ip };
  const res = { statusCode: 200, headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(body) { this.body = body; } };
  let nextCalled = false;
  let nextError;
  await middleware(req, res, (err) => { nextCalled = true; nextError = err; });
  return { req, res, nextCalled, nextError };
}

test('guard answers 403 for a VPN and lets a home connection through', async () => {
  const { fetch } = fakeFetch({ [VPN.ip]: VPN, [HOME.ip]: HOME });
  const middleware = guard({ key: 'k', fetch });
  const blocked = await run(middleware, VPN.ip);
  assert.equal(blocked.res.statusCode, 403);
  assert.equal(blocked.nextCalled, false);
  assert.equal(blocked.req.ipapi.vpn, 'Private Internet Access');
  const home = await run(middleware, HOME.ip);
  assert.equal(home.nextCalled, true);
  assert.equal(home.req.ipapi.blocked, false);
});

test("guard in 'flag' mode only sets req.ipapi", async () => {
  const { fetch } = fakeFetch({ [VPN.ip]: VPN });
  const result = await run(guard({ key: 'k', fetch, mode: 'flag' }), VPN.ip);
  assert.equal(result.nextCalled, true);
  assert.equal(result.req.ipapi.blocked, true);
});

test('guard fails open when the API is unreachable, or passes the error on when told to', async () => {
  const { fetch } = fakeFetch({ [HOME.ip]: new Error('timeout') });
  const errors = [];
  const open = await run(guard({ key: 'k', fetch, onError: (e) => errors.push(e.message) }), HOME.ip);
  assert.equal(open.nextCalled, true);
  assert.equal(open.nextError, undefined);
  assert.equal(open.req.ipapi.error, 'timeout');
  assert.deepEqual(errors, ['timeout']);
  const closed = await run(guard({ key: 'k', fetch, failOpen: false }), HOME.ip);
  assert.equal(closed.nextError.message, 'timeout');
});
