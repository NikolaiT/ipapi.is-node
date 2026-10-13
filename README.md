# ipapi.is

Look up any IP address with [ipapi.is](https://ipapi.is/?ref=npm), and keep
VPN, proxy, Tor and datacenter traffic away from your signup, login or checkout
with one Express middleware. VPN results name the provider, because ipapi.is
finds VPN exit nodes by connecting to the VPN services itself.

```sh
npm install ipapi.is
```

Get a free API key (1,000 lookups a day, commercial use allowed) at
[ipapi.is/app/signup](https://ipapi.is/app/signup?ref=npm) and put it in the
environment as `IPAPI_KEY`. Without a key the API answers with location and
network owner only, so nothing gets flagged.

## Block VPNs at signup (Express)

```js
const express = require('express');
const { guard } = require('ipapi.is');

const app = express();
app.set('trust proxy', 1); // behind a load balancer, so req.ip is the visitor

app.post('/signup', guard({ block: ['vpn', 'proxy', 'tor', 'datacenter'] }), (req, res) => {
  // Only reached by visitors that are none of the above.
  res.send('Welcome!');
});
```

A blocked request gets a `403` with a JSON error; pass `onBlocked(req, res,
verdict)` to answer differently. Every request carries the verdict on
`req.ipapi`:

```js
{ ip: '85.203.46.163', blocked: true, reasons: ['vpn'], vpn: 'Private Internet Access', datacenter: null, data: { /* the full API response */ } }
```

### Flag instead of block

```js
app.post('/login', guard({ mode: 'flag' }), (req, res) => {
  if (req.ipapi.blocked) return askForSecondFactor(req, res);
  // ...
});
```

## Next.js middleware

```ts
// middleware.ts
import { NextResponse, type NextRequest } from 'next/server';
import { createClient } from 'ipapi.is';

const ipapi = createClient(); // reads IPAPI_KEY

export async function middleware(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  const verdict = await ipapi.check(ip ?? '').catch(() => null); // let it through if the API is down
  if (verdict?.blocked) {
    return NextResponse.json({ error: `Signups through ${verdict.vpn ?? 'a VPN or proxy'} are not allowed` }, { status: 403 });
  }
  return NextResponse.next();
}

export const config = { matcher: ['/signup', '/api/signup'] };
```

## Look up an address

```js
const { lookup, createClient } = require('ipapi.is');

const ip = await lookup('85.203.46.163');
ip.is_vpn;           // true
ip.vpn.service;      // 'Private Internet Access'
ip.company.name;     // 'EXPRESS-EQUINIX-LONDON'
ip.location.city;    // 'London'

const asn = await lookup('AS15169');

// Up to 100 addresses per request (needs a key):
const many = await createClient().lookupMany(['1.1.1.1', '8.8.8.8', '2606:4700::1111']);
```

All fields are described in the [API documentation](https://ipapi.is/docs.html?ref=npm).

## What `block` can list

`vpn`, `proxy`, `tor`, `datacenter`, `abuser`, `crawler`, `mobile`,
`satellite`. The default is `['vpn', 'proxy', 'tor']`: datacenter traffic is
often legitimate (corporate egress, uptime checks), so add it where only people
should arrive.

## Options

Both `createClient(options)` and `guard(options)` take:

| Option | Default | |
|---|---|---|
| `key` | `process.env.IPAPI_KEY` | Your API key. Keep it in the environment, not in code. |
| `timeoutMs` | `2000` | Per lookup. |
| `cacheTtlMs` | 6 hours | Each address is looked up once per TTL. |
| `cacheSize` | `10000` | Addresses kept in memory. |
| `fetch` | `globalThis.fetch` | Node.js 18 or newer has one. |

`guard()` adds `block`, `mode` (`'block'` or `'flag'`), `failOpen` (default
`true`: if the API cannot be reached the request goes through rather than
locking your users out; `false` passes the error to `next`), `ip(req)` to read
the address another way, `onBlocked` and `onError`.

Private, loopback and link-local addresses are never sent to the API, so local
development costs no lookups.

## License

MIT. ipapi.is is a German IP intelligence API: geolocation, ASN, company and
abuse data, VPN, proxy and datacenter detection, and downloadable databases.
[Pricing](https://ipapi.is/pricing.html?ref=npm).
