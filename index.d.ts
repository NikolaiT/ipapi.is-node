/** What `block` can list. */
export type Flag = 'vpn' | 'proxy' | 'tor' | 'datacenter' | 'abuser' | 'crawler' | 'mobile' | 'satellite';

/** The API's answer for one address. Fields documented at https://ipapi.is/developers.html */
export interface IpapiResponse {
  ip: string;
  is_bogon?: boolean;
  is_vpn?: boolean;
  is_proxy?: boolean;
  is_tor?: boolean;
  is_datacenter?: boolean;
  is_abuser?: boolean;
  is_crawler?: boolean;
  is_mobile?: boolean;
  is_satellite?: boolean;
  vpn?: { service?: string; url?: string; type?: string; last_seen_str?: string; [k: string]: unknown };
  datacenter?: { datacenter?: string; domain?: string; network?: string };
  company?: { name?: string; domain?: string; type?: string; [k: string]: unknown } | string;
  asn?: { asn?: number; org?: string; route?: string; [k: string]: unknown } | string;
  location?: { country?: string; country_code?: string; city?: string; latitude?: number; longitude?: number; [k: string]: unknown };
  [k: string]: unknown;
}

export interface Verdict {
  ip: string;
  blocked: boolean;
  reasons: Flag[];
  /** The VPN provider's name when the address is a VPN exit. */
  vpn?: string | null;
  /** The hosting provider's name when the address is in a datacenter. */
  datacenter?: string | null;
  data?: IpapiResponse;
  /** Set for private and loopback addresses, which are never looked up. */
  private?: boolean;
  /** Set when the API could not be reached and the request was let through. */
  error?: string;
}

export interface ClientOptions {
  /** Defaults to process.env.IPAPI_KEY. Without a key nothing is flagged. */
  key?: string;
  timeoutMs?: number;
  cacheTtlMs?: number;
  cacheSize?: number;
  fetch?: typeof fetch;
}

export interface Client {
  lookup(ip: string): Promise<IpapiResponse>;
  lookupMany(ips: string[]): Promise<Record<string, IpapiResponse>>;
  check(ip: string, options?: { block?: Flag[] }): Promise<Verdict>;
}

export interface GuardOptions extends ClientOptions {
  client?: Client;
  /** What to block. Defaults to ['vpn', 'proxy', 'tor']. */
  block?: Flag[];
  /** 'block' answers 403; 'flag' only sets req.ipapi. */
  mode?: 'block' | 'flag';
  /** Let requests through when the API cannot be reached. Defaults to true. */
  failOpen?: boolean;
  ip?: (req: any) => string | undefined;
  onBlocked?: (req: any, res: any, verdict: Verdict) => void;
  onError?: (err: Error, req: any) => void;
}

export function createClient(options?: ClientOptions): Client;
export function guard(options?: GuardOptions): (req: any, res: any, next: (err?: unknown) => void) => Promise<void>;
export function lookup(ip: string): Promise<IpapiResponse>;
export function check(ip: string, options?: { block?: Flag[] }): Promise<Verdict>;
export const FLAGS: Flag[];
