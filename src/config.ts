// Configuration: one JSON file in the profile directory, validated on every load
// and every change. Trusted values (provider host allowlist, listen address) are
// only ever read from this file, never accepted from the HTTP API.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';

export type Profile = 'standard' | 'private' | 'paranoid';
export type Strictness = 'minimal' | 'standard' | 'strict';

export interface Config {
  listen: { host: string; port: number };
  profile: Profile;
  provider: { baseUrl: string; allowedHosts: string[]; model: string | null };
  tor: { socks: string; exe: string | null; manage: boolean };
  sanitizer: { baseUrl: string; model: string | null; strictness: Strictness; timeoutMs: number };
  cover: {
    urls: string[];
    ratePerMinute: number;
    concurrency: number;
    maxRequestsPerHour: number;
    maxBytesPerHour: number;
    autoStopMinutes: number;
  };
  sandbox: { bubblewrap: boolean; wslDistro: string };
}

export const DEFAULTS: Config = {
  listen: { host: '127.0.0.1', port: 7700 },
  profile: 'private',
  provider: { baseUrl: 'https://openrouter.ai/api/v1', allowedHosts: ['openrouter.ai'], model: null },
  tor: { socks: '127.0.0.1:9050', exe: null, manage: true },
  sanitizer: { baseUrl: 'http://127.0.0.1:11434/v1', model: null, strictness: 'standard', timeoutMs: 90_000 },
  cover: { urls: [], ratePerMinute: 6, concurrency: 2, maxRequestsPerHour: 360, maxBytesPerHour: 64 * 1024 * 1024, autoStopMinutes: 60 },
  sandbox: { bubblewrap: true, wslDistro: '' },
};

export function profileDir(): string {
  if (process.env.PARANOID_HOME) return process.env.PARANOID_HOME;
  if (process.platform === 'win32') return path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'paranoid');
  return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'paranoid');
}

export class ConfigError extends Error {}

export function isLoopbackHost(host: string): boolean {
  return host === '127.0.0.1' || host === '::1';
}

/** Splits "host:port" for a numeric loopback address. */
export function loopbackAddr(value: string): { host: string; port: number } {
  const m = /^(127\.0\.0\.1|\[::1\]):(\d{1,5})$/.exec(value);
  if (!m) throw new ConfigError(`${value} must be a numeric loopback address with a port`);
  const port = +m[2];
  if (port < 1 || port > 65535) throw new ConfigError(`invalid port in ${value}`);
  return { host: m[1].replace(/[[\]]/g, ''), port };
}

export function checkHttpsUrl(value: string, allowedHosts?: string[]): URL {
  let u: URL;
  try { u = new URL(value); } catch { throw new ConfigError(`invalid URL ${value}`); }
  if (u.protocol !== 'https:') throw new ConfigError(`${value} must use https`);
  if (u.username || u.password || u.search || u.hash) throw new ConfigError(`${value} must not carry credentials, query or fragment`);
  if (net.isIP(u.hostname.replace(/[[\]]/g, '')) || u.hostname === 'localhost' || u.hostname.endsWith('.local') || u.hostname.endsWith('.internal')) {
    throw new ConfigError(`${value} must name a public host`);
  }
  if (u.port && u.port !== '443') throw new ConfigError(`${value} must use port 443`);
  if (allowedHosts && !allowedHosts.includes(u.hostname)) throw new ConfigError(`${u.hostname} is not in provider.allowedHosts`);
  return u;
}

export function validate(c: Config): Config {
  if (!isLoopbackHost(c.listen.host)) throw new ConfigError('listen.host must be 127.0.0.1 or ::1 (remote access is not supported)');
  if (!Number.isInteger(c.listen.port) || c.listen.port < 1024 || c.listen.port > 65535) throw new ConfigError('listen.port must be 1024-65535');
  if (!['standard', 'private', 'paranoid'].includes(c.profile)) throw new ConfigError('profile must be standard, private or paranoid');
  checkHttpsUrl(c.provider.baseUrl, c.provider.allowedHosts);
  if (c.provider.model !== null && !/^[\w.:/-]{1,128}$/.test(c.provider.model)) throw new ConfigError('invalid provider.model');
  loopbackAddr(c.tor.socks);
  let s: URL;
  try { s = new URL(c.sanitizer.baseUrl); } catch { throw new ConfigError('invalid sanitizer.baseUrl'); }
  // the sanitizer sees raw prompts: it must stay on this machine
  if (s.protocol !== 'http:' && s.protocol !== 'https:') throw new ConfigError('sanitizer.baseUrl must be http(s)');
  if (!isLoopbackHost(s.hostname.replace(/[[\]]/g, ''))) throw new ConfigError('sanitizer.baseUrl must be a numeric loopback address');
  if (c.sanitizer.model !== null && !/^[\w.:/-]{1,128}$/.test(c.sanitizer.model)) throw new ConfigError('invalid sanitizer.model');
  if (!['minimal', 'standard', 'strict'].includes(c.sanitizer.strictness)) throw new ConfigError('sanitizer.strictness must be minimal, standard or strict');
  const v = c.cover;
  if (!Array.isArray(v.urls) || v.urls.length > 16) throw new ConfigError('cover.urls: at most 16 URLs');
  v.urls.forEach(u => checkHttpsUrl(u));
  const range = (n: number, lo: number, hi: number, name: string) => { if (typeof n !== 'number' || !(n >= lo && n <= hi)) throw new ConfigError(`${name} must be between ${lo} and ${hi}`); };
  range(v.ratePerMinute, 0.5, 60, 'cover.ratePerMinute');
  range(v.concurrency, 1, 8, 'cover.concurrency');
  range(v.maxRequestsPerHour, 1, 3600, 'cover.maxRequestsPerHour');
  range(v.maxBytesPerHour, 64 * 1024, 1024 * 1024 * 1024, 'cover.maxBytesPerHour');
  range(v.autoStopMinutes, 1, 24 * 60, 'cover.autoStopMinutes');
  if (typeof c.sandbox?.bubblewrap !== 'boolean') throw new ConfigError('sandbox.bubblewrap must be true or false');
  if (typeof c.sandbox.wslDistro !== 'string' || (c.sandbox.wslDistro && !/^[\w.-]{1,64}$/.test(c.sandbox.wslDistro))) throw new ConfigError('sandbox.wslDistro must be a WSL distribution name');
  return c;
}

function merge(base: any, over: any): any {
  if (!over || typeof over !== 'object' || Array.isArray(over)) return over === undefined ? base : over;
  const out: any = { ...base };
  for (const k of Object.keys(over)) out[k] = k in base && base[k] && typeof base[k] === 'object' && !Array.isArray(base[k]) ? merge(base[k], over[k]) : over[k];
  return out;
}

export class ConfigStore {
  dir: string;
  file: string;
  value: Config;
  constructor(dir = profileDir()) {
    this.dir = dir;
    this.file = path.join(dir, 'config.json');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    let raw: any = {};
    if (fs.existsSync(this.file)) raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    this.value = validate(merge(structuredClone(DEFAULTS), raw));
    if (!fs.existsSync(this.file)) this.save();
  }
  update(patch: Partial<Config> | any): Config {
    const next = validate(merge(structuredClone(this.value), patch));
    this.value = next;
    this.save();
    return next;
  }
  save() {
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.value, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}
