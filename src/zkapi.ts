// zkAPI integration. The wallet itself is the official browser SDK
// (@openanonymity/zkapi-browser-sdk, vendored in vendor/zkapi, see SOURCE.md):
// notes, proofs and settlement run in the local UI page and its proof worker.
// This module only (1) serves the SDK's pinned assets and (2) relays its network
// traffic through Tor, to an allowlist derived from the SDK's own trusted
// deployment config, with a fresh Tor identity per request so payment traffic
// shares no circuit with conversations. It never sees note secrets: it carries
// the same HTTP requests the SDK would otherwise send directly.
import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { fileURLToPath } from 'node:url';
import { TorAgent, newIdentity, TorError } from './tor.ts';

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'vendor', 'zkapi', 'v2c');
export const ZKAPI_INFERENCE_BASE = 'https://openrouter.ai/api/v1';

let cached: any;
function config() {
  if (cached !== undefined) return cached;
  try { cached = JSON.parse(fs.readFileSync(path.join(DIR, 'browser-config.json'), 'utf8')); } catch { cached = null; }
  return cached;
}

export function zkapiAssets(): { available: boolean; network: string | null; reason: string } {
  const c = config();
  if (!c) return { available: false, network: null, reason: 'zkAPI SDK assets not found in vendor/zkapi (see vendor/zkapi/SOURCE.md)' };
  if (!fs.existsSync(path.join(DIR, 'sdk.js'))) return { available: false, network: null, reason: 'zkAPI SDK bundle missing (vendor/zkapi/v2c/sdk.js)' };
  const t = c.trusted_deployment || {};
  if (t.deployment_status && t.deployment_status !== 'deployed') return { available: false, network: t.network || null, reason: `zkAPI deployment status is ${t.deployment_status}` };
  return { available: true, network: Number(t.chain_id) === 11155111 ? 'sepolia' : String(t.chain_id), reason: 'ok' };
}

/** Origins the SDK may reach, all through Tor. Inference (OpenRouter) is not here: it goes through the chat pipeline. */
export function allowedOrigins(): Map<string, 'protocol' | 'rpc' | 'verifier' | 'bundler'> {
  const t = config()?.trusted_deployment || {};
  const m = new Map<string, any>();
  const add = (u: string | undefined, kind: string) => { if (!u) return; const x = new URL(u); if (x.protocol === 'https:') m.set(x.origin, kind); };
  add(t.protocol_server_url, 'protocol');
  add(t.indexer_url, 'protocol');
  add(t.rpc_url, 'rpc');
  add(t.verifier_url, 'verifier');
  add(t.gasless?.bundler_url, 'bundler');
  return m;
}

export function protocolOrigin(): string | null {
  const u = config()?.trusted_deployment?.protocol_server_url;
  return u ? new URL(u).origin : null;
}

const TYPES: Record<string, string> = { '.js': 'text/javascript', '.json': 'application/json', '.wasm': 'application/wasm', '.pk': 'application/octet-stream', '.vk': 'application/octet-stream' };

/** Static file under /zkapi/v2c/, or null. */
export function asset(urlPath: string): { body: Buffer; type: string } | null {
  const rel = urlPath.replace(/^\/zkapi\/v2c\//, '');
  if (!/^[\w./-]+$/.test(rel) || rel.includes('..')) return null;
  const f = path.join(DIR, rel);
  if (!f.startsWith(DIR + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) return null;
  const type = TYPES[path.extname(f)];
  return type ? { body: fs.readFileSync(f), type } : null;
}

const REQ_HEADERS = ['content-type', 'accept'];
const RES_HEADERS = ['content-type', 'retry-after'];
const MAX_BODY = 8 * 1024 * 1024;

export interface RelayResult { status: number; headers: Record<string, string>; body: Buffer }

/**
 * One HTTPS request through Tor on a fresh identity. Refuses any origin outside
 * the SDK's trusted deployment, any redirect, and any non-HTTPS target. The
 * testnet password header is forwarded only to the protocol server's /v2/ paths,
 * as the SDK specifies.
 */
export function relay(proxy: { host: string; port: number }, target: string, method: string, headers: Record<string, string>, body: Buffer | undefined): Promise<RelayResult> {
  let u: URL;
  try { u = new URL(target); } catch { return Promise.reject(new RelayError(400, 'invalid target URL')); }
  const kind = allowedOrigins().get(u.origin);
  if (!kind || u.protocol !== 'https:' || u.username || u.password) return Promise.reject(new RelayError(403, `zkAPI relay refuses ${u.origin}`));
  if (!['GET', 'POST'].includes(method)) return Promise.reject(new RelayError(405, 'method not allowed'));
  const out: Record<string, string | number> = { 'user-agent': 'Mozilla/5.0' };
  for (const h of REQ_HEADERS) if (headers[h]) out[h] = headers[h];
  const pw = headers['x-zkapi-testnet-password'];
  if (pw && kind === 'protocol' && /\/v2\//.test(u.pathname)) out['x-zkapi-testnet-password'] = pw;
  if (body) out['content-length'] = body.length;
  return new Promise((resolve, reject) => {
    const req = https.request({ host: u.hostname, port: 443, path: u.pathname + u.search, method, headers: out, agent: new TorAgent(proxy, newIdentity()), timeout: 60_000 }, res => {
      if ((res.statusCode || 0) >= 300 && (res.statusCode || 0) < 400) { res.destroy(); return reject(new RelayError(502, 'redirect refused')); }
      const chunks: Buffer[] = []; let size = 0;
      res.on('data', (d: Buffer) => { size += d.length; if (size > MAX_BODY) { res.destroy(); reject(new RelayError(502, 'response too large')); } else chunks.push(d); });
      res.on('end', () => {
        const h: Record<string, string> = {};
        for (const k of RES_HEADERS) if (res.headers[k]) h[k] = String(res.headers[k]);
        resolve({ status: res.statusCode || 502, headers: h, body: Buffer.concat(chunks) });
      });
      res.on('error', () => reject(new RelayError(502, 'relay read failed')));
    });
    req.on('timeout', () => req.destroy(new RelayError(504, 'relay timed out')));
    req.on('error', (e: any) => reject(e instanceof RelayError ? e : new RelayError(e instanceof TorError ? 503 : 502, e instanceof TorError ? 'Tor unavailable for zkAPI traffic' : 'zkAPI relay failed')));
    if (body) req.write(body);
    req.end();
  });
}

export class RelayError extends Error { status: number; constructor(status: number, message: string) { super(message); this.status = status; } }
