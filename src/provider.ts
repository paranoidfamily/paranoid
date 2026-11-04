// Remote inference provider (OpenAI-compatible, default OpenRouter). Requests
// carry only allow-listed fields and no identifying headers. The route is decided
// by the caller: a TorAgent (isolated identity) or direct, never a silent mix.
import https from 'node:https';
import type { IncomingMessage } from 'node:http';
import { checkHttpsUrl } from './config.ts';

/** OpenRouter wraps upstream failures as "Provider returned error"; the useful reason is in metadata.raw. */
export function providerMessage(j: any, status: number | undefined): string {
  const generic = j?.error?.message;
  const raw = typeof j?.error?.metadata?.raw === 'string' ? j.error.metadata.raw : '';
  const m = raw && (!generic || /provider returned error/i.test(generic)) ? raw : generic;
  return m ? `provider: ${String(m).replace(/\s+/g, ' ').slice(0, 240)}` : `provider returned ${status}`;
}

export class ProviderError extends Error {
  status: number;
  code: string;
  constructor(message: string, status = 502, code = 'provider_error') { super(message); this.status = status; this.code = code; }
}

const ALLOWED = ['model', 'messages', 'stream', 'temperature', 'top_p', 'max_tokens', 'max_completion_tokens', 'stop', 'presence_penalty', 'frequency_penalty', 'seed', 'response_format'];

export function filterBody(body: any): any {
  const out: any = {};
  for (const k of ALLOWED) if (body[k] !== undefined) out[k] = body[k];
  if (out.stream) out.stream_options = { include_usage: true };
  return out;
}

export interface Route { agent: https.Agent | undefined; via: 'tor' | 'direct' }

export function request(baseUrl: string, allowedHosts: string[], apiKey: string, route: Route, method: 'GET' | 'POST', pathname: string, body: any, signal?: AbortSignal): Promise<IncomingMessage> {
  const base = checkHttpsUrl(baseUrl, allowedHosts);
  const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: base.hostname,
      port: 443,
      path: base.pathname.replace(/\/$/, '') + pathname,
      method,
      agent: route.agent ?? new https.Agent({ keepAlive: false }),
      timeout: 120_000,
      signal,
      headers: {
        'user-agent': 'Mozilla/5.0',
        accept: body?.stream ? 'text/event-stream' : 'application/json',
        ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
        ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}),
      },
    }, res => resolve(res));
    req.on('timeout', () => req.destroy(new ProviderError('provider timed out', 504, 'provider_timeout')));
    req.on('error', (e: any) => reject(e instanceof ProviderError ? e : new ProviderError(route.via === 'tor' ? 'provider unreachable through Tor' : 'provider unreachable', 502, e?.code === 'tor_unavailable' ? 'tor_unavailable' : 'provider_unreachable')));
    if (data) req.write(data);
    req.end();
  });
}

export async function readJson(res: IncomingMessage, limit = 8 * 1024 * 1024): Promise<any> {
  let size = 0; const chunks: Buffer[] = [];
  for await (const c of res) { size += c.length; if (size > limit) throw new ProviderError('provider response too large'); chunks.push(c); }
  const text = Buffer.concat(chunks).toString('utf8');
  try { return JSON.parse(text); } catch { throw new ProviderError(`provider returned ${res.statusCode} with a non-JSON body`); }
}
