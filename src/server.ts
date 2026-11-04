// Loopback HTTP server: chat UI, local API, OpenAI-compatible endpoint.
// Every request must carry a loopback Host (blocks DNS rebinding). Requests with
// an Origin header are accepted only from this server's own origin, so no website
// (including the public PARANOID site) can drive the daemon from a browser.
// Every API call needs the local token: the UI receives it inside the page it is
// served (same origin only); CLI clients read it from <profile>/local-token.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Runtime, PolicyError, InputError } from './runtime.ts';
import { asset as zkapiAsset, relay, protocolOrigin, RelayError } from './zkapi.ts';
import { loopbackAddr } from './config.ts';
import { SanitizerError, listLocalModels } from './sanitizer.ts';
import { ProviderError } from './provider.ts';
import { TorError } from './tor.ts';
import { ConfigError } from './config.ts';
import { log } from './log.ts';

const UI_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'ui');

export function loadToken(dir: string): string {
  const f = path.join(dir, 'local-token');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  return fs.readFileSync(f, 'utf8').trim();
}

class HttpError extends Error { status: number; code: string; constructor(status: number, code: string, message: string) { super(message); this.status = status; this.code = code; } }

const SEC_HEADERS = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
  'cross-origin-resource-policy': 'same-origin',
};
const CSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

function send(res: http.ServerResponse, status: number, body: unknown) {
  if (res.headersSent) { res.end(); return; }
  res.writeHead(status, { ...SEC_HEADERS, 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function readBody(req: http.IncomingMessage, limit: number): Promise<any> {
  const empty = !req.headers['content-type'] && (req.headers['content-length'] === '0' || (!req.headers['content-length'] && !req.headers['transfer-encoding']));
  if (empty) return {};
  if (!/^application\/json\b/.test(req.headers['content-type'] || '')) throw new HttpError(415, 'unsupported_media_type', 'content-type must be application/json');
  let size = 0; const chunks: Buffer[] = [];
  for await (const c of req) { size += c.length; if (size > limit) throw new HttpError(413, 'too_large', 'request body too large'); chunks.push(c); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { throw new HttpError(400, 'invalid_json', 'invalid JSON body'); }
}

async function readRaw(req: http.IncomingMessage, limit: number): Promise<Buffer> {
  let size = 0; const chunks: Buffer[] = [];
  for await (const c of req) { size += c.length; if (size > limit) throw new HttpError(413, 'too_large', 'request body too large'); chunks.push(c); }
  return Buffer.concat(chunks);
}

function lowerHeaders(req: http.IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') out[k.toLowerCase()] = v;
  return out;
}

function errorBody(e: any) {
  if (e instanceof HttpError) return [e.status, { error: { code: e.code, message: e.message } }] as const;
  if (e instanceof RelayError) return [e.status, { error: { code: 'zkapi_relay', message: e.message } }] as const;
  if (e instanceof PolicyError) return [409, { error: { code: e.code, message: e.message, missing: e.missing } }] as const;
  if (e instanceof InputError) return [400, { error: { code: e.code, message: e.message } }] as const;
  if (e instanceof ConfigError) return [400, { error: { code: 'invalid_config', message: e.message } }] as const;
  if (e instanceof SanitizerError) return [502, { error: { code: e.code, message: `${e.message}; the prompt was not sent` } }] as const;
  if (e instanceof TorError) return [503, { error: { code: e.code, message: `${e.message}; nothing was sent directly` } }] as const;
  if (e instanceof ProviderError) return [e.status, { error: { code: e.code, message: e.message } }] as const;
  if (e?.name === 'AbortError') return [499, { error: { code: 'cancelled', message: 'request cancelled' } }] as const;
  return [500, { error: { code: 'internal', message: 'internal error' } }] as const;
}

export function createServer(rt: Runtime, token: string) {
  const { host, port } = rt.cfg.listen;
  const hostOk = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  const originOk = new Set([`http://127.0.0.1:${port}`, `http://localhost:${port}`, `http://[::1]:${port}`]);
  const tokenBuf = Buffer.from(token);
  const authed = (req: http.IncomingMessage) => {
    const h = req.headers.authorization || '';
    const m = /^Bearer (\S+)$/.exec(h);
    if (!m) return false;
    const b = Buffer.from(m[1]);
    return b.length === tokenBuf.length && crypto.timingSafeEqual(b, tokenBuf);
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://localhost');
    const p = url.pathname;
    try {
      if (!hostOk.has(String(req.headers.host))) throw new HttpError(421, 'bad_host', 'requests must use a loopback host');
      const origin = req.headers.origin;
      if (origin !== undefined && !originOk.has(origin)) throw new HttpError(403, 'bad_origin', 'cross-origin requests are refused');
      // One exception: a top-level link from another site may open the chat page
      // itself (GET /, navigate, document). The other site cannot read the page or
      // frame it (frame-ancestors 'none'), and every API call stays same-origin.
      const topNav = req.method === 'GET' && (p === '/' || p === '/index.html') && req.headers['sec-fetch-mode'] === 'navigate' && req.headers['sec-fetch-dest'] === 'document';
      if (req.headers['sec-fetch-site'] === 'cross-site' && !topNav) throw new HttpError(403, 'bad_origin', 'cross-site requests are refused');

      // ---- static UI (token is injected into the page, same origin only)
      if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
        const html = fs.readFileSync(path.join(UI_DIR, 'index.html'), 'utf8').replace('__PARANOID_TOKEN__', token);
        res.writeHead(200, { ...SEC_HEADERS, 'content-type': 'text/html; charset=utf-8', 'content-security-policy': CSP });
        return res.end(html);
      }
      if (req.method === 'GET' && /^\/ui\/[\w.-]+\.(js|css|png|svg)$/.test(p)) {
        const f = path.join(UI_DIR, path.basename(p));
        if (!fs.existsSync(f)) throw new HttpError(404, 'not_found', 'not found');
        const type = { js: 'text/javascript', css: 'text/css', png: 'image/png', svg: 'image/svg+xml' }[p.split('.').pop()!]!;
        res.writeHead(200, { ...SEC_HEADERS, 'content-type': type });
        return res.end(fs.readFileSync(f));
      }
      if (req.method === 'GET' && p === '/healthz') return send(res, 200, { ok: true });

      // ---- zkAPI SDK assets (public, pinned build output)
      if (req.method === 'GET' && p.startsWith('/zkapi/v2c/')) {
        const a = zkapiAsset(p);
        if (!a) throw new HttpError(404, 'not_found', 'not found');
        res.writeHead(200, { ...SEC_HEADERS, 'content-type': a.type });
        return res.end(a.body);
      }
      // ---- the SDK's same-origin deployment rewrite: plain fetches without our token,
      // so they are limited to the protocol server, same-origin pages, and go through Tor
      if (p.startsWith('/zkapi-deployment/')) {
        if (!['GET', 'POST'].includes(req.method || '')) throw new HttpError(405, 'method_not_allowed', 'method not allowed');
        if (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') throw new HttpError(403, 'bad_origin', 'same-origin only');
        if (!rt.tor.state.verified) throw new HttpError(503, 'tor_unavailable', 'zkAPI traffic requires verified Tor routing; nothing was sent');
        const origin = protocolOrigin();
        if (!origin) throw new HttpError(503, 'zkapi_unavailable', 'zkAPI SDK not installed');
        const raw = await readRaw(req, 1024 * 1024);
        const r = await relay(loopbackAddr(rt.cfg.tor.socks), origin + p.slice('/zkapi-deployment'.length) + url.search, req.method!, lowerHeaders(req), raw.length ? raw : undefined);
        res.writeHead(r.status, { ...SEC_HEADERS, ...r.headers });
        return res.end(r.body);
      }

      if (!authed(req)) throw new HttpError(401, 'unauthorized', 'missing or invalid local token');
      const body = req.method === 'POST' ? await readBody(req, p === '/v1/chat/completions' ? 4 * 1024 * 1024 : 512 * 1024) : undefined;
      const ac = new AbortController();
      res.on('close', () => { if (!res.writableFinished) ac.abort(); });
      const route = `${req.method} ${p.replace(/\/[0-9a-f]{32}$/, '/:id')}`;

      switch (route) {
        // ---- OpenAI-compatible
        case 'GET /v1/models': return send(res, 200, await rt.models());
        case 'POST /v1/chat/completions': {
          await rt.completions(body, req.headers['x-paranoid-conversation'] as string | undefined, {
            head: (s, h) => res.writeHead(s, { ...SEC_HEADERS, ...h }),
            write: s => res.write(s),
            end: s => res.end(s),
          }, ac.signal);
          return;
        }
        // ---- overall status
        case 'GET /api/status': {
          const r = await rt.readiness(rt.cfg.profile, url.searchParams.get('refresh') === '1');
          return send(res, 200, { daemon: 'ok', profile: rt.cfg.profile, ready: r.ready, missing: r.missing, components: r.components, model: rt.cfg.provider.model, sessions: rt.sessions.sessions.size });
        }
        case 'GET /api/profiles': {
          const out: any = {};
          for (const prof of ['standard', 'private', 'paranoid'] as const) out[prof] = await rt.readiness(prof);
          return send(res, 200, out);
        }
        case 'POST /api/config/profile': {
          rt.config.update({ profile: body.profile });
          rt.modelsCache = null;
          log('config.profile', { profile: rt.cfg.profile });
          return send(res, 200, await rt.readiness());
        }
        case 'POST /api/config/provider': {
          rt.config.update({ provider: { model: body.model ?? null } });
          return send(res, 200, { model: rt.cfg.provider.model });
        }
        case 'POST /api/secrets/provider-key': {
          if (typeof body.key !== 'string' || !/^[\w-]{20,200}$/.test(body.key)) throw new HttpError(400, 'invalid_key', 'invalid API key format');
          rt.secrets.set('openrouter', body.key);
          rt.modelsCache = null;
          log('secret.stored', { name: 'provider' });
          return send(res, 200, { stored: true });
        }
        case 'DELETE /api/secrets/provider-key': rt.secrets.delete('openrouter'); return send(res, 200, { stored: false });

        // ---- sessions
        case 'POST /api/sessions': return send(res, 201, rt.sessions.create().publicView());
        case 'GET /api/sessions': return send(res, 200, [...rt.sessions.sessions.values()].map(s => s.publicView()));
        case 'DELETE /api/sessions/:id': return send(res, rt.sessions.end(p.split('/').pop()!) ? 200 : 404, {});

        // ---- chat (UI): preview, then approved send streamed as SSE
        case 'POST /api/chat/send': {
          const s = rt.sessions.get(body.sessionId);
          if (!s) throw new HttpError(404, 'unknown_session', 'unknown conversation');
          let started = false;
          const start = () => { if (!started) { started = true; res.writeHead(200, { ...SEC_HEADERS, 'content-type': 'text/event-stream' }); } };
          try {
            const r = await rt.send(s, { previewId: body.previewId, edited: body.edited, bypassText: body.bypassText, lease: body.lease, agent: body.agent === true },
              t => { start(); res.write(`data: ${JSON.stringify({ type: 'delta', text: t })}\n\n`); },
              e => { start(); res.write(`data: ${JSON.stringify({ type: 'tool', ...e })}\n\n`); });
            start();
            res.end(`data: ${JSON.stringify({ type: 'done', ...r })}\n\n`);
          } catch (e) {
            if (!started) throw e;
            const [, b] = errorBody(e);
            res.end(`data: ${JSON.stringify({ type: 'error', ...b.error })}\n\n`);
          }
          return;
        }
        case 'POST /api/chat/cancel': { const s = rt.sessions.get(body.sessionId); s?.busy?.abort(); return send(res, 200, { cancelled: !!s?.busy }); }

        // ---- sanitizer
        case 'GET /api/privacy/sanitizer/status': return send(res, 200, await rt.sanitizerState(true));
        case 'GET /api/privacy/sanitizer/models': return send(res, 200, { models: await listLocalModels(rt.cfg.sanitizer).catch(() => []) });
        case 'POST /api/privacy/sanitizer/config': {
          const patch: any = {};
          if ('model' in body) patch.model = body.model;
          if ('strictness' in body) patch.strictness = body.strictness;
          rt.config.update({ sanitizer: patch });
          return send(res, 200, await rt.sanitizerState(true));
        }
        case 'POST /api/privacy/sanitizer/preview': {
          const s = rt.sessions.get(body.sessionId);
          if (!s) throw new HttpError(404, 'unknown_session', 'unknown conversation');
          return send(res, 200, await rt.preview(s, body.text));
        }

        // ---- Tor
        case 'GET /api/privacy/tor/status': return send(res, 200, { ...rt.tor.state, socks: rt.cfg.tor.socks, isolation: 'IsolateSOCKSAuth, one identity per conversation' });
        case 'POST /api/privacy/tor/start': { await rt.tor.start(); return send(res, 200, await rt.tor.verify()); }
        case 'POST /api/privacy/tor/verify': return send(res, 200, await rt.tor.verify());
        case 'GET /api/privacy/tor/sessions': return send(res, 200, [...rt.sessions.sessions.values()].map(s => ({ id: s.id, isolated: !!s.torIdentity, routedVia: s.routedVia, requests: s.requests })));
        case 'POST /api/privacy/tor/reconnect': {
          const s = rt.sessions.get(body.sessionId);
          if (!s) throw new HttpError(404, 'unknown_session', 'unknown conversation');
          s.newCircuit();
          return send(res, 200, { id: s.id, newCircuit: true });
        }

        // ---- cover traffic
        case 'GET /api/privacy/cover-traffic/status': return send(res, 200, rt.cover.status());
        case 'POST /api/privacy/cover-traffic/config': {
          const allowed = ['urls', 'ratePerMinute', 'concurrency', 'maxRequestsPerHour', 'maxBytesPerHour', 'autoStopMinutes'];
          const patch = Object.fromEntries(Object.entries(body).filter(([k]) => allowed.includes(k)));
          rt.config.update({ cover: patch });
          rt.cover.configure(rt.cfg.cover);
          return send(res, 200, rt.cover.status());
        }
        case 'POST /api/privacy/cover-traffic/start': { rt.cover.start(rt.tor.state.verified); return send(res, 200, rt.cover.status()); }
        case 'POST /api/privacy/cover-traffic/stop': { rt.cover.stop('stopped by user'); return send(res, 200, rt.cover.status()); }

        // ---- payment: the zkAPI wallet is the official browser SDK running in the local UI;
        // the daemon holds no note, balance or transaction state and only relays its traffic
        case 'GET /api/payment/status': return send(res, 200, rt.paymentState());
        case 'GET /api/payment/balance':
        case 'GET /api/payment/transactions':
        case 'POST /api/payment/prepare-deposit':
        case 'POST /api/payment/prepare-withdrawal':
          throw new HttpError(501, 'wallet_in_ui', rt.paymentState().zkapi.available
            ? 'the zkAPI wallet runs in the local UI (official browser SDK): balance, deposits and withdrawals are managed there, and the daemon never holds note material'
            : rt.paymentState().zkapi.reason);
        case 'POST /api/zkapi/relay': {
          if (!rt.tor.state.verified) throw new HttpError(503, 'tor_unavailable', 'zkAPI traffic requires verified Tor routing; nothing was sent');
          if (typeof body.url !== 'string' || typeof body.method !== 'string') throw new HttpError(400, 'invalid_request', 'url and method are required');
          const h: Record<string, string> = {};
          for (const [k, v] of Object.entries(body.headers || {})) if (typeof v === 'string') h[k.toLowerCase()] = v;
          const raw = typeof body.bodyB64 === 'string' ? Buffer.from(body.bodyB64, 'base64') : undefined;
          const r = await relay(loopbackAddr(rt.cfg.tor.socks), body.url, body.method.toUpperCase(), h, raw);
          return send(res, 200, { status: r.status, headers: r.headers, bodyB64: r.body.toString('base64') });
        }

        // ---- sandbox
        case 'GET /api/sandbox/status': return send(res, 200, await rt.sandboxState());
        case 'POST /api/sandbox/bubblewrap': {
          if (typeof body.enabled !== 'boolean') throw new HttpError(400, 'invalid', 'enabled must be true or false');
          rt.config.update({ sandbox: { bubblewrap: body.enabled } });
          log('config.bubblewrap', { enabled: body.enabled });
          return send(res, 200, await rt.sandboxState(true));
        }
      }
      throw new HttpError(404, 'not_found', 'not found');
    } catch (e: any) {
      const [status, b] = errorBody(e);
      if (status === 500) log('http.error', { route: p, name: e?.name });
      send(res, status, b);
    }
  });
  server.requestTimeout = 0; // streams can be long; per-call timeouts live in the provider and sanitizer
  server.headersTimeout = 10_000;
  return { server, listen: () => new Promise<void>(r => server.listen(port, host, () => r())) };
}
