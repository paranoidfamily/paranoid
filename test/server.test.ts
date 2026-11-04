import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { makeRuntime } from './helpers.ts';
import { createServer } from '../src/server.ts';

async function boot() {
  const { rt } = await makeRuntime({ profile: 'paranoid' });
  const probe = net.createServer(); await new Promise<void>(r => probe.listen(0, '127.0.0.1', () => r()));
  const port = (probe.address() as net.AddressInfo).port; probe.close();
  rt.config.update({ listen: { port } });
  const token = 'a'.repeat(64);
  const s = createServer(rt, token);
  await s.listen();
  const call = (p: string, opts: { method?: string; headers?: Record<string, string>; body?: string } = {}) => new Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }>((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: p, method: opts.method || 'GET', headers: { host: `127.0.0.1:${port}`, ...opts.headers } }, res => {
      let b = ''; res.on('data', d => b += d); res.on('end', () => resolve({ status: res.statusCode!, body: b, headers: res.headers }));
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
  return { rt, port, token, call, close: () => { s.server.close(); rt.sessions.endAll(); } };
}

test('rejects foreign Host (DNS rebinding), foreign Origin, missing token', async () => {
  const b = await boot();
  assert.equal((await b.call('/api/status', { headers: { host: 'evil.example:80', authorization: `Bearer ${b.token}` } })).status, 421);
  assert.equal((await b.call('/api/status', { headers: { origin: 'https://paranoid2.vercel.app', authorization: `Bearer ${b.token}` } })).status, 403);
  assert.equal((await b.call('/api/status')).status, 401);
  assert.equal((await b.call('/api/status', { headers: { authorization: 'Bearer ' + 'b'.repeat(64) } })).status, 401);
  b.close();
});

test('serves the UI with the token only to same-origin loopback requests, with a strict CSP', async () => {
  const b = await boot();
  const r = await b.call('/');
  assert.equal(r.status, 200);
  assert.ok(r.body.includes(b.token));
  assert.match(String(r.headers['content-security-policy']), /frame-ancestors 'none'/);
  assert.equal(r.headers['x-frame-options'], 'DENY');
  assert.equal((await b.call('/', { headers: { origin: 'https://evil.example' } })).status, 403);
  b.close();
});

test('status reports paranoid mode unavailable with the missing layers', async () => {
  const b = await boot();
  const r = await b.call('/api/status', { headers: { authorization: `Bearer ${b.token}` } });
  const j = JSON.parse(r.body);
  assert.equal(j.ready, false);
  assert.deepEqual(j.missing.sort(), ['cover_traffic', 'sanitizer', 'tor']);
  b.close();
});

test('zkAPI relay: Tor required, only the SDK deployment hosts, same-origin rewrite only', async () => {
  const b = await boot();
  const auth = { authorization: `Bearer ${b.token}`, 'content-type': 'application/json' };
  // Tor not verified: nothing leaves
  let r = await b.call('/api/zkapi/relay', { method: 'POST', headers: auth, body: JSON.stringify({ url: 'https://zkapi-sepolia.openanonymity.ai/v0.4/health', method: 'GET' }) });
  assert.equal(r.status, 503);
  r = await b.call('/zkapi-deployment/v0.4/health', { headers: { 'sec-fetch-site': 'same-origin' } });
  assert.equal(r.status, 503);
  // a hostile page cannot use the rewrite
  r = await b.call('/zkapi-deployment/v0.4/health', { headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(r.status, 403);
  // with Tor "verified", a non-allowlisted origin is refused before any connection
  b.rt.tor.state.verified = true;
  r = await b.call('/api/zkapi/relay', { method: 'POST', headers: auth, body: JSON.stringify({ url: 'https://evil.example/steal', method: 'POST' }) });
  assert.equal(r.status, 403);
  r = await b.call('/api/zkapi/relay', { method: 'POST', headers: auth, body: JSON.stringify({ url: 'http://zkapi-sepolia.openanonymity.ai/v0.4/health', method: 'GET' }) });
  assert.equal(r.status, 403);
  b.close();
});

test('serves the pinned zkAPI SDK assets with the right types and nothing outside them', async () => {
  const b = await boot();
  const wasm = await b.call('/zkapi/v2c/wasm/zkapi_browser_bg.wasm');
  assert.equal(wasm.status, 200);
  assert.equal(wasm.headers['content-type'], 'application/wasm');
  assert.notEqual((await b.call('/zkapi/v2c/../../src/secrets.ts')).status, 200);
  assert.notEqual((await b.call('/zkapi/v2c/%2e%2e/%2e%2e/package.json')).status, 200);
  b.close();
});

test('chat completions refused (409) when the profile is not ready; nothing forwarded', async () => {
  const b = await boot();
  let called = 0; b.rt.providerRequest = (async () => { called++; throw new Error('should not be called'); }) as any;
  const r = await b.call('/v1/chat/completions', { method: 'POST', headers: { authorization: `Bearer ${b.token}`, 'content-type': 'application/json' }, body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }) });
  assert.equal(r.status, 409);
  assert.equal(called, 0);
  b.close();
});

test('body size limit and content-type enforced', async () => {
  const b = await boot();
  const big = JSON.stringify({ text: 'x'.repeat(600 * 1024) });
  assert.equal((await b.call('/api/sessions', { method: 'POST', headers: { authorization: `Bearer ${b.token}`, 'content-type': 'application/json' }, body: big })).status, 413);
  assert.equal((await b.call('/api/sessions', { method: 'POST', headers: { authorization: `Bearer ${b.token}`, 'content-type': 'text/plain' }, body: '{}' })).status, 415);
  b.close();
});

test('payment endpoints never invent a balance: the wallet lives in the UI', async () => {
  const b = await boot();
  const r = await b.call('/api/payment/balance', { headers: { authorization: `Bearer ${b.token}` } });
  assert.equal(r.status, 501);
  assert.match(JSON.parse(r.body).error.message, /local UI/);
  b.close();
});

test('config API cannot point the sanitizer off-machine or the provider at another host', async () => {
  const b = await boot();
  const h = { authorization: `Bearer ${b.token}`, 'content-type': 'application/json' };
  // only model and strictness are accepted by the sanitizer config route
  await b.call('/api/privacy/sanitizer/config', { method: 'POST', headers: h, body: JSON.stringify({ baseUrl: 'https://evil.example/v1', model: 'x' }) });
  assert.equal(b.rt.cfg.sanitizer.baseUrl, 'http://127.0.0.1:9/v1');
  const r = await b.call('/api/privacy/cover-traffic/config', { method: 'POST', headers: h, body: JSON.stringify({ urls: ['http://169.254.169.254/latest'] }) });
  assert.equal(r.status, 400);
  b.close();
});

test('a link from the public site may open the chat page, nothing else cross-site', async () => {
  const b = await boot();
  const nav = { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' };
  const page = await b.call('/', { headers: nav });
  assert.equal(page.status, 200);
  assert.match(String(page.headers['content-security-policy']), /frame-ancestors 'none'/);
  // the same metadata cannot reach the API, a framed page, or a fetch of the page
  assert.equal((await b.call('/api/status', { headers: { ...nav, authorization: `Bearer ${b.token}` } })).status, 403);
  assert.equal((await b.call('/', { headers: { ...nav, 'sec-fetch-dest': 'iframe' } })).status, 403);
  assert.equal((await b.call('/', { headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty' } })).status, 403);
  assert.equal((await b.call('/', { method: 'POST', headers: nav })).status, 403);
  b.close();
});
