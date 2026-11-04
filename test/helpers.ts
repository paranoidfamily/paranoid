import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { Readable } from 'node:stream';
import { ConfigStore } from '../src/config.ts';
import { SecretStore } from '../src/secrets.ts';
import { Runtime } from '../src/runtime.ts';

export function tmpDir(): string { return fs.mkdtempSync(path.join(os.tmpdir(), 'paranoid-test-')); }

/** Secret store that never touches DPAPI or disk. */
export class MemSecrets extends SecretStore {
  mem = new Map<string, string>();
  has(n: string) { return this.mem.has(n); }
  get(n: string) { return this.mem.get(n) ?? null; }
  set(n: string, v: string) { this.mem.set(n, v); }
  delete(n: string) { this.mem.delete(n); }
}

/** Local OpenAI-compatible model server on loopback (the sanitizer backend). */
export async function fakeLocalModel(handler: (body: any) => any | Promise<any>, models = ['local-sanitizer']) {
  const seen: any[] = [];
  const srv = http.createServer(async (req, res) => {
    if (req.url?.endsWith('/models')) { res.setHeader('content-type', 'application/json'); return res.end(JSON.stringify({ data: models.map(id => ({ id })) })); }
    let s = ''; for await (const c of req) s += c;
    const body = JSON.parse(s); seen.push(body);
    const out = await handler(body);
    if (out === null) { res.statusCode = 500; return res.end('fail'); }
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ choices: [{ message: { content: typeof out === 'string' ? out : JSON.stringify(out) } }] }));
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
  const port = (srv.address() as net.AddressInfo).port;
  return { url: `http://127.0.0.1:${port}/v1`, seen, close: () => srv.close() };
}

/** Echoes the user text back, uppercased placeholders untouched: a deterministic "rewrite". */
export const isExtract = (body: any) => body.messages[0].content.includes('"entities"');
export const echoRewrite = (body: any) => isExtract(body) ? { entities: [] } : ({ texts: JSON.parse(body.messages[1].content).texts.map((t: string) => 'Task: ' + t) });

/** Records provider calls and answers with a fixed SSE stream. */
export function fakeProvider(reply = 'Hello [NAME_1], noted.') {
  const calls: any[] = [];
  const fn = async (_base: string, _hosts: string[], key: string, route: any, method: string, p: string, body: any) => {
    calls.push({ key, via: route.via, identity: route.agent?.identity, method, path: p, body });
    const chunks = [...reply.match(/.{1,4}/gs)!].map(t => `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: t } }] })}\n\n`);
    chunks.push(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: 'stop' }], usage: { prompt_tokens: 10, completion_tokens: 5 } })}\n\n`, 'data: [DONE]\n\n');
    const r: any = Readable.from((body?.stream ? chunks : [JSON.stringify({ choices: [{ index: 0, message: { role: 'assistant', content: reply } }] })]).map(s => Buffer.from(s)));
    r.statusCode = 200;
    return r;
  };
  return { calls, fn };
}

/** Provider answering a scripted sequence of turns; a turn may request tool calls. */
export function scriptedProvider(turns: { text?: string; tools?: { name: string; args: string }[] }[]) {
  const calls: any[] = [];
  let i = 0;
  const fn = async (_b: string, _h: string[], key: string, route: any, method: string, p: string, body: any) => {
    calls.push({ key, via: route.via, identity: route.agent?.identity, body: JSON.parse(JSON.stringify(body)) });
    const t = turns[Math.min(i++, turns.length - 1)];
    const ev: string[] = [];
    if (t.text) ev.push(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: t.text } }] })}\n\n`);
    (t.tools || []).forEach((c, n) => ev.push(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { tool_calls: [{ index: n, id: `call_${n}`, function: { name: c.name, arguments: c.args } }] } }] })}\n\n`));
    ev.push(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: t.tools ? 'tool_calls' : 'stop' }], usage: { prompt_tokens: 1, completion_tokens: 1 } })}\n\n`, 'data: [DONE]\n\n');
    const r: any = Readable.from(ev.map(s => Buffer.from(s)));
    r.statusCode = 200;
    return r;
  };
  return { calls, fn };
}

export async function makeRuntime(opts: { profile?: 'standard' | 'private' | 'paranoid'; sanitizerUrl?: string; torVerified?: boolean; key?: boolean } = {}) {
  const dir = tmpDir();
  const store = new ConfigStore(dir);
  store.update({ profile: opts.profile ?? 'private', provider: { model: 'test/model' }, sanitizer: { baseUrl: opts.sanitizerUrl ?? 'http://127.0.0.1:9/v1', model: 'local-sanitizer' } });
  const secrets = new MemSecrets(dir);
  if (opts.key !== false) secrets.set('openrouter', 'sk-or-test-0000000000000000000000');
  const rt = new Runtime(store, secrets);
  rt.tor.state.verified = !!opts.torVerified;
  rt.tor.state.running = !!opts.torVerified;
  // tests never depend on the host having bubblewrap/WSL
  rt.bwrapProbe = async () => ({ available: false, reason: 'not probed in tests' });
  return { rt, dir };
}
