// The privacy runtime: component status, privacy profiles and the request
// pipeline shared by the chat UI and the OpenAI-compatible endpoint.
// Rule: a profile either has every layer it requires, or nothing is sent.
import type { IncomingMessage } from 'node:http';
import { ConfigStore, loopbackAddr, type Config, type Profile } from './config.ts';
import { SecretStore } from './secrets.ts';
import { TorManager, TorAgent } from './tor.ts';
import { CoverEngine } from './cover.ts';
import { SessionManager, Session, digest } from './sessions.ts';
import { sanitize, applyRules, rehydrate, listLocalModels, SanitizerError } from './sanitizer.ts';
import { request as providerRequest, readJson, filterBody, ProviderError, providerMessage, type Route } from './provider.ts';
import { sandboxHealth, runJs, TOOLS, POLICY } from './sandbox.ts';
import { bwrapHealth, runShell, SHELL_TOOL, BWRAP_POLICY } from './bwrap.ts';
import { zkapiAssets, ZKAPI_INFERENCE_BASE } from './zkapi.ts';
import { log } from './log.ts';

/** A zkAPI lease obtained by the browser wallet for one request: an ephemeral provider key. Held in memory for that request only. */
export interface Lease { apiKey: string; baseUrl: string }

export class PolicyError extends Error {
  status = 409; code = 'privacy_policy'; missing: string[];
  constructor(message: string, missing: string[] = []) { super(message); this.missing = missing; }
}
export class InputError extends Error { status = 400; code = 'invalid_request'; }

export const PROFILE_REQUIREMENTS: Record<Profile, string[]> = {
  standard: ['provider'],
  private: ['provider', 'tor', 'sanitizer'],
  paranoid: ['provider', 'tor', 'sanitizer', 'payment_zkapi', 'cover_traffic', 'sandbox'],
};

export interface ComponentState { ready: boolean; detail: string }

/** Tool rounds per request before the model must answer without tools. */
const MAX_ROUNDS = 4;

export class Runtime {
  config: ConfigStore;
  secrets: SecretStore;
  tor: TorManager;
  cover: CoverEngine;
  sessions = new SessionManager();
  sanitizerCache: { at: number; models: string[] | null; error: string | null } = { at: 0, models: null, error: null };
  modelsCache: { at: number; via: string; data: any } | null = null;
  providerRequest = providerRequest; // injectable for tests

  constructor(config: ConfigStore, secrets: SecretStore) {
    this.config = config;
    this.secrets = secrets;
    const c = config.value;
    this.tor = new TorManager(loopbackAddr(c.tor.socks), c.tor.exe, config.dir);
    this.cover = new CoverEngine(c.cover, loopbackAddr(c.tor.socks));
    this.cover.onStop = reason => { if (reason === 'auto-stop') queueMicrotask(() => this.syncCover()); };
  }
  get cfg(): Config { return this.config.value; }

  // ------------------------------------------------------------ cover traffic follows the profile
  // Paranoid requires running cover traffic, so choosing it starts the engine and
  // keeps it running (a new budget window after each auto-stop) while the profile
  // is active; leaving the profile stops what the profile started. The hourly
  // request and byte budgets still apply, and a stop by the user is respected:
  // the profile then reports cover traffic as missing instead of restarting it.
  coverAuto = false;
  coverUserStopped = false;
  syncCover() {
    const want = this.cfg.profile === 'paranoid' && !this.coverUserStopped;
    if (want && !this.cover.running && this.tor.state.verified && this.cfg.cover.urls.length && this.cover.hasBudget()) {
      try { this.cover.start(true); this.coverAuto = true; log('cover.auto_start', { profile: this.cfg.profile }); } catch { /* reported by components() */ }
    } else if (this.cfg.profile !== 'paranoid' && this.cover.running && this.coverAuto) {
      this.cover.stop('profile changed'); this.coverAuto = false;
    }
  }

  // ------------------------------------------------------------ components
  async sanitizerState(force = false) {
    if (force || Date.now() - this.sanitizerCache.at > 15_000) {
      try { this.sanitizerCache = { at: Date.now(), models: await listLocalModels(this.cfg.sanitizer), error: null }; }
      catch { this.sanitizerCache = { at: Date.now(), models: null, error: 'local model server unavailable' }; }
    }
    const s = this.cfg.sanitizer, models = this.sanitizerCache.models;
    let ready = false, detail: string;
    if (s.strictness === 'minimal') detail = 'rules only (strictness minimal): no local model rewrite';
    else if (!models) detail = this.sanitizerCache.error!;
    else if (!s.model) detail = 'no local model selected';
    else if (!models.includes(s.model)) detail = `model ${s.model} not found on the local server`;
    else { ready = true; detail = `${s.model}, ${s.strictness}`; }
    return { ready, detail, serverUp: !!models, models: models || [], model: s.model, strictness: s.strictness };
  }

  paymentState() {
    const key = this.secrets.has('openrouter');
    const z = zkapiAssets();
    return {
      method: this.cfg.profile === 'paranoid' ? 'zkapi-lease' : key ? 'provider-api-key (or zkAPI lease when the wallet is connected)' : z.available ? 'zkapi-lease' : 'none',
      identityLinked: this.cfg.profile !== 'paranoid' && key,
      zkapi: {
        available: z.available,
        network: z.network,
        reason: z.available
          ? 'zkAPI browser wallet (official SDK) on Sepolia staging: development proving keys, test ETH only, the operator requires a testnet password. Wallet notes stay in the local UI\'s browser storage; protocol, indexer and RPC traffic goes through Tor.'
          : z.reason,
      },
    };
  }

  /** bubblewrap state: off when disabled in config; health is probed, never assumed. */
  async bubblewrapState(force = false) {
    if (!this.cfg.sandbox.bubblewrap) return { enabled: false, available: false, reason: 'disabled in settings' };
    return { enabled: true, ...(await this.bwrapProbe({ wslDistro: this.cfg.sandbox.wslDistro, force })) };
  }
  bwrapProbe: (o: { wslDistro?: string; force?: boolean }) => Promise<{ available: boolean; reason: string }> = o => bwrapHealth(o);
  runShell: (script: string) => Promise<any> = script => runShell(script, { wslDistro: this.cfg.sandbox.wslDistro });

  async sandboxState(force = false) {
    return { ...(await sandboxHealth()), policy: POLICY, bubblewrap: { ...(await this.bubblewrapState(force)), policy: BWRAP_POLICY } };
  }

  async components(force = false): Promise<Record<string, ComponentState>> {
    const san = await this.sanitizerState(force);
    const key = this.secrets.has('openrouter');
    const t = this.tor.state;
    const pay = this.paymentState();
    const sbx = await sandboxHealth();
    const canPay = this.cfg.profile === 'paranoid' ? pay.zkapi.available : key || pay.zkapi.available;
    return {
      provider: { ready: canPay && !!this.cfg.provider.model, detail: !this.cfg.provider.model ? 'no model selected' : !canPay ? (this.cfg.profile === 'paranoid' ? 'zkAPI client unavailable' : 'no OpenRouter API key stored and no zkAPI client') : this.cfg.provider.model },
      tor: { ready: t.verified, detail: t.verified ? 'connected, exit verified as Tor' : !t.installed && !t.running ? 'Tor not installed' : !t.running ? 'Tor not running' : t.error || 'not verified yet' },
      sanitizer: { ready: san.ready, detail: san.detail },
      cover_traffic: { ready: this.cover.running, detail: this.cover.running ? 'running' : this.cfg.cover.urls.length ? 'stopped' : 'no cover URLs configured' },
      payment_zkapi: { ready: pay.zkapi.available, detail: pay.zkapi.available ? 'client available; each request needs a lease from the connected wallet' : pay.zkapi.reason },
      sandbox: { ready: sbx.available, detail: sbx.reason },
    };
  }

  /** Picks the provider key for one request: a zkAPI lease, or the stored key outside paranoid mode. */
  keyFor(lease: Lease | undefined): { key: string; paidWith: 'zkapi-lease' | 'api-key' } {
    if (lease !== undefined) {
      if (!lease || typeof lease.apiKey !== 'string' || !/^[\w-]{20,300}$/.test(lease.apiKey)) throw new InputError('invalid zkAPI lease');
      if (String(lease.baseUrl).replace(/\/$/, '') !== ZKAPI_INFERENCE_BASE || this.cfg.provider.baseUrl.replace(/\/$/, '') !== ZKAPI_INFERENCE_BASE) {
        throw new PolicyError('the zkAPI lease is for a different inference endpoint than the configured provider');
      }
      return { key: lease.apiKey, paidWith: 'zkapi-lease' };
    }
    if (this.cfg.profile === 'paranoid') throw new PolicyError('paranoid mode pays only through a zkAPI lease: connect the wallet in Settings', ['payment_zkapi']);
    return { key: this.apiKey(), paidWith: 'api-key' };
  }

  async readiness(profile: Profile = this.cfg.profile, force = false) {
    const comps = await this.components(force);
    const missing = PROFILE_REQUIREMENTS[profile].filter(k => !comps[k].ready);
    return { profile, ready: missing.length === 0, missing, components: comps };
  }

  async requireReady() {
    const r = await this.readiness();
    if (!r.ready) throw new PolicyError(`${r.profile} mode unavailable: ${r.missing.map(m => `${m} (${r.components[m].detail})`).join('; ')}`, r.missing);
    return r;
  }

  route(session: Session | null): Route {
    if (this.cfg.profile === 'standard') return { agent: undefined, via: 'direct' };
    if (!this.tor.state.verified) throw new PolicyError('Tor routing required but not verified', ['tor']);
    return { agent: new TorAgent(loopbackAddr(this.cfg.tor.socks), session ? session.torIdentity : require_identity()), via: 'tor' };
  }

  apiKey(): string {
    const k = this.secrets.get('openrouter');
    if (!k) throw new PolicyError('no provider API key stored', ['provider']);
    return k;
  }

  // ------------------------------------------------------------ sanitization
  sanitizerRequired() { return this.cfg.profile !== 'standard'; }

  async preview(session: Session, text: string) {
    if (typeof text !== 'string' || !text.trim()) throw new InputError('text is required');
    if (text.length > 128 * 1024) throw new InputError('text too long');
    const san = await this.sanitizerState();
    const strictness = san.ready ? this.cfg.sanitizer.strictness : 'minimal';
    if (!san.ready && this.sanitizerRequired()) throw new PolicyError(`local sanitizer unavailable: ${san.detail}`, ['sanitizer']);
    const r = await sanitize(text, session.placeholders, strictness, this.cfg.sanitizer);
    const id = digest([session.id, Date.now(), Math.random()]).slice(0, 24);
    session.previews.set(id, { text: r.text, createdAt: Date.now(), digest: digest(text) });
    if (session.previews.size > 8) session.previews.delete(session.previews.keys().next().value!);
    log('sanitize.preview', { rewritten: r.rewritten, rulesHits: r.rulesHits, entities: r.entities, strictness: r.strictness });
    // every value withheld from this prompt, whether the rewrite kept its placeholder or dropped it
    return { previewId: id, sanitized: r.text, rewritten: r.rewritten, rulesHits: r.rulesHits, entities: r.entities, strictness: r.strictness, placeholders: r.replaced, sanitizerReady: san.ready };
  }

  // ------------------------------------------------------------ UI chat
  /** Sends an approved preview. `edited` (optional) replaces the sanitized text; rules are re-applied to it. `bypass` (standard mode only) sends the original. */
  async send(session: Session, opts: { previewId?: string; edited?: string; bypassText?: string; lease?: Lease; agent?: boolean },
    onDelta: (t: string) => void, onTool: (e: { name: string; code: string; ok: boolean; output: string }) => void = () => {}): Promise<{ usage: any; via: string; sanitization: 'sanitized' | 'bypassed'; paidWith: string; toolRuns: number }> {
    await this.requireReady();
    const pay = this.keyFor(opts.lease);
    const agent = !!opts.agent;
    if (agent && !(await sandboxHealth()).available) throw new PolicyError('the agent sandbox is unavailable', ['sandbox']);
    // run_shell is offered only while bubblewrap passes its isolation probe
    const shell = agent && (await this.bubblewrapState()).available;
    const tools = shell ? [...TOOLS, SHELL_TOOL] : TOOLS;
    if (session.busy) throw new InputError('a request is already running in this conversation');
    let text: string, sanitization: 'sanitized' | 'bypassed';
    if (opts.bypassText !== undefined) {
      if (this.cfg.profile !== 'standard') throw new PolicyError('sending an unsanitized prompt is only possible in standard mode');
      if (typeof opts.bypassText !== 'string' || !opts.bypassText.trim()) throw new InputError('text is required');
      text = opts.bypassText; sanitization = 'bypassed';
    } else {
      const p = opts.previewId ? session.previews.get(opts.previewId) : undefined;
      if (!p) throw new InputError('unknown or expired preview: sanitize the prompt first');
      session.previews.delete(opts.previewId!);
      text = typeof opts.edited === 'string' && opts.edited.trim() ? applyRules(opts.edited, session.placeholders).text : p.text;
      sanitization = 'sanitized';
    }
    const route = this.route(session);
    const messages: any[] = [...session.history, { role: 'user', content: text }];
    const ac = new AbortController();
    session.busy = ac;
    const usage = { prompt_tokens: 0, completion_tokens: 0 };
    let toolRuns = 0;
    try {
      // Agent loop: tool calls run only inside a sandbox (QuickJS/WASM, or bubblewrap for run_shell), at most MAX_ROUNDS times.
      for (let round = 0; ; round++) {
        const body = filterBody({ model: this.cfg.provider.model, messages, stream: true });
        if (agent) { body.tools = tools; body.tool_choice = round < MAX_ROUNDS ? 'auto' : 'none'; }
        const res = await this.providerRequest(this.cfg.provider.baseUrl, this.cfg.provider.allowedHosts, pay.key, route, 'POST', '/chat/completions', body, ac.signal);
        if (res.statusCode !== 200) {
          const j = await readJson(res).catch(() => null);
          throw new ProviderError(providerMessage(j, res.statusCode), res.statusCode === 401 || res.statusCode === 402 ? res.statusCode : 502);
        }
        let raw = '';
        const calls = new Map<number, { id: string; name: string; args: string }>();
        const re = new Rehydrator(session.placeholders);
        await readSSE(res, obj => {
          const delta = obj.choices?.[0]?.delta;
          if (typeof delta?.content === 'string' && delta.content) { raw += delta.content; const out = re.push(delta.content); if (out) onDelta(out); }
          for (const tc of delta?.tool_calls || []) {
            const c = calls.get(tc.index ?? 0) || { id: '', name: '', args: '' };
            if (tc.id) c.id = tc.id;
            if (tc.function?.name) c.name += tc.function.name;
            if (tc.function?.arguments) c.args += tc.function.arguments;
            calls.set(tc.index ?? 0, c);
          }
          if (obj.usage) { usage.prompt_tokens += obj.usage.prompt_tokens || 0; usage.completion_tokens += obj.usage.completion_tokens || 0; }
        });
        const tail = re.flush(); if (tail) onDelta(tail);
        if (!agent || !calls.size || round >= MAX_ROUNDS) {
          messages.push({ role: 'assistant', content: raw });
          break;
        }
        const list = [...calls.values()].map((c, i) => ({ ...c, id: c.id || `call_${round}_${i}` }));
        messages.push({ role: 'assistant', content: raw || null, tool_calls: list.map(c => ({ id: c.id, type: 'function', function: { name: c.name, arguments: c.args } })) });
        for (const c of list) {
          let code: any = '', result: any;
          const field = c.name === 'run_shell' ? 'script' : 'code';
          try { code = JSON.parse(c.args || '{}')[field]; } catch { /* reported below */ }
          if (c.name !== 'run_js' && !(c.name === 'run_shell' && shell)) result = { ok: false, error: `unknown tool ${c.name}` };
          else if (typeof code !== 'string') result = { ok: false, error: `arguments must be {"${field}": string}` };
          else if (c.name === 'run_shell') {
            // re-probe right before running: never run when isolation is not proven
            const h = await this.bubblewrapState();
            result = h.available ? await this.runShell(code) : { ok: false, error: 'bubblewrap sandbox unavailable' };
            if (h.available) toolRuns++;
          }
          else { result = await runJs(code); toolRuns++; }
          const output = result.ok || result.output ? (result.output || '') + (result.value !== null && result.value !== undefined ? `=> ${result.value}` : '') + (result.ok ? '' : `\nerror: ${result.error}`) : `error: ${result.error}`;
          onTool({ name: c.name, code: rehydrate(code || c.args, session.placeholders), ok: !!result.ok, output: rehydrate(output, session.placeholders) });
          // tool output goes back to the provider: mask anything that matches a withheld value
          messages.push({ role: 'tool', tool_call_id: c.id, content: applyRules(JSON.stringify({ ok: result.ok, output: result.output ?? '', value: result.value ?? null, error: result.error ?? null, ...(result.exitCode !== undefined ? { exitCode: result.exitCode } : {}) }), session.placeholders).text });
        }
      }
      session.history = messages;
      session.requests++; session.routedVia = route.via;
      log('chat.done', { via: route.via, sanitization, paidWith: pay.paidWith, toolRuns, promptTokens: usage.prompt_tokens, completionTokens: usage.completion_tokens });
      return { usage, via: route.via, sanitization, paidWith: pay.paidWith, toolRuns };
    } finally { session.busy = null; }
  }

  // ------------------------------------------------------------ OpenAI-compatible endpoint
  async completions(body: any, sessionHeader: string | undefined, res: { head: (status: number, headers: Record<string, string>) => void; write: (s: string) => void; end: (s?: string) => void }, signal: AbortSignal) {
    await this.requireReady();
    if (!body || !Array.isArray(body.messages) || !body.messages.length) throw new InputError('messages must be a non-empty array');
    if (body.messages.length > 500) throw new InputError('too many messages');
    // client-side tools would run outside the sandbox; agent tools exist only in the chat UI
    if (body.tools || body.functions) throw new InputError('client tool calling is refused: tools run only in the daemon\'s sandboxed agent (chat UI)');
    const pay = this.keyFor(undefined); // no browser wallet here: paranoid mode is refused for /v1
    const msgs = body.messages.map((m: any) => {
      if (!m || !['system', 'user', 'assistant'].includes(m.role)) throw new InputError('only system, user and assistant messages are supported');
      let content = m.content;
      if (Array.isArray(content)) {
        if (!content.every((p: any) => p?.type === 'text' && typeof p.text === 'string')) throw new InputError('only text content parts are supported');
        content = content.map((p: any) => p.text).join('\n');
      }
      if (typeof content !== 'string') throw new InputError('message content must be text');
      return { role: m.role, content };
    });
    const digests = msgs.map((m: any) => digest(m));
    let session = sessionHeader ? this.sessions.get(sessionHeader) : this.sessions.matchPrefix(digests);
    if (sessionHeader && !session) throw new InputError('unknown conversation id');
    if (!session) session = this.sessions.create();
    if (session.busy) throw new InputError('a request is already running in this conversation');

    const san = await this.sanitizerState();
    const strictness = san.ready ? this.cfg.sanitizer.strictness : 'minimal';
    if (!san.ready && this.sanitizerRequired()) throw new PolicyError(`local sanitizer unavailable: ${san.detail}`, ['sanitizer']);
    const out: { role: string; content: string }[] = [];
    let sanitized = 0;
    for (const m of msgs) {
      if (m.role === 'user') {
        const key = digest(m.content);
        let s = session.sanitizedByDigest.get(key);
        if (s === undefined) { s = (await sanitize(m.content, session.placeholders, strictness, this.cfg.sanitizer)).text; session.sanitizedByDigest.set(key, s); sanitized++; }
        out.push({ role: 'user', content: s });
      } else {
        // replies were rehydrated locally: mask known values again before they go back out
        out.push({ role: m.role, content: applyRules(m.content, session.placeholders).text });
      }
    }
    session.digests = digests;
    const route = this.route(session);
    const stream = !!body.stream;
    const ac = new AbortController();
    signal.addEventListener('abort', () => ac.abort());
    session.busy = ac;
    try {
      const upstream = await this.providerRequest(this.cfg.provider.baseUrl, this.cfg.provider.allowedHosts, pay.key, route, 'POST', '/chat/completions',
        filterBody({ ...body, messages: out, model: body.model && body.model !== 'paranoid' ? body.model : this.cfg.provider.model }), ac.signal);
      const headers = { 'x-paranoid-conversation': session.id, 'x-paranoid-route': route.via, 'x-paranoid-sanitization': strictness === 'minimal' && !this.sanitizerRequired() ? 'rules-only' : 'sanitized' };
      if (upstream.statusCode !== 200) {
        const j = await readJson(upstream).catch(() => null);
        res.head(upstream.statusCode === 401 || upstream.statusCode === 402 || upstream.statusCode === 429 ? upstream.statusCode : 502, { 'content-type': 'application/json', ...headers });
        res.end(JSON.stringify({ error: { message: providerMessage(j, upstream.statusCode), type: 'provider_error' } }));
        return;
      }
      session.requests++; session.routedVia = route.via;
      if (!stream) {
        const j = await readJson(upstream);
        for (const c of j.choices || []) if (typeof c.message?.content === 'string') c.message.content = rehydrate(c.message.content, session.placeholders);
        res.head(200, { 'content-type': 'application/json', ...headers });
        res.end(JSON.stringify(j));
      } else {
        res.head(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', ...headers });
        const re = new Map<number, Rehydrator>();
        await readSSE(upstream, obj => {
          for (const c of obj.choices || []) {
            if (typeof c.delta?.content === 'string') {
              if (!re.has(c.index ?? 0)) re.set(c.index ?? 0, new Rehydrator(session!.placeholders));
              const r = re.get(c.index ?? 0)!;
              c.delta.content = c.finish_reason ? r.push(c.delta.content) + r.flush() : r.push(c.delta.content);
            } else if (c.finish_reason && re.has(c.index ?? 0)) {
              c.delta = { ...(c.delta || {}), content: re.get(c.index ?? 0)!.flush() };
            }
          }
          res.write(`data: ${JSON.stringify(obj)}\n\n`);
        });
        res.end('data: [DONE]\n\n');
      }
      log('v1.done', { via: route.via, stream, sanitizedTurns: sanitized });
    } finally { session.busy = null; }
  }

  async models() {
    const via = this.cfg.profile === 'standard' ? 'direct' : 'tor';
    if (this.modelsCache && this.modelsCache.via === via && Date.now() - this.modelsCache.at < 10 * 60_000) return this.modelsCache.data;
    if (via === 'tor' && !this.tor.state.verified) throw new PolicyError('Tor routing required but not verified', ['tor']);
    const res = await this.providerRequest(this.cfg.provider.baseUrl, this.cfg.provider.allowedHosts, this.secrets.get('openrouter') || '', this.route(null), 'GET', '/models', undefined);
    const j = await readJson(res, 32 * 1024 * 1024);
    if (res.statusCode !== 200) throw new ProviderError(`provider returned ${res.statusCode}`);
    const data = { object: 'list', data: (j.data || []).map((m: any) => ({ id: m.id, object: 'model', owned_by: String(m.id).split('/')[0], context_length: m.context_length, pricing: m.pricing ? { prompt: m.pricing.prompt, completion: m.pricing.completion } : undefined })) };
    this.modelsCache = { at: Date.now(), via, data };
    return data;
  }
}

function require_identity(): string {
  // requests outside a conversation (model listing) get a single-use identity
  return digest([Date.now(), Math.random(), process.pid]);
}

/** Holds back a possible partial placeholder ("[EMA") until it can be resolved. */
export class Rehydrator {
  map: Record<string, string>;
  buf = '';
  constructor(map: Record<string, string>) { this.map = map; }
  push(s: string): string {
    this.buf += s;
    const open = this.buf.lastIndexOf('[');
    let keep = '';
    if (open >= 0 && !this.buf.slice(open).includes(']') && this.buf.length - open < 24) { keep = this.buf.slice(open); this.buf = this.buf.slice(0, open); }
    const out = rehydrate(this.buf, this.map);
    this.buf = keep;
    return out;
  }
  flush(): string { const out = rehydrate(this.buf, this.map); this.buf = ''; return out; }
}

export async function readSSE(res: IncomingMessage, onEvent: (obj: any) => void) {
  let buf = '';
  res.setEncoding('utf8');
  for await (const chunk of res as AsyncIterable<string>) {
    buf += chunk;
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, '');
      buf = buf.slice(i + 1);
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim();
      if (!data || data === '[DONE]') continue;
      let obj: any;
      try { obj = JSON.parse(data); } catch { continue; }
      if (obj.error) throw new ProviderError(`provider: ${String(obj.error.message || 'stream error').slice(0, 200)}`);
      onEvent(obj);
    }
  }
}
