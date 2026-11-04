// Privacy regression tests: every required layer missing => nothing sent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeRuntime, fakeLocalModel, fakeProvider, scriptedProvider, echoRewrite } from './helpers.ts';
import { PolicyError } from '../src/runtime.ts';
import { sink } from '../src/log.ts';

const PROMPT = "I'm Claire Martin, claire.martin@protonmail.com. Summarize my contract.";

test('private mode: sanitizer down => preview refused, provider never called', async () => {
  const { rt } = await makeRuntime({ profile: 'private', torVerified: true });
  const p = fakeProvider(); rt.providerRequest = p.fn as any;
  const s = rt.sessions.create();
  await assert.rejects(rt.preview(s, PROMPT), PolicyError);
  await assert.rejects(rt.send(s, { previewId: 'nope' }, () => {}), PolicyError);
  assert.equal(p.calls.length, 0);
});

test('private mode: Tor not verified => refused, provider never called', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: false });
  const p = fakeProvider(); rt.providerRequest = p.fn as any;
  const s = rt.sessions.create();
  const pv = await rt.preview(s, PROMPT);
  await assert.rejects(rt.send(s, { previewId: pv.previewId }, () => {}), PolicyError);
  assert.equal(p.calls.length, 0);
  m.close();
});

test('private mode: provider receives only sanitized text, over Tor, with the conversation identity; reply rehydrated locally', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
  const p = fakeProvider('Hello [NAME_1], noted.'); rt.providerRequest = p.fn as any;
  const logs: string[] = []; const orig = sink.write; sink.write = l => { logs.push(l); };
  try {
    const a = rt.sessions.create(), b = rt.sessions.create();
    let out = '';
    const pv = await rt.preview(a, PROMPT);
    await rt.send(a, { previewId: pv.previewId }, t => { out += t; });
    const pv2 = await rt.preview(b, 'Another question about taxes');
    await rt.send(b, { previewId: pv2.previewId }, () => {});
    const sent = JSON.stringify(p.calls[0].body);
    assert.ok(!sent.includes('Claire') && !sent.includes('protonmail'), 'raw identifiers reached the provider');
    assert.equal(p.calls[0].via, 'tor');
    assert.equal(p.calls[0].identity, a.torIdentity);
    assert.notEqual(p.calls[1].identity, p.calls[0].identity, 'conversations share a circuit identity');
    assert.equal(out, 'Hello Claire Martin, noted.');
    // logs carry no content, identifiers or keys
    const all = logs.join('\n');
    for (const v of ['Claire', 'protonmail', 'contract', 'sk-or-test', a.torIdentity, 'Hello']) assert.ok(!all.includes(v), `log leaked ${v}`);
  } finally { sink.write = orig; m.close(); }
});

test('unsanitized bypass is refused outside standard mode', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
  const p = fakeProvider(); rt.providerRequest = p.fn as any;
  await assert.rejects(rt.send(rt.sessions.create(), { bypassText: PROMPT }, () => {}), PolicyError);
  assert.equal(p.calls.length, 0);
  m.close();
});

test('standard mode: direct route, explicit bypass allowed and recorded', async () => {
  const { rt } = await makeRuntime({ profile: 'standard' });
  const p = fakeProvider('ok'); rt.providerRequest = p.fn as any;
  const r = await rt.send(rt.sessions.create(), { bypassText: 'plain question' }, () => {});
  assert.equal(r.sanitization, 'bypassed');
  assert.equal(p.calls[0].via, 'direct');
});

test('paranoid mode refuses to start while cover traffic is stopped', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'paranoid', sanitizerUrl: m.url, torVerified: true });
  const p = fakeProvider(); rt.providerRequest = p.fn as any;
  const r = await rt.readiness();
  assert.equal(r.ready, false);
  assert.deepEqual(r.missing, ['cover_traffic']);
  assert.equal(r.components.sandbox.ready, true);
  assert.equal(r.components.payment_zkapi.ready, true);
  await assert.rejects(rt.send(rt.sessions.create(), { previewId: 'x' }, () => {}), PolicyError);
  assert.equal(p.calls.length, 0);
  m.close();
});

const LEASE = { apiKey: 'sk-or-v1-lease000000000000000000000000', baseUrl: 'https://openrouter.ai/api/v1' };

test('paranoid mode pays only with a zkAPI lease: the stored key is never used, a foreign lease endpoint is refused', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'paranoid', sanitizerUrl: m.url, torVerified: true });
  rt.cover.running = true; // readiness only; no traffic in tests
  const p = fakeProvider('ok'); rt.providerRequest = p.fn as any;
  const s = rt.sessions.create();
  let pv = await rt.preview(s, 'Explain Groth16');
  await assert.rejects(rt.send(s, { previewId: pv.previewId }, () => {}), /zkAPI lease/);
  pv = await rt.preview(s, 'Explain Groth16');
  await assert.rejects(rt.send(s, { previewId: pv.previewId, lease: { ...LEASE, baseUrl: 'https://evil.example/api/v1' } }, () => {}), PolicyError);
  pv = await rt.preview(s, 'Explain Groth16');
  const r = await rt.send(s, { previewId: pv.previewId, lease: LEASE }, () => {});
  assert.equal(r.paidWith, 'zkapi-lease');
  assert.equal(p.calls.length, 1);
  assert.equal(p.calls[0].key, LEASE.apiKey);
  assert.notEqual(p.calls[0].key, 'sk-or-test-0000000000000000000000');
  rt.cover.running = false;
  m.close();
});

test('agent loop: tool calls run in the sandbox, results go back to the model, withheld values stay masked', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
  const p = scriptedProvider([
    { tools: [{ name: 'run_js', args: JSON.stringify({ code: 'console.log(6*7)' }) }] },
    { tools: [{ name: 'run_js', args: JSON.stringify({ code: 'console.log(typeof fetch, typeof require, typeof process)' }) }, { name: 'rm_rf', args: '{}' }] },
    { text: 'The answer is 42.' },
  ]);
  rt.providerRequest = p.fn as any;
  const s = rt.sessions.create();
  const pv = await rt.preview(s, 'What is six times seven? Ask claire.martin@protonmail.com if unsure.');
  const tools: any[] = []; let out = '';
  const r = await rt.send(s, { previewId: pv.previewId, agent: true }, t => { out += t; }, e => tools.push(e));
  assert.equal(out, 'The answer is 42.');
  assert.equal(r.toolRuns, 2);
  assert.equal(tools[0].output.trim(), '42');
  assert.equal(tools[1].output.trim(), 'undefined undefined undefined', 'sandbox exposes network or host APIs');
  assert.equal(tools[2].ok, false, 'unknown tool executed');
  assert.ok(p.calls[0].body.tools?.[0]?.function?.name === 'run_js');
  const third = p.calls[2].body.messages;
  assert.ok(third.some((x: any) => x.role === 'tool' && x.content.includes('42')));
  assert.ok(!JSON.stringify(p.calls).includes('protonmail'), 'withheld value reached the provider');
  m.close();
});

test('agent mode is never enabled implicitly', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
  const p = scriptedProvider([{ tools: [{ name: 'run_js', args: '{"code":"1"}' }] }]);
  rt.providerRequest = p.fn as any;
  const s = rt.sessions.create();
  const pv = await rt.preview(s, 'hi');
  const r = await rt.send(s, { previewId: pv.previewId }, () => {});
  assert.equal(r.toolRuns, 0);
  assert.equal(p.calls[0].body.tools, undefined);
  m.close();
});

test('OpenAI-compatible endpoint: history re-masked, prefix continuity keeps the circuit, new transcript gets a new one', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
  const p = fakeProvider('Sure, Claire Martin.'); rt.providerRequest = p.fn as any;
  const sink2 = () => { let body = ''; return { head: () => {}, write: (s: string) => { body += s; }, end: (s?: string) => { body += s ?? ''; }, get body() { return body; } }; };
  const t1 = [{ role: 'user', content: PROMPT }];
  const r1 = sink2(); await rt.completions({ messages: t1 }, undefined, r1, new AbortController().signal);
  const reply = JSON.parse(r1.body).choices[0].message.content;
  assert.equal(reply, 'Sure, Claire Martin.'); // provider answered with a raw name; returned as-is to the local client
  const t2 = [...t1, { role: 'assistant', content: reply }, { role: 'user', content: 'Shorter please' }];
  await rt.completions({ messages: t2 }, undefined, sink2(), new AbortController().signal);
  await rt.completions({ messages: [{ role: 'user', content: 'Unrelated' }] }, undefined, sink2(), new AbortController().signal);
  assert.equal(p.calls[1].identity, p.calls[0].identity, 'continuation changed circuit');
  assert.notEqual(p.calls[2].identity, p.calls[0].identity, 'new conversation reused a circuit');
  const second = JSON.stringify(p.calls[1].body.messages);
  assert.ok(!second.includes('Claire'), 'history leaked an identifier');
  m.close();
});

test('tool calls are refused (no sandboxed agent runtime)', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
  await assert.rejects(rt.completions({ messages: [{ role: 'user', content: 'hi' }], tools: [{}] }, undefined, { head() {}, write() {}, end() {} }, new AbortController().signal), /tool calling/);
  m.close();
});

test('cover traffic requires verified Tor and configured URLs; budgets stop it', async () => {
  const { rt } = await makeRuntime({ profile: 'private' });
  assert.throws(() => rt.cover.start(false), /verified Tor/);
  assert.throws(() => rt.cover.start(true), /no cover URLs/);
  rt.config.update({ cover: { urls: ['https://example.org/'], maxRequestsPerHour: 1 } });
  rt.cover.configure(rt.cfg.cover);
  rt.cover.window.push({ t: Date.now(), bytes: 10 });
  rt.cover.start(true);
  (rt.cover as any).fire();
  assert.equal(rt.cover.running, false);
  assert.equal(rt.cover.stopReason, 'request budget reached');
  assert.equal(rt.cover.status().policy.inferenceSpendUsd, 0);
});

test('paranoid profile keeps cover traffic running; leaving it stops it; a user stop is respected', async () => {
  const { rt } = await makeRuntime({ profile: 'paranoid', torVerified: true });
  rt.config.update({ cover: { urls: ['https://example.org/'] } });
  rt.cover.configure(rt.cfg.cover);
  const starts: number[] = [];
  rt.cover.start = function (this: any) { this.running = true; starts.push(Date.now()); } as any; // no real traffic in tests
  rt.syncCover();
  assert.equal(rt.cover.running, true, 'paranoid did not start cover traffic');
  // auto-stop at the end of a window: restarted while paranoid is active
  rt.cover.stop('auto-stop');
  await new Promise(r => setImmediate(r));
  assert.equal(rt.cover.running, true, 'cover traffic not renewed after auto-stop');
  assert.equal(starts.length, 2);
  // exhausted hourly budget: not restarted until the window frees
  rt.cover.stop('request budget reached');
  for (let i = 0; i < rt.cfg.cover.maxRequestsPerHour; i++) rt.cover.window.push({ t: Date.now(), bytes: 1 });
  rt.syncCover();
  assert.equal(rt.cover.running, false, 'budget ignored');
  rt.cover.window = [];
  rt.syncCover();
  assert.equal(rt.cover.running, true);
  // a stop by the user is not overridden
  rt.coverUserStopped = true; rt.cover.stop('stopped by user');
  rt.syncCover();
  assert.equal(rt.cover.running, false, 'user stop overridden');
  assert.ok((await rt.readiness('paranoid')).missing.includes('cover_traffic'));
  // leaving paranoid stops what the profile started
  rt.coverUserStopped = false; rt.syncCover();
  rt.config.update({ profile: 'private' }); rt.syncCover();
  assert.equal(rt.cover.running, false, 'cover traffic left running after leaving paranoid');
  // no Tor: never started
  rt.config.update({ profile: 'paranoid' }); rt.tor.state.verified = false; rt.syncCover();
  assert.equal(rt.cover.running, false);
});
