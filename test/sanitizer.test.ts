import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyRules, rehydrate, sanitize, SanitizerError } from '../src/sanitizer.ts';
import { fakeLocalModel, echoRewrite, isExtract } from './helpers.ts';
import { Rehydrator } from '../src/runtime.ts';

const SAMPLE = "Hi, I'm Claire Martin (claire.martin@protonmail.com, +33 6 12 34 56 78). Dispute a charge on card 4111 1111 1111 1111, refund to FR76 3000 6000 0112 3456 7890 189. Wallet 0x8f3c2a91b7e04d6f5a1c9e2b3d4f6a7b8c9d0e1f, key sk-or-v1-abcdefghijklmnopqrstuvwxyz0123, server 192.168.1.20. Claire needs it today.";

test('rules replace identifiers with stable placeholders', () => {
  const map = {};
  const r = applyRules(SAMPLE, map);
  for (const v of ['Claire', 'Martin', 'claire.martin@protonmail.com', '4111 1111 1111 1111', 'FR76', '0x8f3c', 'sk-or-v1', '192.168.1.20', '+33 6 12']) assert.ok(!r.text.includes(v), `leaked ${v}`);
  assert.match(r.text, /\[NAME_1\].*\[EMAIL_1\].*\[PHONE_1\].*\[CARD_1\].*\[IBAN_1\].*\[WALLET_1\].*\[SECRET_1\].*\[IP_1\]/s);
  // same values keep the same placeholder in a later turn
  const again = applyRules('Mail claire.martin@protonmail.com again', map);
  assert.equal(again.text, 'Mail [EMAIL_1] again');
  assert.equal(rehydrate('Dear [NAME_1], see [EMAIL_1]', map), 'Dear Claire Martin, see claire.martin@protonmail.com');
});

test('non-Luhn digit runs and ordinary numbers are left alone', () => {
  const r = applyRules('Order 1234 5678 9012 3456 cost 240 EUR in 2026', {});
  assert.equal(r.hits, 0);
});

test('local model rewrite: code blocks verbatim, placeholders kept, reintroduced identifiers re-masked', async () => {
  const m = await fakeLocalModel(body => {
    if (isExtract(body)) return { entities: [] };
    const [t] = JSON.parse(body.messages[1].content).texts;
    // a misbehaving model drops a code placeholder and leaks an email
    return { texts: [t.replace('[CODE_1]', '') + ' Contact bob@example.org.'] };
  });
  const code = '```js\nconst x = 1; // keep\n```';
  const r = await sanitize(`Fix this for me:\n${code}`, {}, 'standard', { baseUrl: m.url, model: 'local-sanitizer', timeoutMs: 5000 });
  m.close();
  assert.ok(r.rewritten);
  assert.ok(r.text.includes(code), 'code block restored verbatim');
  assert.ok(!r.text.includes('bob@example.org'), 'email re-masked');
  // the model must never see the raw identifiers either
  assert.ok(!JSON.stringify(m.seen).includes('claire'));
});

test('people and organizations listed by the local model are masked before the rewrite, even if the rewrite would keep them', async () => {
  const m = await fakeLocalModel(body => {
    if (isExtract(body)) return { entities: [{ text: 'Paul Durand', type: 'PERSON' }, { text: 'Renault', type: 'ORG' }, { text: 'not in text', type: 'ORG' }, { text: 'Lyon', type: 'PLACE' }] };
    return { texts: JSON.parse(body.messages[1].content).texts }; // a rewrite that changes nothing
  });
  const map = {};
  const r = await sanitize('My manager Paul Durand at Renault in Lyon rejects my leave. Paul says no.', map, 'standard', { baseUrl: m.url, model: 'local-sanitizer', timeoutMs: 5000 });
  m.close();
  assert.ok(!r.text.includes('Paul') && !r.text.includes('Renault'), r.text);
  assert.ok(r.text.includes('Lyon'), 'PLACE is only masked in strict mode');
  assert.equal(r.replaced['[PERSON_1]'], 'Paul Durand');
  assert.equal(r.replaced['[ORG_1]'], 'Renault');
  assert.equal(rehydrate('Write to [PERSON_1] at [ORG_1]', map), 'Write to Paul Durand at Renault');
  // the rewrite request itself only saw placeholders
  const rewriteReq = m.seen.find(b => !isExtract(b));
  assert.ok(!JSON.stringify(rewriteReq).includes('Durand'));
});

test('raw identifiers never reach the local model (rules run first)', async () => {
  const m = await fakeLocalModel(echoRewrite);
  await sanitize(SAMPLE, {}, 'standard', { baseUrl: m.url, model: 'local-sanitizer', timeoutMs: 5000 });
  m.close();
  const sent = JSON.stringify(m.seen);
  for (const v of ['protonmail', '4111 1111', 'FR76', 'sk-or-v1']) assert.ok(!sent.includes(v));
});

for (const [name, reply] of [['server error', null], ['invalid JSON', 'not json'], ['wrong count', { texts: ['a', 'b'] }], ['empty text', { texts: [' '] }]] as const) {
  test(`fails closed on ${name}`, async () => {
    const m = await fakeLocalModel(() => reply);
    await assert.rejects(sanitize('Write a poem about my cat Felix', {}, 'standard', { baseUrl: m.url, model: 'local-sanitizer', timeoutMs: 5000 }), SanitizerError);
    m.close();
  });
}

test('fails closed when no local model server is running', async () => {
  await assert.rejects(sanitize('hello there', {}, 'standard', { baseUrl: 'http://127.0.0.1:9/v1', model: 'x', timeoutMs: 2000 }), SanitizerError);
});

test('streaming rehydration handles placeholders split across chunks', () => {
  const r = new Rehydrator({ '[EMAIL_1]': 'a@b.co' });
  const out = ['Write to [EM', 'AIL_', '1] now [', 'x'].map(c => r.push(c)).join('') + r.flush();
  assert.equal(out, 'Write to a@b.co now [x');
});
