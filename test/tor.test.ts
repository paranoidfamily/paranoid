import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { socksConnect, TorError, newIdentity } from '../src/tor.ts';

/** Minimal SOCKS5 server recording what the client offered. `mode` controls its answers. */
async function fakeSocks(mode: 'ok' | 'noauth-only' | 'reject-auth' | 'connect-fail') {
  const seen: { methods: number[]; user: string; atyp: number; host: string; port: number }[] = [];
  const srv = net.createServer(sock => {
    let buf = Buffer.alloc(0), stage = 0;
    const rec: any = {};
    sock.on('data', d => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2 && buf.length >= 2 + buf[1]) {
        rec.methods = [...buf.subarray(2, 2 + buf[1])];
        buf = buf.subarray(2 + buf[1]);
        stage = 1;
        sock.write(Buffer.from([5, mode === 'noauth-only' ? 0xff : 2]));
        if (mode === 'noauth-only') return sock.end();
      }
      if (stage === 1 && buf.length >= 2 && buf.length >= 3 + buf[1]) {
        const ul = buf[1]; rec.user = buf.subarray(2, 2 + ul).toString();
        const pl = buf[2 + ul]; buf = buf.subarray(3 + ul + pl);
        stage = 2;
        sock.write(Buffer.from([1, mode === 'reject-auth' ? 1 : 0]));
        if (mode === 'reject-auth') return sock.end();
      }
      if (stage === 2 && buf.length >= 5) {
        rec.atyp = buf[3];
        const len = buf[4];
        rec.host = buf.subarray(5, 5 + len).toString();
        rec.port = buf.readUInt16BE(5 + len);
        seen.push(rec);
        stage = 3;
        sock.write(Buffer.from([5, mode === 'connect-fail' ? 5 : 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        if (mode === 'connect-fail') sock.end();
      }
    });
    sock.on('error', () => {});
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
  return { srv, seen, proxy: { host: '127.0.0.1', port: (srv.address() as net.AddressInfo).port } };
}

test('offers only username/password auth, sends the isolation identity and the hostname (remote DNS)', async () => {
  const f = await fakeSocks('ok');
  const id = newIdentity();
  const s = await socksConnect(f.proxy, 'openrouter.ai', 443, id);
  s.destroy(); f.srv.close();
  assert.deepEqual(f.seen[0].methods, [2]);
  assert.equal(f.seen[0].user, id);
  assert.equal(f.seen[0].atyp, 3);
  assert.equal(f.seen[0].host, 'openrouter.ai');
  assert.equal(f.seen[0].port, 443);
});

test('identities are distinct per conversation', () => {
  const a = newIdentity(), b = newIdentity();
  assert.notEqual(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

for (const mode of ['noauth-only', 'reject-auth', 'connect-fail'] as const) {
  test(`fails closed when the proxy answers ${mode}`, async () => {
    const f = await fakeSocks(mode);
    await assert.rejects(socksConnect(f.proxy, 'openrouter.ai', 443, newIdentity()), TorError);
    f.srv.close();
  });
}

test('fails closed when Tor is not running (no direct fallback)', async () => {
  // a port nothing listens on
  const probe = net.createServer(); await new Promise<void>(r => probe.listen(0, '127.0.0.1', () => r()));
  const port = (probe.address() as net.AddressInfo).port; probe.close();
  await assert.rejects(socksConnect({ host: '127.0.0.1', port }, 'openrouter.ai', 443, newIdentity(), 2000), TorError);
});
