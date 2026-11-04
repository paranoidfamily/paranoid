// Tor routing. Port of zkapi-clientd internal/relay/socks5.go (vbuterin/zkapi
// feat/client-concession-local @ 0fb263b, MIT, Open Anonymity Team):
//  - destination names go to the proxy (ATYP 3): the local resolver never sees them;
//  - RFC 1929 username = random per-conversation identity, password "x"; with
//    Tor's IsolateSOCKSAuth each identity gets its own circuit;
//  - no-auth is never offered in Tor mode and a failed handshake never falls back to direct TCP.
import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { log } from './log.ts';

export class TorError extends Error { code = 'tor_unavailable'; }

export function newIdentity(): string { return crypto.randomBytes(32).toString('hex'); }

function readExactly(sock: net.Socket, n: number, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => done(new TorError('SOCKS5 timeout')), timeoutMs);
    const onData = (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= n) {
        const rest = buf.subarray(n);
        done(null, buf.subarray(0, n));
        // only after our listener is gone and the socket paused, or unshift re-enters onData
        if (rest.length) sock.unshift(rest);
      }
    };
    const onEnd = () => done(new TorError('SOCKS5 connection closed'));
    const onErr = () => done(new TorError('SOCKS5 proxy unavailable'));
    let settled = false;
    function done(err: Error | null, out?: Buffer) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.off('data', onData); sock.off('end', onEnd); sock.off('error', onErr);
      sock.pause();
      err ? reject(err) : resolve(out!);
    }
    sock.on('data', onData); sock.once('end', onEnd); sock.once('error', onErr);
    sock.resume();
  });
}

export async function socksConnect(proxy: { host: string; port: number }, host: string, port: number, identity: string, timeoutMs = 20_000): Promise<net.Socket> {
  if (!identity || identity.length > 255) throw new TorError('invalid Tor isolation identity');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new TorError('invalid destination port');
  let atyp = 3, addr = Buffer.from(host);
  const ipv = net.isIP(host);
  if (ipv === 4) { atyp = 1; addr = Buffer.from(host.split('.').map(Number)); }
  else if (ipv === 6) throw new TorError('IPv6 literal destinations are not supported');
  else if (addr.length === 0 || addr.length > 255) throw new TorError('invalid destination name');

  const sock = net.connect({ host: proxy.host, port: proxy.port });
  sock.pause();
  try {
    await new Promise<void>((res, rej) => {
      const t = setTimeout(() => rej(new TorError('SOCKS5 proxy unavailable')), timeoutMs);
      sock.once('connect', () => { clearTimeout(t); res(); });
      sock.once('error', () => { clearTimeout(t); rej(new TorError('SOCKS5 proxy unavailable')); });
    });
    sock.write(Buffer.from([5, 1, 2])); // username/password only
    let r = await readExactly(sock, 2, timeoutMs);
    if (r[0] !== 5 || r[1] !== 2) throw new TorError('SOCKS5 proxy rejected required authentication method');
    const id = Buffer.from(identity);
    sock.write(Buffer.concat([Buffer.from([1, id.length]), id, Buffer.from([1, 0x78])]));
    r = await readExactly(sock, 2, timeoutMs);
    if (r[0] !== 1 || r[1] !== 0) throw new TorError('Tor isolation authentication rejected');
    const req = [Buffer.from([5, 1, 0, atyp])];
    if (atyp === 3) req.push(Buffer.from([addr.length]));
    req.push(addr, Buffer.from([port >> 8, port & 255]));
    sock.write(Buffer.concat(req));
    r = await readExactly(sock, 4, timeoutMs);
    if (r[0] !== 5 || r[1] !== 0 || r[2] !== 0) throw new TorError('SOCKS5 connect failed');
    let remaining: number;
    if (r[3] === 1) remaining = 4;
    else if (r[3] === 4) remaining = 16;
    else if (r[3] === 3) remaining = (await readExactly(sock, 1, timeoutMs))[0];
    else throw new TorError('SOCKS5 connect reply invalid');
    await readExactly(sock, remaining + 2, timeoutMs);
    return sock;
  } catch (e) {
    sock.destroy();
    throw e instanceof TorError ? e : new TorError('SOCKS5 failure');
  }
}

/** HTTPS agent whose every connection goes through Tor with one isolation identity. No keep-alive, no local DNS. */
export class TorAgent extends https.Agent {
  proxy: { host: string; port: number };
  identity: string;
  constructor(proxy: { host: string; port: number }, identity: string) {
    super({ keepAlive: false, maxSockets: 4 });
    this.proxy = proxy;
    this.identity = identity;
  }
  createConnection(options: any, cb: (err: Error | null, s?: net.Socket) => void): any {
    const host = options.host || options.hostname;
    const port = +options.port || 443;
    socksConnect(this.proxy, host, port, this.identity).then(raw => {
      const t = tls.connect({ socket: raw, servername: options.servername || host, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] });
      t.once('secureConnect', () => cb(null, t));
      t.once('error', err => cb(err));
    }, cb);
    return undefined;
  }
}

// ------------------------------------------------------------------ tor.exe management
export interface TorState { installed: boolean; running: boolean; verified: boolean; managed: boolean; lastCheck: string | null; error: string | null; exitIsTor: boolean | null }

export class TorManager {
  proxy: { host: string; port: number };
  exe: string | null;
  dataDir: string;
  child: ChildProcess | null = null;
  state: TorState = { installed: false, running: false, verified: false, managed: false, lastCheck: null, error: null, exitIsTor: null };

  constructor(proxy: { host: string; port: number }, exe: string | null, profileDir: string) {
    this.proxy = proxy;
    this.dataDir = path.join(profileDir, 'tor-data');
    const bundled = path.join(profileDir, 'tor', 'tor', process.platform === 'win32' ? 'tor.exe' : 'tor');
    this.exe = exe || (fs.existsSync(bundled) ? bundled : null);
    this.state.installed = !!this.exe;
  }

  portOpen(): Promise<boolean> {
    return new Promise(res => {
      const s = net.connect({ host: this.proxy.host, port: this.proxy.port });
      const t = setTimeout(() => { s.destroy(); res(false); }, 1500);
      s.once('connect', () => { clearTimeout(t); s.destroy(); res(true); });
      s.once('error', () => { clearTimeout(t); res(false); });
    });
  }

  async start(): Promise<void> {
    if (await this.portOpen()) { this.state.running = true; return; }
    if (!this.exe) throw new TorError('Tor is not installed (run node scripts/install-tor.mjs)');
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    const torrc = path.join(this.dataDir, 'torrc');
    fs.writeFileSync(torrc, [
      `SocksPort ${this.proxy.host}:${this.proxy.port} IsolateSOCKSAuth`,
      'SocksPolicy accept 127.0.0.1',
      'SocksPolicy reject *',
      'ControlPort 0',
      `DataDirectory ${this.dataDir.replace(/\\/g, '/')}`,
      'ClientOnly 1',
      'AvoidDiskWrites 1',
      'Log notice stdout',
    ].join('\n') + '\n');
    const child = spawn(this.exe, ['-f', torrc], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    this.child = child;
    this.state.managed = true;
    await new Promise<void>((resolve, reject) => {
      const t = setTimeout(() => reject(new TorError('Tor bootstrap timed out')), 120_000);
      child.stdout!.on('data', (d: Buffer) => {
        const m = /Bootstrapped (\d+)%/.exec(d.toString());
        if (m) log('tor.bootstrap', { percent: +m[1] });
        if (m && m[1] === '100') { clearTimeout(t); resolve(); }
      });
      child.once('exit', code => { clearTimeout(t); this.child = null; this.state.running = false; reject(new TorError(`tor exited (${code})`)); });
    });
    child.on('exit', () => { this.child = null; this.state.running = false; this.state.verified = false; log('tor.exit'); });
    this.state.running = true;
  }

  stop() { this.child?.kill(); this.child = null; }

  /** Fetches check.torproject.org's JSON API through a fresh identity: confirms traffic exits through Tor. */
  async verify(): Promise<TorState> {
    this.state.lastCheck = new Date().toISOString();
    this.state.running = await this.portOpen();
    if (!this.state.running) { this.state.verified = false; this.state.error = 'SOCKS port closed'; return this.state; }
    try {
      const body = await new Promise<string>((resolve, reject) => {
        const req = https.request({ host: 'check.torproject.org', path: '/api/ip', method: 'GET', agent: new TorAgent(this.proxy, newIdentity()), timeout: 30_000, headers: { 'user-agent': 'Mozilla/5.0' } }, res => {
          let s = ''; res.setEncoding('utf8');
          res.on('data', (d: string) => { s += d; if (s.length > 4096) req.destroy(); });
          res.on('end', () => resolve(s));
        });
        req.on('timeout', () => req.destroy(new TorError('check timed out')));
        req.on('error', reject);
        req.end();
      });
      const j = JSON.parse(body);
      this.state.exitIsTor = j.IsTor === true;
      this.state.verified = this.state.exitIsTor;
      this.state.error = this.state.verified ? null : 'exit is not a Tor relay';
    } catch (e: any) {
      this.state.verified = false;
      this.state.error = e instanceof TorError ? e.message : 'verification request failed';
    }
    log('tor.verify', { verified: this.state.verified });
    return this.state;
  }
}
