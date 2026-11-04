// Live check of PARANOID's Tor routing, run by the public CI against a real Tor
// daemon: every request goes through PARANOID's own SOCKS5 code (TorAgent),
// check.torproject.org must confirm each exit is a Tor relay, one conversation
// identity must keep its exit, and separate identities must not all share one.
//   node scripts/verify-tor.ts [socksPort]
import https from 'node:https';
import { TorAgent, newIdentity } from '../src/tor.ts';

const proxy = { host: '127.0.0.1', port: Number(process.argv[2] || 9050) };

function exitOf(identity: string): Promise<{ IsTor: boolean; IP: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request({ host: 'check.torproject.org', path: '/api/ip', agent: new TorAgent(proxy, identity), timeout: 60_000, headers: { 'user-agent': 'Mozilla/5.0' } }, res => {
      let s = ''; res.setEncoding('utf8');
      res.on('data', d => { s += d; });
      res.on('end', () => { try { resolve(JSON.parse(s)); } catch { reject(new Error('bad response')); } });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

async function retry<T>(f: () => Promise<T>, n = 4): Promise<T> {
  for (let i = 1; ; i++) { try { return await f(); } catch (e) { if (i >= n) throw e; await new Promise(r => setTimeout(r, 3000)); } }
}

const ids = [newIdentity(), newIdentity(), newIdentity()];
const first = await retry(() => exitOf(ids[0]));
const again = await retry(() => exitOf(ids[0]));
const others = [await retry(() => exitOf(ids[1])), await retry(() => exitOf(ids[2]))];
const all = [first, again, ...others];
const mask = (ip: string) => ip.replace(/\.\d+$/, '.x').replace(/:[0-9a-f]*$/i, ':x');

console.log(`conversation A, request 1: exit ${mask(first.IP)}  IsTor=${first.IsTor}`);
console.log(`conversation A, request 2: exit ${mask(again.IP)}  IsTor=${again.IsTor}`);
console.log(`conversation B:            exit ${mask(others[0].IP)}  IsTor=${others[0].IsTor}`);
console.log(`conversation C:            exit ${mask(others[1].IP)}  IsTor=${others[1].IsTor}`);

let ok = true;
if (!all.every(r => r.IsTor === true)) { console.error('FAIL: an exit was not confirmed as Tor'); ok = false; }
if (first.IP !== again.IP) { console.error('FAIL: one conversation changed exit between requests'); ok = false; }
if (new Set([first.IP, ...others.map(o => o.IP)]).size < 2) { console.error('FAIL: three conversations shared a single exit'); ok = false; }
console.log(ok ? 'PASS: every exit is Tor, a conversation keeps its circuit, conversations are isolated' : 'FAIL');
process.exit(ok ? 0 : 1);
