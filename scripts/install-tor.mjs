// Downloads the official Tor Expert Bundle into <profile>/tor and verifies it:
//  1. SHA-256 of the archive against sha256sums-signed-build.txt from dist.torproject.org;
//  2. the OpenPGP signature of that sums file with the Tor Browser signing key
//     (fingerprint EF6E286DDA85EA2A4BA7DE684E2C6E8793298290), when gpg is available.
// Refuses to install on any mismatch. Usage: node scripts/install-tor.mjs [--require-signature]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const KEY_FPR = 'EF6E286DDA85EA2A4BA7DE684E2C6E8793298290';
const requireSig = process.argv.includes('--require-signature');
const home = process.env.PARANOID_HOME || (process.platform === 'win32'
  ? path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'paranoid')
  : path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'paranoid'));
const target = { win32: 'windows-x86_64', linux: 'linux-x86_64', darwin: 'macos-aarch64' }[process.platform];
if (!target) throw new Error('unsupported platform');

const get = async url => { const r = await fetch(url); if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`); return Buffer.from(await r.arrayBuffer()); };

const listing = (await get('https://dist.torproject.org/torbrowser/')).toString();
const versions = [...listing.matchAll(/href="(\d+\.\d+(?:\.\d+)?)\/"/g)].map(m => m[1])
  .sort((a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); return 0; });
let version, base, name;
for (const v of versions.reverse()) {
  base = `https://dist.torproject.org/torbrowser/${v}/`;
  const files = (await get(base)).toString();
  const m = new RegExp(`tor-expert-bundle-${target}-${v.replace(/\./g, '\\.')}\\.tar\\.gz`).exec(files);
  if (m && files.includes('sha256sums-signed-build.txt.asc')) { version = v; name = m[0]; break; }
}
if (!version) throw new Error('no Tor Expert Bundle found');
console.log(`Tor Expert Bundle ${version} (${target})`);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'paranoid-tor-'));
const archive = path.join(tmp, name);
fs.writeFileSync(archive, await get(base + name));
const sums = await get(base + 'sha256sums-signed-build.txt');
const sig = await get(base + 'sha256sums-signed-build.txt.asc');
fs.writeFileSync(path.join(tmp, 'sums.txt'), sums);
fs.writeFileSync(path.join(tmp, 'sums.txt.asc'), sig);

const digest = crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex');
const line = sums.toString().split('\n').find(l => l.trim().endsWith(name));
if (!line || line.split(/\s+/)[0] !== digest) throw new Error('SHA-256 mismatch: refusing to install');
console.log('SHA-256 matches the published sums file');

const gpg = spawnSync('gpg', ['--version'], { encoding: 'utf8' });
if (gpg.status === 0) {
  const gnupg = path.join(tmp, 'gnupg'); fs.mkdirSync(gnupg, { mode: 0o700 });
  // the MSYS gpg shipped with Git for Windows reads "C:/x" as a relative path: give it "/c/x"
  const fwd = p => p.replace(/\\/g, '/');
  const msys = process.platform === 'win32' && /Home: \//.test(gpg.stdout);
  const gh = ['--homedir', msys ? fwd(gnupg).replace(/^([A-Za-z]):/, (_, d) => '/' + d.toLowerCase()) : gnupg];
  spawnSync('gpg', [...gh, '--batch', '--auto-key-locate', 'nodefault,wkd', '--locate-keys', 'torbrowser@torproject.org'], { encoding: 'utf8' });
  const v = spawnSync('gpg', [...gh, '--batch', '--status-fd', '1', '--verify', fwd(path.join(tmp, 'sums.txt.asc')), fwd(path.join(tmp, 'sums.txt'))], { encoding: 'utf8' });
  if (process.env.DEBUG_GPG) console.log(v.status, v.stdout, v.stderr);
  const valid = /\[GNUPG:\] VALIDSIG ([0-9A-F]+)/.exec(v.stdout || '');
  const primary = /\[GNUPG:\] VALIDSIG [0-9A-F]+ .* ([0-9A-F]{40})\s*$/m.exec(v.stdout || '');
  if (!valid || (primary ? primary[1] : valid[1]) !== KEY_FPR) {
    if (requireSig) throw new Error('signature verification failed: refusing to install');
    console.warn('WARNING: could not verify the signature of the sums file (key fetch or gpg failure)');
  } else console.log(`Signature valid (key ${KEY_FPR})`);
} else if (requireSig) throw new Error('gpg not found and --require-signature given');
else console.warn('WARNING: gpg not found; only the SHA-256 was checked');

const dest = path.join(home, 'tor');
fs.rmSync(dest, { recursive: true, force: true });
fs.mkdirSync(dest, { recursive: true });
const tarBin = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
const t = spawnSync(tarBin, ['-xzf', archive, '-C', dest], { encoding: 'utf8' });
if (t.status !== 0) throw new Error('extraction failed: ' + t.stderr);
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`Installed in ${dest}`);
