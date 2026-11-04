// Secrets at rest. Windows: DPAPI (CurrentUser scope) through PowerShell, the
// secret travelling on stdin, never on the command line. Elsewhere: a 0600 file.
// Secret values are never logged and never returned by the HTTP API.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const PS = ['-NoProfile', '-NonInteractive', '-Command'];

function dpapi(mode: 'protect' | 'unprotect', input: string): string {
  const script = mode === 'protect'
    ? "Add-Type -AssemblyName System.Security; $i=[Console]::In.ReadToEnd(); [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($i),$null,'CurrentUser'))"
    : "Add-Type -AssemblyName System.Security; $i=[Console]::In.ReadToEnd().Trim(); [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($i),$null,'CurrentUser'))";
  const r = spawnSync('powershell.exe', [...PS, script], { input, encoding: 'utf8', windowsHide: true, timeout: 20_000 });
  if (r.status !== 0) throw new Error(`DPAPI ${mode} failed`);
  return r.stdout.replace(/\r?\n$/, '');
}

export class SecretStore {
  dir: string;
  cache = new Map<string, string>();
  constructor(profileDir: string) {
    this.dir = path.join(profileDir, 'secrets');
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }
  private file(name: string) {
    if (!/^[a-z0-9-]+$/.test(name)) throw new Error('invalid secret name');
    return path.join(this.dir, name + (process.platform === 'win32' ? '.dpapi' : '.secret'));
  }
  has(name: string): boolean { return this.cache.has(name) || fs.existsSync(this.file(name)); }
  get(name: string): string | null {
    if (this.cache.has(name)) return this.cache.get(name)!;
    const f = this.file(name);
    if (!fs.existsSync(f)) return null;
    const raw = fs.readFileSync(f, 'utf8');
    const value = process.platform === 'win32' ? dpapi('unprotect', raw) : raw;
    this.cache.set(name, value);
    return value;
  }
  set(name: string, value: string) {
    const f = this.file(name);
    const data = process.platform === 'win32' ? dpapi('protect', value) : value;
    fs.writeFileSync(f, data, { mode: 0o600 });
    this.cache.set(name, value);
  }
  delete(name: string) {
    this.cache.delete(name);
    fs.rmSync(this.file(name), { force: true });
  }
}
