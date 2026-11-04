// OS-level sandbox for agent shell tools: bubblewrap (Linux namespaces).
// On Linux, bwrap runs directly. On Windows it runs inside WSL2 (bwrap needs a
// Linux kernel); nothing here falls back to running code on the host.
//
// The guest gets: a read-only /usr (and the /bin, /lib links into it), the
// dynamic-linker cache, a fresh /proc and minimal /dev, an empty tmpfs as /tmp
// and working directory, uid/gid 65534, no capabilities, an empty environment,
// and new user, pid, network, ipc, uts and cgroup namespaces. No home, no /mnt
// (so no Windows drives under WSL), no /etc/passwd, no resolver, no sockets to
// the host. The network namespace contains only an unconfigured loopback, so
// egress is impossible. CPU time, address space, file size, process count and
// open files are capped with ulimit; wall time is capped by `timeout -s KILL`
// inside Linux and by a kill from Node as a backstop; when bwrap's pid 1 dies,
// the kernel kills everything left in its pid namespace.
import { spawn } from 'node:child_process';
import { log } from './log.ts';

export interface ShellResult { ok: boolean; output: string; exitCode: number | null; error: string | null; ms: number; truncated: boolean }

export const BWRAP_LIMITS = { timeoutS: 5, cpuS: 5, memoryKiB: 512 * 1024, fileKiB: 8 * 1024, procs: 128, files: 64, maxOutput: 16 * 1024, maxCode: 32 * 1024 };

export const BWRAP_POLICY: [string, string][] = [
  ['Engine', 'bubblewrap (Linux namespaces)'],
  ['Filesystem', 'read-only /usr; empty /tmp; no home, no /mnt, no host files'],
  ['Network', 'none (own network namespace, loopback only, down)'],
  ['Identity', 'uid 65534, no capabilities, empty environment'],
  ['Memory', `${BWRAP_LIMITS.memoryKiB / 1024} MiB address space`],
  ['Time', `${BWRAP_LIMITS.timeoutS} s wall, ${BWRAP_LIMITS.cpuS} s CPU, then SIGKILL`],
  ['Processes', `${BWRAP_LIMITS.procs} max, killed with the sandbox`],
];

/** bwrap arguments, without the program to run. Pure, so tests can check the policy. */
export function bwrapArgs(): string[] {
  return [
    '--unshare-all', // user, pid, net, ipc, uts, cgroup (and mount)
    '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
    '--uid', '65534', '--gid', '65534', '--hostname', 'sandbox',
    '--clearenv', '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin', '--setenv', 'HOME', '/tmp', '--setenv', 'LANG', 'C.UTF-8',
    '--ro-bind', '/usr', '/usr',
    '--ro-bind-try', '/bin', '/bin', '--ro-bind-try', '/sbin', '/sbin',
    '--ro-bind-try', '/lib', '/lib', '--ro-bind-try', '/lib64', '/lib64', '--ro-bind-try', '/lib32', '/lib32',
    '--ro-bind-try', '/etc/ld.so.cache', '/etc/ld.so.cache', '--ro-bind-try', '/etc/alternatives', '/etc/alternatives',
    '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--chdir', '/tmp',
  ];
}

/** The shell inside the sandbox sets the resource limits, then reads the script from stdin. */
export function guestCommand(): string[] {
  const L = BWRAP_LIMITS;
  return ['/bin/sh', '-c', `ulimit -t ${L.cpuS}; ulimit -v ${L.memoryKiB}; ulimit -f ${L.fileKiB}; ulimit -n ${L.files}; ulimit -u ${L.procs} 2>/dev/null; exec /bin/sh -s`];
}

export interface Launcher { cmd: string; args: string[] }

/** How bwrap is reached from this host: directly on Linux, through wsl.exe on Windows. */
export function launcher(platform = process.platform, wslDistro = ''): Launcher | null {
  const inner = ['timeout', '-s', 'KILL', String(BWRAP_LIMITS.timeoutS + 1), 'bwrap', ...bwrapArgs(), '--', ...guestCommand()];
  if (platform === 'linux') return { cmd: inner[0], args: inner.slice(1) };
  if (platform === 'win32') {
    if (wslDistro && !/^[\w.-]{1,64}$/.test(wslDistro)) return null;
    // --exec: no Linux shell parses the arguments
    return { cmd: 'wsl.exe', args: [...(wslDistro ? ['-d', wslDistro] : []), '--exec', ...inner] };
  }
  return null;
}

// wsl.exe prints its own messages in UTF-16LE
const decode = (bufs: Buffer[]) => {
  const b = Buffer.concat(bufs);
  let zeros = 0;
  for (let i = 1; i < Math.min(b.length, 200); i += 2) if (b[i] === 0) zeros++;
  return (zeros > 20 ? b.toString('utf16le') : b.toString('utf8')).replace(/\u0000/g, '').replace(/\r/g, '').trim();
};

export type Spawner = typeof spawn;

export function runShell(code: string, opts: { wslDistro?: string; spawner?: Spawner; platform?: string } = {}): Promise<ShellResult> {
  const fail = (error: string): ShellResult => ({ ok: false, output: '', exitCode: null, error, ms: 0, truncated: false });
  if (typeof code !== 'string' || !code.trim()) return Promise.resolve(fail('empty script'));
  if (code.length > BWRAP_LIMITS.maxCode) return Promise.resolve(fail('script too long'));
  const l = launcher((opts.platform || process.platform) as NodeJS.Platform, opts.wslDistro || '');
  if (!l) return Promise.resolve(fail('bubblewrap is not supported on this platform'));
  const t0 = Date.now();
  return new Promise(resolve => {
    let child;
    try {
      child = (opts.spawner || spawn)(l.cmd, l.args, { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, env: process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot || 'C:\\Windows', PATH: process.env.PATH || '' } : { PATH: '/usr/bin:/bin' } });
    } catch { resolve(fail('could not start bubblewrap')); return; }
    const bufs: Buffer[] = []; let size = 0, truncated = false, done = false;
    const add = (b: Buffer) => {
      if (truncated) return;
      const room = BWRAP_LIMITS.maxOutput - size;
      bufs.push(b.length > room ? b.subarray(0, room) : b); size += Math.min(b.length, room);
      if (b.length > room) { truncated = true; child.kill('SIGKILL'); }
    };
    child.stdout.on('data', add); child.stderr.on('data', add);
    const finish = (r: ShellResult) => { if (done) return; done = true; clearTimeout(kill); log('sandbox.shell', { ok: r.ok, ms: r.ms, exitCode: r.exitCode }); resolve(r); };
    const kill = setTimeout(() => { child.kill('SIGKILL'); finish({ ok: false, output: decode(bufs), exitCode: null, error: 'time limit exceeded', ms: Date.now() - t0, truncated }); }, (BWRAP_LIMITS.timeoutS + 4) * 1000);
    child.on('error', () => finish(fail('could not start bubblewrap')));
    child.on('close', (codeNum: number | null, signal: string | null) => {
      const ms = Date.now() - t0;
      if (truncated) return finish({ ok: false, output: decode(bufs), exitCode: codeNum, error: 'output limit exceeded', ms, truncated });
      // 137 = SIGKILL from `timeout`, 152 = SIGXCPU
      if (codeNum === 137 || codeNum === 124 || signal === 'SIGKILL' && !truncated) return finish({ ok: false, output: decode(bufs), exitCode: codeNum, error: 'time limit exceeded', ms, truncated });
      if (codeNum === 152) return finish({ ok: false, output: decode(bufs), exitCode: codeNum, error: 'CPU limit exceeded', ms, truncated });
      finish({ ok: codeNum === 0, output: decode(bufs), exitCode: codeNum, error: codeNum === 0 ? null : `exit status ${codeNum}`, ms, truncated });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(code);
  });
}

// The probe proves the isolation instead of trusting the flags: it must run as
// 65534, see only loopback in its network namespace, and see no host home,
// no Windows drives and no writable /usr.
export const PROBE = [
  'id -u',
  'awk \'NR>2{sub(":","",$1);print $1}\' /proc/net/dev | tr "\\n" ","; echo',
  'for p in /mnt /home /root /run/WSL /etc/passwd; do [ -e "$p" ] && echo "visible:$p"; done',
  'touch /usr/x 2>/dev/null && echo usr-writable',
  'echo probe-ok',
].join('\n');

export function checkProbe(r: ShellResult): string | null {
  if (!r.ok) return r.error === 'could not start bubblewrap' ? 'bubblewrap could not be started' : `bubblewrap probe failed: ${(r.output || r.error || '').slice(0, 200)}`;
  const lines = r.output.split('\n').map(s => s.trim()).filter(Boolean);
  if (lines[lines.length - 1] !== 'probe-ok') return 'bubblewrap probe gave unexpected output';
  if (lines[0] !== '65534') return 'sandbox does not run as an unprivileged user';
  if (lines[1].replace(/,$/, '') !== 'lo') return 'sandbox has a network interface other than loopback';
  const leak = lines.find(l => l.startsWith('visible:') || l === 'usr-writable');
  if (leak) return `sandbox isolation check failed (${leak})`;
  return null;
}

let cached: { at: number; value: { available: boolean; reason: string } } | null = null;

/** Probes bubblewrap (cached 5 min when available, 30 s when not). */
export async function bwrapHealth(opts: { wslDistro?: string; spawner?: Spawner; platform?: string; force?: boolean } = {}) {
  if (!opts.force && cached && Date.now() - cached.at < (cached.value.available ? 300_000 : 30_000)) return cached.value;
  const platform = opts.platform || process.platform;
  let value: { available: boolean; reason: string };
  if (platform !== 'linux' && platform !== 'win32') value = { available: false, reason: 'bubblewrap needs Linux (or WSL2 on Windows)' };
  else {
    const r = await runShell(PROBE, opts);
    const bad = checkProbe(r);
    value = bad
      ? { available: false, reason: platform === 'win32' && !r.ok ? `${bad}. Install WSL2 (wsl --install), then in it: sudo apt install bubblewrap` : bad }
      : { available: true, reason: `bubblewrap${platform === 'win32' ? ' in WSL2' : ''}: no network, read-only system, empty /tmp, uid 65534` };
  }
  cached = { at: Date.now(), value };
  return value;
}

export function resetBwrapHealth() { cached = null; }

export const SHELL_TOOL = {
  type: 'function',
  function: {
    name: 'run_shell',
    description: `Run a POSIX sh script in a bubblewrap sandbox and get its combined output. Read-only system tools (/usr), an empty writable /tmp, no network, no user files; ${BWRAP_LIMITS.timeoutS} s and ${BWRAP_LIMITS.memoryKiB / 1024} MiB limits. Interpreters available depend on the Linux system (e.g. python3, awk).`,
    parameters: { type: 'object', properties: { script: { type: 'string', description: 'Shell script, run with /bin/sh in /tmp.' } }, required: ['script'] },
  },
};
