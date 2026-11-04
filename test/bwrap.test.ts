// bubblewrap backend: the sandbox policy, the launcher, the isolation probe and
// the agent-loop gating. The real bwrap binary is not needed: a fake spawner
// stands in for it, and the live check runs only where bwrap exists.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { bwrapArgs, guestCommand, launcher, checkProbe, runShell, bwrapHealth, PROBE, resetBwrapHealth } from '../src/bwrap.ts';
import { makeRuntime, fakeLocalModel, scriptedProvider, echoRewrite } from './helpers.ts';

/** Fake child process: records stdin, emits the given output and exit code. */
function fakeSpawner(reply: (stdin: string, cmd: string, args: string[]) => { out?: string; code?: number | null; signal?: string; hang?: boolean }) {
  const calls: { cmd: string; args: string[]; stdin: string; env: any }[] = [];
  const fn: any = (cmd: string, args: string[], o: any) => {
    const ch: any = new EventEmitter();
    ch.stdout = new PassThrough(); ch.stderr = new PassThrough(); ch.stdin = new PassThrough();
    let input = '';
    ch.stdin.on('data', (b: Buffer) => { input += b; });
    ch.kill = () => { setImmediate(() => ch.emit('close', null, 'SIGKILL')); };
    ch.stdin.on('finish', () => {
      calls.push({ cmd, args, stdin: input, env: o.env });
      const r = reply(input, cmd, args);
      if (r.hang) return;
      setImmediate(() => { if (r.out) ch.stdout.write(r.out); setImmediate(() => ch.emit('close', r.code ?? 0, r.signal ?? null)); });
    });
    return ch;
  };
  return { fn, calls };
}

test('policy: every namespace unshared, no capabilities, empty env, no host home or drives', () => {
  const a = bwrapArgs();
  for (const f of ['--unshare-all', '--die-with-parent', '--new-session', '--clearenv']) assert.ok(a.includes(f), f);
  assert.deepEqual(a.slice(a.indexOf('--cap-drop'), a.indexOf('--cap-drop') + 2), ['--cap-drop', 'ALL']);
  assert.equal(a[a.indexOf('--uid') + 1], '65534');
  assert.ok(!a.includes('--share-net'), 'network shared');
  // only read-only binds, and none of them exposes user data
  assert.ok(!a.includes('--bind') && !a.includes('--dev-bind'), 'writable host bind');
  const sources = a.flatMap((x, i) => x.startsWith('--ro-bind') ? [a[i + 1]] : []);
  for (const s of sources) assert.match(s, /^\/(usr|bin|sbin|lib|lib64|lib32|etc\/ld\.so\.cache|etc\/alternatives)$/, s);
  assert.equal(a[a.indexOf('--tmpfs') + 1], '/tmp');
  const g = guestCommand().join(' ');
  for (const l of ['ulimit -t', 'ulimit -v', 'ulimit -f', 'ulimit -n']) assert.ok(g.includes(l), l);
  assert.ok(g.endsWith('exec /bin/sh -s'), 'script must come from stdin, not argv');
});

test('launcher: direct on Linux, wsl.exe --exec on Windows, nothing elsewhere', () => {
  const lin = launcher('linux')!;
  assert.equal(lin.cmd, 'timeout');
  assert.deepEqual(lin.args.slice(0, 3), ['-s', 'KILL', '6']);
  assert.equal(lin.args[3], 'bwrap');
  const win = launcher('win32', 'Ubuntu')!;
  assert.equal(win.cmd, 'wsl.exe');
  assert.deepEqual(win.args.slice(0, 4), ['-d', 'Ubuntu', '--exec', 'timeout']);
  assert.equal(launcher('win32', 'Ubuntu; rm -rf /'), null);
  assert.equal(launcher('darwin'), null);
});

const GOOD = '65534\nlo,\nprobe-ok\n';
test('isolation probe: accepts only uid 65534, loopback-only network, no host paths', () => {
  const ok = (output: string) => ({ ok: true, output, exitCode: 0, error: null, ms: 1, truncated: false });
  assert.equal(checkProbe(ok(GOOD)), null);
  assert.match(checkProbe(ok('1000\nlo,\nprobe-ok'))!, /unprivileged/);
  assert.match(checkProbe(ok('65534\nlo,eth0,\nprobe-ok'))!, /network/);
  assert.match(checkProbe(ok('65534\nlo,\nvisible:/mnt\nprobe-ok'))!, /visible:\/mnt/);
  assert.match(checkProbe(ok('65534\nlo,\nusr-writable\nprobe-ok'))!, /usr-writable/);
  assert.match(checkProbe({ ok: false, output: '', exitCode: null, error: 'could not start bubblewrap', ms: 0, truncated: false })!, /could not be started/);
});

test('health: fails closed with install instructions when WSL/bwrap is missing', async () => {
  resetBwrapHealth();
  const sp = fakeSpawner(() => ({ out: 'bwrap: not found', code: 1 }));
  const h = await bwrapHealth({ platform: 'win32', spawner: sp.fn, force: true });
  assert.equal(h.available, false);
  assert.match(h.reason, /wsl --install/);
  assert.equal(sp.calls[0].stdin, PROBE);
  assert.equal(sp.calls[0].cmd, 'wsl.exe');
  assert.ok(!('APPDATA' in sp.calls[0].env) && !('USERPROFILE' in sp.calls[0].env), 'host environment passed to the sandbox launcher');
  const good = fakeSpawner(() => ({ out: GOOD, code: 0 }));
  assert.equal((await bwrapHealth({ platform: 'win32', spawner: good.fn, force: true })).available, true);
  resetBwrapHealth();
});

test('runShell: script goes through stdin, timeouts and output floods are cut', async () => {
  const echo = fakeSpawner(s => ({ out: 'ran:' + s, code: 0 }));
  const r = await runShell('echo "$HOME" && ls /', { platform: 'linux', spawner: echo.fn });
  assert.equal(r.ok, true);
  assert.equal(r.output, 'ran:echo "$HOME" && ls /');
  assert.ok(!echo.calls[0].args.some(a => a.includes('ls /')), 'script leaked into argv');
  const slow = fakeSpawner(() => ({ code: 137 }));
  assert.equal((await runShell('while :; do :; done', { platform: 'linux', spawner: slow.fn })).error, 'time limit exceeded');
  const f =fakeSpawner(() => ({ out: 'x'.repeat(100_000), code: 0 }));
  const big = await runShell('yes', { platform: 'linux', spawner: f.fn });
  assert.equal(big.truncated, true);
  assert.ok(big.output.length <= 16 * 1024);
  assert.equal((await runShell('', { platform: 'linux', spawner: echo.fn })).error, 'empty script');
  assert.equal((await runShell('true', { platform: 'darwin', spawner: echo.fn })).error, 'bubblewrap is not supported on this platform');
});

test('agent loop: run_shell is offered and executed only while bubblewrap passes its probe', async () => {
  const m = await fakeLocalModel(echoRewrite);
  const script = 'printf "%s" "$((6*7))"';
  // unavailable: not offered, and a call to it is refused
  {
    const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
    let ran = 0; rt.runShell = async () => { ran++; return { ok: true, output: 'x' }; };
    const p = scriptedProvider([{ tools: [{ name: 'run_shell', args: JSON.stringify({ script }) }] }, { text: 'done' }]);
    rt.providerRequest = p.fn as any;
    const s = rt.sessions.create();
    const pv = await rt.preview(s, 'compute');
    const tools: any[] = [];
    await rt.send(s, { previewId: pv.previewId, agent: true }, () => {}, e => tools.push(e));
    assert.deepEqual(p.calls[0].body.tools.map((t: any) => t.function.name), ['run_js']);
    assert.equal(ran, 0, 'shell ran without a passing isolation probe');
    assert.equal(tools[0].ok, false);
  }
  // available: offered, executed, output returned to the model masked
  {
    const { rt } = await makeRuntime({ profile: 'private', sanitizerUrl: m.url, torVerified: true });
    rt.bwrapProbe = async () => ({ available: true, reason: 'test' });
    const seen: string[] = [];
    rt.runShell = async (sc: string) => { seen.push(sc); return { ok: true, output: '42 claire.martin@protonmail.com', exitCode: 0, error: null }; };
    const p = scriptedProvider([{ tools: [{ name: 'run_shell', args: JSON.stringify({ script }) }] }, { text: 'done' }]);
    rt.providerRequest = p.fn as any;
    const s = rt.sessions.create();
    const pv = await rt.preview(s, 'compute');
    const r = await rt.send(s, { previewId: pv.previewId, agent: true }, () => {});
    assert.deepEqual(p.calls[0].body.tools.map((t: any) => t.function.name), ['run_js', 'run_shell']);
    assert.deepEqual(seen, [script]);
    assert.equal(r.toolRuns, 1);
    assert.ok(!JSON.stringify(p.calls[1].body).includes('protonmail'), 'tool output reached the provider unmasked');
    // disabled in settings: not offered even if bwrap works
    rt.config.update({ sandbox: { bubblewrap: false } });
    assert.equal((await rt.bubblewrapState()).available, false);
  }
  m.close();
});

// Live check, only where bubblewrap actually runs (Linux, or Windows with WSL2 + bwrap).
test('live: real bubblewrap blocks network and host files', async t => {
  resetBwrapHealth();
  const h = await bwrapHealth({ force: true });
  if (!h.available) { t.skip(h.reason); return; }
  const r = await runShell('id -u; cat /proc/net/dev | wc -l; ls /mnt /home 2>&1 | head -2; (exec 3<>/dev/tcp/1.1.1.1/443) 2>&1 | head -1; echo end');
  assert.equal(r.ok, true, r.error || '');
  assert.match(r.output, /^65534\n3\n/);
  assert.match(r.output, /end$/);
});
