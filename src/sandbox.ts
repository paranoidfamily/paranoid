// Agent runtime sandbox. Model-generated code is untrusted: it runs in QuickJS
// compiled to WebAssembly, inside a separate worker thread with a V8 heap cap,
// a QuickJS memory and stack limit, an interrupt deadline, and a hard kill of
// the worker as a backstop. The guest gets no filesystem, network, process,
// timer or host object; egress is impossible by construction rather than by
// policy, so no Tor or firewall rule is needed for it.
// This is language-level isolation, not an OS sandbox: it is not bubblewrap and
// not a microVM, and it runs JavaScript only.
import { Worker } from 'node:worker_threads';
import { log } from './log.ts';

export interface SandboxResult { ok: boolean; output: string; value: string | null; error: string | null; ms: number; truncated: boolean }

export const LIMITS = { timeoutMs: 3000, memoryBytes: 32 * 1024 * 1024, maxOutput: 16 * 1024, maxCode: 32 * 1024 };

export const POLICY = [
  ['Engine', 'QuickJS (WebAssembly) in a worker thread'],
  ['Filesystem', 'none'],
  ['Network', 'none (no socket or fetch API exists inside)'],
  ['Processes', 'none'],
  ['Host objects', 'console.log only'],
  ['Memory', `${LIMITS.memoryBytes / 1048576} MiB`],
  ['Time', `${LIMITS.timeoutMs / 1000} s, then the worker is killed`],
];

const WORKER = new URL('./sandbox-worker.ts', import.meta.url);

export function runJs(code: string): Promise<SandboxResult> {
  if (typeof code !== 'string' || !code.trim()) return Promise.resolve({ ok: false, output: '', value: null, error: 'empty code', ms: 0, truncated: false });
  if (code.length > LIMITS.maxCode) return Promise.resolve({ ok: false, output: '', value: null, error: 'code too long', ms: 0, truncated: false });
  return new Promise(resolve => {
    const t0 = Date.now();
    const w = new Worker(WORKER, {
      workerData: { code, timeoutMs: LIMITS.timeoutMs, memoryBytes: LIMITS.memoryBytes, maxOutput: LIMITS.maxOutput },
      resourceLimits: { maxOldGenerationSizeMb: 96, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
      env: {}, // no environment variables in the worker
      stdout: true, stderr: true,
    });
    let done = false;
    const finish = (r: SandboxResult) => { if (done) return; done = true; clearTimeout(kill); w.terminate(); log('sandbox.run', { ok: r.ok, ms: r.ms }); resolve(r); };
    const kill = setTimeout(() => finish({ ok: false, output: '', value: null, error: 'time limit exceeded', ms: Date.now() - t0, truncated: false }), LIMITS.timeoutMs + 2000);
    w.once('message', (m: any) => finish({ ok: !m.error, output: m.output, value: m.value, error: m.error, ms: m.ms, truncated: m.truncated }));
    w.once('error', () => finish({ ok: false, output: '', value: null, error: 'sandbox failure', ms: Date.now() - t0, truncated: false }));
    w.once('exit', () => finish({ ok: false, output: '', value: null, error: 'sandbox exited', ms: Date.now() - t0, truncated: false }));
  });
}

let health: { available: boolean; reason: string } | null = null;
/** Probes the sandbox once: the engine must load and a trivial program must run. */
export async function sandboxHealth() {
  if (health) return health;
  const r = await runJs('console.log(1 + 1)');
  health = r.ok && r.output.trim() === '2'
    ? { available: true, reason: 'QuickJS WebAssembly sandbox: JavaScript only, no filesystem, network or processes' }
    : { available: false, reason: `sandbox engine failed to start (${r.error})` };
  return health;
}

/** Tool definition offered to the remote model when the agent runtime is enabled. */
export const TOOLS = [{
  type: 'function',
  function: {
    name: 'run_js',
    description: 'Run JavaScript in an isolated sandbox and get what it prints with console.log. No network, no filesystem, no timers; 3 s and 32 MiB limits. Use it for calculations, parsing and data transformation.',
    parameters: { type: 'object', properties: { code: { type: 'string', description: 'JavaScript source. Print results with console.log.' } }, required: ['code'] },
  },
}];
