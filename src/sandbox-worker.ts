// Runs inside a worker thread. The guest code executes in QuickJS compiled to
// WebAssembly: it has no filesystem, no network, no processes, no timers and no
// host objects. The only capability it receives is console.log, which appends
// strings to a capped buffer.
import { parentPort, workerData } from 'node:worker_threads';
import { newQuickJSWASMModuleFromVariant, shouldInterruptAfterDeadline } from 'quickjs-emscripten-core';
import variant from '@jitl/quickjs-wasmfile-release-sync';

const { code, timeoutMs, memoryBytes, maxOutput } = workerData as { code: string; timeoutMs: number; memoryBytes: number; maxOutput: number };

const QuickJS = await newQuickJSWASMModuleFromVariant(variant as any);
const runtime = QuickJS.newRuntime();
runtime.setMemoryLimit(memoryBytes);
runtime.setMaxStackSize(512 * 1024);
runtime.setInterruptHandler(shouldInterruptAfterDeadline(Date.now() + timeoutMs));
const ctx = runtime.newContext();

let output = '';
let truncated = false;
const append = (s: string) => {
  if (output.length + s.length > maxOutput) { output += s.slice(0, Math.max(0, maxOutput - output.length)); truncated = true; }
  else output += s;
};
const consoleObj = ctx.newObject();
const log = ctx.newFunction('log', (...args) => {
  append(args.map(a => { const v = ctx.dump(a); return typeof v === 'string' ? v : JSON.stringify(v); }).join(' ') + '\n');
});
ctx.setProp(consoleObj, 'log', log);
ctx.setProp(consoleObj, 'error', log);
ctx.setProp(ctx.global, 'console', consoleObj);
log.dispose();
consoleObj.dispose();

const started = Date.now();
const result = ctx.evalCode(code, 'agent.js');
let value: unknown = undefined, error: string | null = null;
if (result.error) {
  const e = ctx.dump(result.error);
  error = typeof e === 'object' && e ? `${e.name || 'Error'}: ${e.message || ''}` : String(e);
  result.error.dispose();
} else {
  try { value = ctx.dump(result.value); } catch { value = '[unserializable]'; }
  result.value.dispose();
}
const ms = Date.now() - started;
ctx.dispose();
runtime.dispose();
parentPort!.postMessage({ output, truncated, value: value === undefined ? null : JSON.stringify(value)?.slice(0, maxOutput) ?? null, error, ms });
