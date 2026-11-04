// Privacy-minimizing structured logs: event names and counters only. Keys that
// could carry content or identifiers are dropped before writing, whatever the caller passes.
const FORBIDDEN = /prompt|content|message|text|response|key|token|secret|identity|password|auth|url|sanitized|original|note|witness/i;

export type LogFields = Record<string, string | number | boolean | null | undefined>;

export const sink = { write: (line: string) => process.stdout.write(line + '\n') };

export function log(event: string, fields: LogFields = {}) {
  const safe: LogFields = {};
  for (const [k, v] of Object.entries(fields)) {
    if (FORBIDDEN.test(k)) continue;
    if (typeof v === 'string' && v.length > 120) continue;
    safe[k] = v;
  }
  sink.write(JSON.stringify({ t: new Date().toISOString(), event, ...safe }));
}
