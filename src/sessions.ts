// Conversations. Each one owns a Tor isolation identity, its placeholder map and
// its sanitized transcript. Everything lives in memory only and is wiped on end
// or after inactivity; nothing here is ever written to disk or logs.
import crypto from 'node:crypto';
import { newIdentity } from './tor.ts';
import type { PlaceholderMap } from './sanitizer.ts';

export interface Turn { role: 'user' | 'assistant'; content: string }
export interface Preview { text: string; createdAt: number; digest: string }

export class Session {
  id = crypto.randomBytes(16).toString('hex');
  torIdentity = newIdentity();
  createdAt = Date.now();
  lastUsed = Date.now();
  placeholders: PlaceholderMap = {};
  history: Turn[] = [];             // what the provider has seen: sanitized user turns + replies
  sanitizedByDigest = new Map<string, string>(); // original user turn digest -> sanitized text (for /v1 clients)
  digests: string[] = [];           // digests of the last /v1 request's messages, for prefix continuity
  previews = new Map<string, Preview>();
  requests = 0;
  routedVia: 'tor' | 'direct' | null = null;
  busy: AbortController | null = null;

  touch() { this.lastUsed = Date.now(); }
  newCircuit() { this.torIdentity = newIdentity(); }
  publicView() {
    return { id: this.id, createdAt: new Date(this.createdAt).toISOString(), lastUsed: new Date(this.lastUsed).toISOString(), turns: this.history.length, requests: this.requests, routedVia: this.routedVia, busy: !!this.busy };
  }
  wipe() {
    this.busy?.abort();
    this.history.length = 0;
    this.sanitizedByDigest.clear();
    this.previews.clear();
    for (const k of Object.keys(this.placeholders)) delete this.placeholders[k];
    this.torIdentity = '';
  }
}

export const digest = (v: unknown) => crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');

export class SessionManager {
  sessions = new Map<string, Session>();
  max = 64;
  idleMs = 2 * 60 * 60 * 1000;
  timer: NodeJS.Timeout;
  constructor() { this.timer = setInterval(() => this.sweep(), 60_000); this.timer.unref(); }

  create(): Session {
    if (this.sessions.size >= this.max) this.sweep(true);
    const s = new Session();
    this.sessions.set(s.id, s);
    return s;
  }
  get(id: unknown): Session | null {
    if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) return null;
    const s = this.sessions.get(id) || null;
    s?.touch();
    return s;
  }
  end(id: string): boolean {
    const s = this.sessions.get(id);
    if (!s) return false;
    s.wipe();
    this.sessions.delete(id);
    return true;
  }
  sweep(force = false) {
    const now = Date.now();
    const order = [...this.sessions.values()].sort((a, b) => a.lastUsed - b.lastUsed);
    for (const s of order) {
      if (now - s.lastUsed > this.idleMs || (force && this.sessions.size >= this.max && !s.busy)) this.end(s.id);
    }
  }
  /** OpenAI-compatible clients send whole transcripts: a request continues the session whose last transcript is its prefix. */
  matchPrefix(digests: string[]): Session | null {
    for (const s of this.sessions.values()) {
      if (s.digests.length && s.digests.length < digests.length && s.digests.every((d, i) => d === digests[i])) return s;
    }
    return null;
  }
  endAll() { for (const id of [...this.sessions.keys()]) this.end(id); clearInterval(this.timer); }
}
