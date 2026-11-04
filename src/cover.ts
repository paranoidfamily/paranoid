// Bounded cover traffic. Behaviour follows zkapi-clientd internal/cover (MIT,
// Open Anonymity Team): GET requests to user-configured HTTPS URLs only, Poisson
// arrivals from crypto randomness, each worker on its own Tor identity, responses
// capped at 64 KiB, arrivals dropped (not queued) when all workers are busy.
// Added here: hourly request and byte budgets and an automatic stop, which the
// upstream engine does not enforce. Decoys never carry user content and never
// call a paid inference API, so their inference spend is zero by construction.
import https from 'node:https';
import crypto from 'node:crypto';
import { TorAgent, newIdentity } from './tor.ts';
import { checkHttpsUrl, type Config } from './config.ts';
import { log } from './log.ts';

const CAP = 64 * 1024;

export interface CoverStatus {
  running: boolean; startedAt: string | null; stopsAt: string | null; stopReason: string | null;
  sent: number; failed: number; skipped: number; bytes: number;
  lastHour: { requests: number; bytes: number };
  policy: Config['cover'] & { inferenceSpendUsd: 0 };
}

function expDelay(ratePerMinute: number): number {
  const u = (crypto.randomInt(1, 2 ** 31) / 2 ** 31);
  return -Math.log(u) * 60_000 / ratePerMinute;
}

export class CoverEngine {
  cfg: Config['cover'];
  proxy: { host: string; port: number };
  running = false;
  startedAt: number | null = null;
  stopsAt: number | null = null;
  stopReason: string | null = null;
  sent = 0; failed = 0; skipped = 0; bytes = 0;
  window: { t: number; bytes: number }[] = [];
  workers: { identity: string; busy: boolean }[] = [];
  timer: NodeJS.Timeout | null = null;
  autoStop: NodeJS.Timeout | null = null;
  inflight = new Set<{ destroy: () => void }>();

  constructor(cfg: Config['cover'], proxy: { host: string; port: number }) { this.cfg = cfg; this.proxy = proxy; }

  configure(cfg: Config['cover']) { this.cfg = cfg; }

  private hourly() {
    const cut = Date.now() - 3_600_000;
    this.window = this.window.filter(w => w.t > cut);
    return { requests: this.window.length, bytes: this.window.reduce((s, w) => s + w.bytes, 0) };
  }

  start(torVerified: boolean) {
    if (this.running) return;
    if (!torVerified) throw new Error('cover traffic requires verified Tor routing');
    if (!this.cfg.urls.length) throw new Error('no cover URLs configured');
    this.cfg.urls.forEach(u => checkHttpsUrl(u));
    this.running = true;
    this.stopReason = null;
    this.startedAt = Date.now();
    this.stopsAt = this.startedAt + this.cfg.autoStopMinutes * 60_000;
    this.workers = Array.from({ length: this.cfg.concurrency }, () => ({ identity: newIdentity(), busy: false }));
    this.autoStop = setTimeout(() => this.stop('auto-stop'), this.cfg.autoStopMinutes * 60_000);
    log('cover.start', { workers: this.workers.length, ratePerMinute: this.cfg.ratePerMinute });
    this.schedule();
  }

  stop(reason = 'stopped') {
    if (!this.running) return;
    this.running = false;
    this.stopReason = reason;
    if (this.timer) clearTimeout(this.timer);
    if (this.autoStop) clearTimeout(this.autoStop);
    for (const r of this.inflight) r.destroy();
    this.inflight.clear();
    this.workers = [];
    log('cover.stop', { reason, sent: this.sent });
  }

  private schedule() {
    if (!this.running) return;
    this.timer = setTimeout(() => { this.fire(); this.schedule(); }, expDelay(this.cfg.ratePerMinute));
  }

  private fire() {
    const h = this.hourly();
    if (h.requests >= this.cfg.maxRequestsPerHour) { this.stop('request budget reached'); return; }
    if (h.bytes >= this.cfg.maxBytesPerHour) { this.stop('byte budget reached'); return; }
    const w = this.workers.find(x => !x.busy);
    if (!w) { this.skipped++; return; }
    w.busy = true;
    const url = new URL(this.cfg.urls[crypto.randomInt(this.cfg.urls.length)]);
    let got = 0;
    const entry = { t: Date.now(), bytes: 0 };
    this.window.push(entry);
    const req = https.request({ host: url.hostname, port: 443, path: url.pathname || '/', method: 'GET', agent: new TorAgent(this.proxy, w.identity), timeout: 20_000, headers: { 'user-agent': 'Mozilla/5.0', accept: '*/*' } }, res => {
      res.on('data', (d: Buffer) => { got += d.length; entry.bytes = got; if (got >= CAP) res.destroy(); });
      res.on('close', finish);
    });
    const handle = { destroy: () => req.destroy() };
    this.inflight.add(handle);
    let done = false;
    const self = this;
    function finish() {
      if (done) return; done = true;
      self.inflight.delete(handle);
      w.busy = false;
      self.bytes += got;
      if (got > 0) self.sent++; else self.failed++;
    }
    req.on('timeout', () => req.destroy());
    req.on('error', finish);
    req.on('close', finish);
    req.end();
  }

  status(): CoverStatus {
    return {
      running: this.running,
      startedAt: this.startedAt ? new Date(this.startedAt).toISOString() : null,
      stopsAt: this.running && this.stopsAt ? new Date(this.stopsAt).toISOString() : null,
      stopReason: this.stopReason,
      sent: this.sent, failed: this.failed, skipped: this.skipped, bytes: this.bytes,
      lastHour: this.hourly(),
      policy: { ...this.cfg, inferenceSpendUsd: 0 },
    };
  }
}
