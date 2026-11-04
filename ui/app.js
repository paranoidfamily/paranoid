// PARANOID chat UI. Talks only to the local daemon (same origin). Prompts and
// replies stay in this page's memory: nothing is written to browser storage.
(function () {
  'use strict';
  const TOKEN = document.querySelector('meta[name=paranoid-token]').content;
  const $ = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const REQUIRED = { standard: ['provider'], private: ['provider', 'tor', 'sanitizer'], paranoid: ['provider', 'tor', 'sanitizer', 'payment_zkapi', 'cover_traffic', 'sandbox'] };
  const LABEL = { provider: 'Model', tor: 'Tor', sanitizer: 'Sanitizer', cover_traffic: 'Cover', payment_zkapi: 'zkAPI', sandbox: 'Sandbox' };

  async function api(method, path, body) {
    const r = await fetch(path, { method, headers: { authorization: 'Bearer ' + TOKEN, ...(body ? { 'content-type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error?.message || 'HTTP ' + r.status); e.code = j.error?.code; e.missing = j.error?.missing; throw e; }
    return j;
  }

  // ------------------------------------------------------------ state
  let status = null;
  const convs = []; // {id, title, messages:[{role, text, sent?, meta?}]}
  let current = null;
  let pending = null; // {original, preview}
  let streaming = null;

  // ------------------------------------------------------------ status, profile, banner
  async function refresh(force) {
    try { status = await api('GET', '/api/status' + (force ? '?refresh=1' : '')); } catch (e) { status = null; }
    render();
  }
  function render() {
    const prof = status?.profile;
    for (const b of $('profiles').children) b.setAttribute('aria-pressed', b.dataset.p === prof);
    const req = REQUIRED[prof] || [];
    $('pills').innerHTML = status ? Object.entries(status.components).map(([k, c]) =>
      `<span class="pill ${c.ready ? 'ok' : ''} ${req.includes(k) ? 'req' : ''}" title="${esc(c.detail)}"><b></b>${LABEL[k]}</span>`).join('') : '';
    const b = $('banner');
    if (!status) { b.hidden = false; b.innerHTML = '<b>Local daemon unreachable.</b> Start it with <code>npm start</code> in paranoid2/local.'; }
    else if (!status.ready) {
      b.hidden = false;
      b.innerHTML = `<b>${prof[0].toUpperCase() + prof.slice(1)} mode is unavailable — nothing will be sent.</b><ul>${status.missing.map(m => `<li>${LABEL[m]}: ${esc(status.components[m].detail)}</li>`).join('')}</ul>`;
    } else b.hidden = true;
    $('go').disabled = !status || !!streaming;
    $('review-send').disabled = $('review-bypass').disabled = !status?.ready;
    $('route-hint').textContent = !status ? '' : prof === 'standard' ? 'Standard: direct connection, your IP and API key are visible to the provider.' : prof === 'private' ? 'Private: sanitized locally, sent through this conversation\'s Tor circuit. Payment uses your API key.' : 'Paranoid: every layer required.';
  }
  $('profiles').addEventListener('click', async e => {
    const p = e.target.closest('[data-p]')?.dataset.p; if (!p) return;
    try { await api('POST', '/api/config/profile', { profile: p }); } catch (err) { alert(err.message); }
    refresh(true);
  });

  // ------------------------------------------------------------ conversations
  async function newConv() {
    const s = await api('POST', '/api/sessions');
    const c = { id: s.id, title: 'New conversation', messages: [] };
    convs.unshift(c); select(c);
  }
  function select(c) { current = c; closeReview(); renderConvs(); renderThread(); $('input').focus(); }
  function renderConvs() {
    $('convs').innerHTML = convs.map(c => `<div class="conv ${c === current ? 'active' : ''}" data-id="${c.id}"><span>${esc(c.title)}</span><button data-end="${c.id}" title="End and wipe">×</button></div>`).join('');
  }
  $('convs').addEventListener('click', async e => {
    const end = e.target.closest('[data-end]');
    if (end) {
      await api('DELETE', '/api/sessions/' + end.dataset.end).catch(() => {});
      const i = convs.findIndex(c => c.id === end.dataset.end); convs.splice(i, 1);
      if (current?.id === end.dataset.end) { current = convs[0] || null; if (!current) await newConv(); }
      renderConvs(); renderThread(); return;
    }
    const row = e.target.closest('[data-id]'); if (row) select(convs.find(c => c.id === row.dataset.id));
  });
  $('new-chat').addEventListener('click', newConv);

  function renderThread() {
    const t = $('thread');
    if (!current || !current.messages.length) { t.innerHTML = $('empty').outerHTML.replace(' hidden', ''); return; }
    t.innerHTML = current.messages.map((m, i) => {
      if (m.role === 'user') return `<div class="msg user"><div class="who">You <button class="toggle" data-sent="${i}">${m.showSent ? 'hide' : 'show'} what was sent</button></div><div class="body">${esc(m.text)}</div>${m.showSent ? `<div class="sent">${esc(m.sent)}</div>` : ''}<div class="meta">${esc(m.meta || '')}</div></div>`;
      if (m.role === 'error') return `<div class="msg error"><div class="who">Not sent</div><div class="body">${esc(m.text)}</div></div>`;
      if (m.role === 'tool') return `<div class="msg tool"><div class="who">Sandbox · ${esc(m.name)} · ${m.ok ? 'ok' : 'failed'}</div><div class="body"><b>${m.name === 'run_shell' ? 'script' : 'code'}</b>\n${esc(m.code)}\n\n<b>output</b>\n${esc(m.output || '(nothing printed)')}</div></div>`;
      return `<div class="msg"><div class="who">${esc(status?.model || 'Model')}</div><div class="body">${esc(m.text)}${m.live ? '▍' : ''}</div><div class="meta">${esc(m.meta || '')}</div></div>`;
    }).join('');
    t.scrollTop = t.scrollHeight;
  }
  $('thread').addEventListener('click', e => {
    const b = e.target.closest('[data-sent]'); if (!b) return;
    const m = current.messages[+b.dataset.sent]; m.showSent = !m.showSent; renderThread();
  });

  // ------------------------------------------------------------ review + send
  $('composer').addEventListener('submit', async e => {
    e.preventDefault();
    const text = $('input').value.trim();
    if (!text || !current || streaming) return;
    $('go').disabled = true; $('go').textContent = 'Sanitizing…';
    try {
      const p = await api('POST', '/api/privacy/sanitizer/preview', { sessionId: current.id, text });
      pending = { original: text, preview: p };
      $('review-text').value = p.sanitized;
      const entries = Object.entries(p.placeholders);
      $('review-map').innerHTML = entries.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');
      $('review-empty').hidden = entries.length > 0;
      $('review-meta').textContent = `${p.rewritten ? 'rewritten by local model' : 'rules only'} · ${p.strictness}${p.sanitizerReady ? '' : ' · local model unavailable'}`;
      $('review-bypass').hidden = status?.profile !== 'standard';
      $('review').hidden = false;
      $('review-send').focus();
    } catch (err) {
      current.messages.push({ role: 'error', text: err.message }); renderThread();
    } finally { $('go').textContent = 'Review'; render(); }
  });
  function closeReview() { pending = null; $('review').hidden = true; }
  $('review-cancel').addEventListener('click', closeReview);
  $('review-send').addEventListener('click', () => sendApproved(false));
  $('review-bypass').addEventListener('click', () => { if (confirmBypass()) sendApproved(true); });
  function confirmBypass() { return window.confirm('Send your original prompt, without sanitization, directly to the provider?'); }

  async function sendApproved(bypass) {
    if (!pending) return;
    const conv = current, edited = $('review-text').value;
    const userMsg = { role: 'user', text: pending.original, sent: bypass ? pending.original : edited, meta: bypass ? 'sent unsanitized (approved)' : 'sanitized locally' };
    const reply = { role: 'assistant', text: '', live: true, meta: '' };
    conv.messages.push(userMsg, reply);
    if (conv.title === 'New conversation') conv.title = pending.original.slice(0, 40);
    const body = bypass ? { sessionId: conv.id, bypassText: pending.original } : { sessionId: conv.id, previewId: pending.preview.previewId, edited: edited !== pending.preview.sanitized ? edited : undefined };
    body.agent = $('agent').checked;
    closeReview(); $('input').value = ''; renderConvs(); renderThread();
    streaming = conv; $('stop').hidden = false; render();
    let access = null;
    try {
      if (status?.profile === 'paranoid' || $('zk-use').checked) {
        if (!zk) throw new Error('Pay with zkAPI is on: start and connect the zkAPI wallet in Settings first.');
        reply.meta = 'creating a private zkAPI key…'; renderThread();
        // one proof-backed ephemeral key per conversation; the SDK rotates it when the conversation changes
        access = await zk.acquireInferenceAccess(conv.id);
        body.lease = { apiKey: access.apiKey, baseUrl: access.baseUrl };
        reply.meta = '';
      }
      const r = await fetch('/api/chat/send', { method: 'POST', headers: { authorization: 'Bearer ' + TOKEN, 'content-type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok || !r.headers.get('content-type')?.includes('event-stream')) { const j = await r.json().catch(() => ({})); throw new Error(j.error?.message || 'HTTP ' + r.status); }
      const reader = r.body.getReader(), dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read(); if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 2);
          if (!line.startsWith('data: ')) continue;
          const ev = JSON.parse(line.slice(6));
          if (ev.type === 'delta') { reply.text += ev.text; if (current === conv) renderThread(); }
          if (ev.type === 'tool') { conv.messages.splice(conv.messages.indexOf(reply), 0, { role: 'tool', name: ev.name, code: ev.code, ok: ev.ok, output: ev.output }); if (current === conv) renderThread(); }
          if (ev.type === 'done') reply.meta = `via ${ev.via === 'tor' ? 'Tor (own circuit)' : 'direct connection'} · paid with ${ev.paidWith === 'zkapi-lease' ? 'zkAPI (unlinked)' : 'your API key'}${ev.toolRuns ? ` · ${ev.toolRuns} sandbox run${ev.toolRuns > 1 ? 's' : ''}` : ''}${ev.usage ? ` · ${ev.usage.prompt_tokens}+${ev.usage.completion_tokens} tokens` : ''}`;
          if (ev.type === 'error') throw new Error(ev.message);
        }
      }
    } catch (err) {
      if (!reply.text) { conv.messages.splice(conv.messages.indexOf(reply), 1); userMsg.meta = 'not answered'; }
      conv.messages.push({ role: 'error', text: err.message });
    } finally {
      access?.release(); // lets the SDK settle the lease once the stream is over
      reply.live = false; streaming = null; $('stop').hidden = true;
      renderThread(); refresh();
    }
  }

  // ------------------------------------------------------------ zkAPI wallet (official browser SDK)
  let zk = null;
  const b64 = bytes => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  /** The SDK's network goes through the daemon, which sends it over Tor to the SDK's own trusted hosts only. */
  async function relayTransport(url, init = {}) {
    let body;
    if (init.body != null) {
      const b = init.body;
      body = typeof b === 'string' ? new TextEncoder().encode(b) : b instanceof ArrayBuffer ? new Uint8Array(b) : ArrayBuffer.isView(b) ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength) : new Uint8Array(await new Response(b).arrayBuffer());
    }
    const headers = {};
    new Headers(init.headers || {}).forEach((v, k) => { headers[k] = v; });
    const r = await fetch('/api/zkapi/relay', { method: 'POST', signal: init.signal, headers: { authorization: 'Bearer ' + TOKEN, 'content-type': 'application/json' },
      body: JSON.stringify({ url: String(url), method: init.method || 'GET', headers, bodyB64: body ? b64(body) : undefined }) });
    const j = await r.json();
    if (!r.ok) throw new TypeError(j.error?.message || 'zkAPI relay failed');
    const nullBody = [101, 204, 205, 304].includes(j.status);
    return new Response(nullBody ? null : unb64(j.bodyB64), { status: j.status, headers: j.headers });
  }
  function askTestnetPassword({ authenticate, signal }) {
    return new Promise((resolve, reject) => {
      $('settings').hidden = false; $('zk-pw').hidden = false; $('zk-pw-input').value = ''; $('zk-pw-input').focus();
      $('zk-op').textContent = 'The Sepolia operator requires its shared testnet password.';
      const ctl = new AbortController();
      const done = () => { $('zk-pw').hidden = true; $('zk-pw-ok').onclick = $('zk-pw-cancel').onclick = null; signal?.removeEventListener('abort', onAbort); };
      const onAbort = () => { ctl.abort(); done(); reject(new DOMException('Cancelled', 'AbortError')); };
      signal?.addEventListener('abort', onAbort);
      $('zk-pw-ok').onclick = async () => {
        try { await authenticate($('zk-pw-input').value, { signal: ctl.signal }); $('zk-pw-input').value = ''; $('zk-op').textContent = 'Testnet password accepted.'; done(); resolve(); }
        catch (e) { $('zk-op').textContent = 'Password rejected: ' + (e.message || 'try again'); }
      };
      $('zk-pw-cancel').onclick = () => { ctl.abort(); done(); reject(new DOMException('Cancelled', 'AbortError')); };
    });
  }
  function renderZk(snap) {
    if (!snap) return;
    const note = snap.wallet?.note;
    const svc = snap.config?.service;
    const parts = [];
    parts.push(snap.initialized ? 'Wallet started' : 'Starting…');
    if (snap.walletAddress) parts.push('account ' + snap.walletAddress.slice(0, 6) + '…' + snap.walletAddress.slice(-4));
    parts.push(note ? `private balance ${(Number(note.current_balance) / 1e9).toFixed(6)} ETH (note #${note.note_id})` : 'no private balance yet');
    if (svc && svc.available === false) parts.push(svc.message || 'operator unavailable: exits only');
    if (snap.lastError) parts.push('last error: ' + (snap.lastError.message || snap.lastError.code || 'unknown'));
    $('zk-status').textContent = parts.join(' · ');
  }
  $('zk-init').addEventListener('click', async () => {
    if (zk) return renderZk(zk.snapshot());
    $('zk-status').textContent = 'Loading the zkAPI SDK and its proof worker…';
    try {
      const sdk = await import('/zkapi/v2c/sdk.js');
      sdk.configureBrowserSdk({ configUrl: '/zkapi/v2c/browser-config.json', workerUrl: '/zkapi/v2c/assets/zkapiWasmWorker.js', transport: relayTransport, requestTestnetPassword: askTestnetPassword });
      zk = sdk.zkapiClient;
      zk.subscribe(renderZk);
      renderZk(await zk.init());
    } catch (e) { zk = null; $('zk-status').textContent = 'zkAPI wallet failed to start: ' + e.message; }
  });
  $('zk-connect').addEventListener('click', async () => {
    if (!zk) { $('zk-op').textContent = 'Start the wallet first.'; return; }
    if (!window.ethereum) { $('zk-op').textContent = 'No browser wallet found. Install MetaMask (or another EIP-1193 wallet) in this browser and switch it to Sepolia.'; return; }
    try { await zk.connectWallet(); renderZk(zk.snapshot()); } catch (e) { $('zk-op').textContent = e.message; }
  });
  $('zk-deposit').addEventListener('click', async () => {
    if (!zk) { $('zk-op').textContent = 'Start the wallet first.'; return; }
    const amount = $('zk-amount').value.trim();
    if (!/^\d+(\.\d{1,9})?$/.test(amount)) { $('zk-op').textContent = 'Enter an amount in ETH, e.g. 0.002 (minimum 0.001).'; return; }
    try { await zk.deposit(amount, s => { $('zk-op').textContent = typeof s === 'string' ? s : (s?.message || s?.phase || ''); }); $('zk-op').textContent = 'Deposit submitted. The private balance appears once it is confirmed.'; }
    catch (e) { $('zk-op').textContent = e.message; }
  });
  $('zk-withdraw').addEventListener('click', async () => {
    if (!zk) { $('zk-op').textContent = 'Start the wallet first.'; return; }
    try { await zk.withdraw('mutual', s => { $('zk-op').textContent = typeof s === 'string' ? s : (s?.message || s?.phase || ''); }); $('zk-op').textContent = 'Withdrawal submitted.'; }
    catch (e) { $('zk-op').textContent = e.message; }
  });
  $('stop').addEventListener('click', () => { if (streaming) api('POST', '/api/chat/cancel', { sessionId: streaming.id }).catch(() => {}); });
  $('input').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) $('composer').requestSubmit(); });

  // ------------------------------------------------------------ settings
  let allModels = [];
  async function openSettings() {
    $('settings').hidden = false;
    const [san, tor, cover, pay, sbx] = await Promise.all([
      api('GET', '/api/privacy/sanitizer/status'), api('GET', '/api/privacy/tor/status'), api('GET', '/api/privacy/cover-traffic/status'),
      api('GET', '/api/payment/status'), api('GET', '/api/sandbox/status')]);
    $('san-status').textContent = san.serverUp ? (san.ready ? `Ready: ${san.detail}` : san.detail) : 'No local model server on ' + 'the configured loopback address. Install Ollama and pull a model (see docs).';
    $('san-model').innerHTML = '<option value="">— local model —</option>' + san.models.map(m => `<option ${m === san.model ? 'selected' : ''}>${esc(m)}</option>`).join('');
    for (const b of $('strict').children) b.setAttribute('aria-pressed', b.dataset.s === san.strictness);
    $('tor-status').textContent = tor.verified ? 'Connected. Exit verified as a Tor relay. Each conversation uses its own circuit.' : !tor.installed && !tor.running ? 'Tor is not installed. Run node scripts/install-tor.mjs.' : (tor.error || 'Not verified yet.');
    const p = cover.policy;
    $('cover-urls').value = p.urls.join('\n'); $('cv-rate').value = p.ratePerMinute; $('cv-conc').value = p.concurrency; $('cv-req').value = p.maxRequestsPerHour; $('cv-mb').value = Math.round(p.maxBytesPerHour / 1048576); $('cv-stop').value = p.autoStopMinutes;
    showCover(cover);
    $('pay-status').textContent = status?.profile === 'paranoid' ? 'Paranoid mode pays only through zkAPI.' : 'Without “Pay requests with zkAPI”, requests use your OpenRouter API key, which OpenRouter can link to your account.';
    $('sbx-status').textContent = sbx.available ? 'Available. Turn on “Sandbox tools” next to the composer to let the model run JavaScript here.' : sbx.reason;
    $('sbx-policy').innerHTML = (sbx.policy || []).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');
    showBwrap(sbx.bubblewrap);
    if (zk) renderZk(zk.snapshot());
    $('model-hint').textContent = status?.model ? 'Selected: ' + status.model : 'No model selected.';
    loadModels();
  }
  function showBwrap(b) {
    if (!b) return;
    $('bw-on').checked = !!b.enabled;
    $('bw-status').textContent = !b.enabled ? 'Off. The model can only use run_js.' : b.available ? 'Isolation probe passed. With “Sandbox tools” on, the model may also call run_shell.' : 'Unavailable: ' + b.reason;
    $('bw-policy').innerHTML = b.available ? (b.policy || []).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('') : '';
  }
  $('bw-on').addEventListener('change', async e => {
    $('bw-status').textContent = 'Checking…';
    try { showBwrap((await api('POST', '/api/sandbox/bubblewrap', { enabled: e.target.checked })).bubblewrap); } catch (err) { $('bw-status').textContent = err.message; }
  });
  function showCover(c) { $('cv-status').textContent = c.running ? `running · ${c.sent} sent · ${(c.bytes / 1048576).toFixed(1)} MB · stops ${new Date(c.stopsAt).toLocaleTimeString()}` : c.stopReason ? 'stopped: ' + c.stopReason : 'stopped'; }
  async function loadModels() {
    try { allModels = (await api('GET', '/v1/models')).data.map(m => m.id); } catch (e) { $('model-hint').textContent = e.message; allModels = []; }
    fillModels();
  }
  function fillModels() {
    const f = $('model-filter').value.toLowerCase();
    const list = allModels.filter(m => m.toLowerCase().includes(f)).slice(0, 300);
    $('model').innerHTML = '<option value="">— remote model —</option>' + list.map(m => `<option ${m === status?.model ? 'selected' : ''}>${esc(m)}</option>`).join('');
  }
  $('model-filter').addEventListener('input', fillModels);
  $('model').addEventListener('change', async e => { if (e.target.value) { await api('POST', '/api/config/provider', { model: e.target.value }); $('model-hint').textContent = 'Selected: ' + e.target.value; refresh(); } });
  $('save-key').addEventListener('click', async () => {
    try { await api('POST', '/api/secrets/provider-key', { key: $('key').value.trim() }); $('key').value = ''; $('model-hint').textContent = 'Key stored.'; refresh(); loadModels(); } catch (e) { $('model-hint').textContent = e.message; }
  });
  $('del-key').addEventListener('click', async () => { await api('DELETE', '/api/secrets/provider-key'); $('model-hint').textContent = 'Key removed.'; refresh(); });
  $('san-model').addEventListener('change', async e => { const s = await api('POST', '/api/privacy/sanitizer/config', { model: e.target.value || null }); $('san-status').textContent = s.ready ? 'Ready: ' + s.detail : s.detail; refresh(true); });
  $('strict').addEventListener('click', async e => {
    const s = e.target.closest('[data-s]')?.dataset.s; if (!s) return;
    const r = await api('POST', '/api/privacy/sanitizer/config', { strictness: s });
    for (const b of $('strict').children) b.setAttribute('aria-pressed', b.dataset.s === s);
    $('san-status').textContent = r.ready ? 'Ready: ' + r.detail : r.detail; refresh(true);
  });
  $('tor-start').addEventListener('click', async () => {
    $('tor-status').textContent = 'Starting Tor and verifying the exit (up to 2 minutes)…';
    try { const t = await api('POST', '/api/privacy/tor/start'); $('tor-status').textContent = t.verified ? 'Connected. Exit verified as a Tor relay.' : t.error || 'Not verified.'; }
    catch (e) { $('tor-status').textContent = e.message; }
    refresh(true);
  });
  $('cv-save').addEventListener('click', async () => {
    try {
      showCover(await api('POST', '/api/privacy/cover-traffic/config', { urls: $('cover-urls').value.split('\n').map(s => s.trim()).filter(Boolean), ratePerMinute: +$('cv-rate').value, concurrency: +$('cv-conc').value, maxRequestsPerHour: +$('cv-req').value, maxBytesPerHour: +$('cv-mb').value * 1048576, autoStopMinutes: +$('cv-stop').value }));
    } catch (e) { $('cv-status').textContent = e.message; }
  });
  $('cv-start').addEventListener('click', async () => { try { showCover(await api('POST', '/api/privacy/cover-traffic/start')); } catch (e) { $('cv-status').textContent = e.message; } refresh(); });
  $('cv-stop-btn').addEventListener('click', async () => { showCover(await api('POST', '/api/privacy/cover-traffic/stop')); refresh(); });
  $('open-settings').addEventListener('click', openSettings);
  $('close-settings').addEventListener('click', () => { $('settings').hidden = true; refresh(true); });
  $('settings').addEventListener('click', e => { if (e.target === $('settings')) { $('settings').hidden = true; refresh(true); } });

  // ------------------------------------------------------------ init
  refresh(true).then(() => newConv().catch(() => {}));
  setInterval(() => refresh(), 15000);
})();
