# PARANOID local runtime

A loopback daemon that sits between you and a remote AI model. It sanitizes prompts on your machine, shows you exactly what will be sent, routes each conversation through its own Tor circuit, can run bounded cover traffic, and refuses to send anything when a layer your privacy profile requires is missing.

The public site (https://paranoid2.vercel.app) is marketing and documentation only. Prompts, keys and wallet state never go through it.

## Requirements (Windows, as tested)

- Node.js 24+ (runs the TypeScript sources directly, no build step). Two pinned dependencies for the agent sandbox, shipped in the download: `quickjs-emscripten-core@0.32.0` and `@jitl/quickjs-wasmfile-release-sync@0.32.0` (MIT).
- Ollama with a local model for sanitization: `winget install Ollama.Ollama`, then `ollama pull qwen3:8b` (≈5 GB, runs on a 12 GB GPU; any instruction-following model served on loopback works).
- Tor: `node scripts/install-tor.mjs --require-signature` downloads the official Tor Expert Bundle into the profile directory and refuses to install unless the SHA-256 matches the published sums file and that file's OpenPGP signature is valid for the Tor Browser signing key `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`.
- To pay for inference, either an OpenRouter API key (entered in the UI, stored with Windows DPAPI; OpenRouter can link it to you), or the zkAPI wallet: a browser wallet such as MetaMask on Sepolia, test ETH (minimum deposit 0.001), and the operator's shared testnet password.

## Run

```
git clone <this repository> && cd paranoid
npm install        # two pinned dependencies (QuickJS sandbox)
npm start          # = node src/main.ts
npm test           # 45 unit, integration and privacy-regression tests
```

Open http://127.0.0.1:7700/. Settings → paste the OpenRouter key, pick a remote model, pick the local sanitizer model.

The daemon starts and supervises `tor.exe` (`SocksPort 127.0.0.1:9050 IsolateSOCKSAuth`, `ControlPort 0`), then verifies through `check.torproject.org/api/ip` that traffic exits from a Tor relay.

Profile directory: `%APPDATA%\paranoid` (`config.json`, `local-token`, `secrets\*.dpapi`, `tor\`, `tor-data\`). Override with `PARANOID_HOME`.

## Privacy profiles

| Profile | Requires | Sends |
|---|---|---|
| Standard | model + key | directly; sanitization if available, or the original after explicit approval |
| Private | model + key, verified Tor, local sanitizer | sanitized text only, over the conversation's own Tor circuit |
| Paranoid | Private + zkAPI client + running cover traffic + agent sandbox | sanitized text over Tor, paid only with a zkAPI lease (your API key is never used); not available on `/v1`, which has no wallet |

A profile never downgrades itself. If a required layer is missing, the UI shows which one and why, and the API answers `409 privacy_policy` without contacting the provider.

## Request pipeline

1. **Rules** (deterministic): secrets/API keys, private keys, wallet addresses, emails, IBANs, Luhn-valid card numbers, IPs, phone numbers, street addresses, introduced names → `[EMAIL_1]`, `[CARD_1]`… Code blocks and inline code are set aside verbatim.
2. **Entity extraction** (local model): people and organizations tied to the writer (plus places and dates in *strict*) are listed by the model and masked deterministically (`[PERSON_1]`, `[ORG_1]`…). A person's first or last name alone gets the same placeholder.
3. **Rewrite** (local model): impersonal task statements, unnecessary personal context generalized, placeholders and code kept.
4. **Safety net**: rules run again on the rewrite; a reintroduced identifier is masked again.
5. **Review**: the UI shows the exact text that will be sent (editable) and what stays on the device. Nothing is sent until you approve.
6. **Send**: through the conversation's Tor identity (Private), with an allow-listed request body and no identifying headers.
7. **Rehydrate**: placeholders in the answer are restored locally, including across streaming chunks.

Any failure in steps 1–4 (model server down, invalid JSON, wrong count, timeout) aborts: the original is never sent (`502 sanitize_failed`).

Sanitization reduces what the provider learns. It is not anonymization: the provider still reads the sanitized task, and writing style or the task itself can identify you.

## OpenAI-compatible endpoint

`GET /v1/models`, `POST /v1/chat/completions` (SSE streaming) on `http://127.0.0.1:7700/v1`, bearer token from `%APPDATA%\paranoid\local-token`. Same pipeline without the review step (sanitization is automatic and fail-closed). Conversations are matched by transcript prefix (as in zkapi-clientd) or by the `X-Paranoid-Conversation` header; earlier user turns are replayed in their sanitized form and earlier replies are re-masked. Tool calling is refused.

## Security model

- Listens on `127.0.0.1` only; remote access is not supported.
- `Host` must be a loopback name (blocks DNS rebinding). Any request carrying an `Origin` other than the daemon's own, or `Sec-Fetch-Site: cross-site`, is refused: no website, including the public PARANOID site, can drive the daemon from a browser.
- Every API call needs the local bearer token (constant-time comparison). The UI receives it inside the page the daemon serves; the page is protected by `frame-ancestors 'none'`, `X-Frame-Options: DENY` and a CSP limiting scripts to the daemon itself.
- State-changing calls require `application/json` (no simple-form CSRF) and the token.
- Body limits (512 KiB API, 4 MiB `/v1`), header timeout, per-call provider and sanitizer timeouts.
- The sanitizer URL must be a numeric loopback address and the provider host must be in `provider.allowedHosts`; both are read only from `config.json`, never from the HTTP API (no SSRF through the API). Cover URLs must be public HTTPS hosts on port 443.
- The OpenRouter key is stored with DPAPI (CurrentUser), passed to PowerShell on stdin, never logged or returned.

## Data retention

- Conversations, sanitized transcripts, placeholder maps and previews live in daemon memory only. They are wiped when a conversation ends, after 2 hours idle, or when the daemon stops.
- The UI keeps messages in page memory only; nothing is written to browser storage.
- Logs are JSON lines on stdout with event names and counters only. The logger drops any field whose name suggests content, keys, tokens, identities or URLs.

## Cover traffic

GET requests through Tor to HTTPS URLs you configure (none by default), Poisson arrivals, each worker on its own circuit, responses capped at 64 KiB. Added over the upstream engine: hourly request and byte budgets and an automatic stop. Decoys never contain your content and never call a paid API (inference spend: 0). It makes simple timing and volume analysis harder; it does not defeat an adversary who observes most of the network.

## zkAPI payments

The wallet is the official browser SDK (`@openanonymity/zkapi-browser-sdk`, vendored from ethereum/zkapi @ `6fb229a`, see `vendor/zkapi/SOURCE.md`). It runs in the local UI page: private notes in that page's browser storage on this machine, Groth16 proofs in its WebAssembly worker, deposits and withdrawals signed by your browser wallet. The daemon serves the pinned SDK files and relays the SDK's network traffic over Tor (fresh identity per request, so payment traffic never shares a circuit with a conversation) to the hosts the SDK's own trusted deployment lists: the Sepolia protocol server, the Sepolia RPC, the verifier. Any other host is refused. The daemon never sees note secrets or proofs' witnesses; it holds a lease key only for the duration of the request it pays for.

Per request: the UI asks the SDK for a proof-backed ephemeral OpenRouter key bound to that conversation, sends it with the approved prompt, and releases it when the stream ends so the SDK can settle. In paranoid mode this is the only way to pay.

Limits, as stated upstream: Sepolia staging only, single-party development proving keys (whoever generated them could forge proofs), no audit, operator requires a shared testnet password; requests sharing a key are linkable; the provider still reads the sanitized prompt.

## Agent sandbox

With "Sandbox tools" on, the model may call `run_js`. The code runs in QuickJS compiled to WebAssembly, in a worker thread with a heap cap, a 32 MiB QuickJS memory limit, a 3 s interrupt deadline and a hard kill. The guest has no filesystem, network, process, timer or host object (only `console.log`): egress is impossible by construction. Tool output is re-masked before it goes back to the model; unknown tools are refused; at most 4 tool rounds per message. Client-side tools on `/v1` are refused. QuickJS is language-level isolation for JavaScript.

### bubblewrap (`run_shell`)

When bubblewrap is available and passes its isolation probe, the model also gets `run_shell`: a POSIX `sh` script run under `bwrap` with every namespace unshared (user, pid, network, ipc, uts, cgroup, mount), uid/gid 65534, all capabilities dropped, an empty environment, a read-only `/usr` (plus the `/bin`/`/lib` links and the linker cache), a fresh `/proc`, a minimal `/dev`, and an empty tmpfs `/tmp` as working directory. There is no home directory, no `/mnt` (so no Windows drives under WSL), no `/etc/passwd`, no resolver, and the network namespace holds only a loopback interface that is down. Limits: `ulimit` for 5 s CPU, 512 MiB address space, 8 MiB files, 64 open files and 128 processes; `timeout -s KILL` after 6 s inside Linux, and a kill from Node as a backstop. When bwrap's pid 1 dies the kernel kills everything left in the namespace. The script reaches the sandbox on stdin, never on a command line.

- **Linux**: `sudo apt install bubblewrap` (or your distribution's package).
- **Windows**: bubblewrap needs a Linux kernel, so it runs in WSL2: `wsl --install` (admin, then reboot), then inside the distribution `sudo apt install bubblewrap`. Set `sandbox.wslDistro` in `config.json` to use a distribution other than the default.

Before `run_shell` is offered, and again before each run, the daemon runs a probe inside the sandbox and checks the result: uid 65534, only `lo` in `/proc/net/dev`, no `/mnt`, `/home`, `/root`, `/run/WSL` or `/etc/passwd`, `/usr` not writable. If any check fails, or bwrap is missing, `run_shell` is not offered and calls to it are refused; nothing falls back to running on the host. Settings → Agent sandbox shows the probe result and can turn the shell off (`POST /api/sandbox/bubblewrap`).

Not a microVM: the sandbox shares the Linux kernel (WSL2's kernel on Windows), so a kernel exploit would escape it.

## Subsystem status (2026-11-04)

| Subsystem | Status | Evidence |
|---|---|---|
| Loopback daemon, sessions, profiles | Implemented and tested | `test/server.test.ts`, `test/privacy.test.ts` |
| Local sanitizer (rules + entity extraction + rewrite) | Implemented and tested; verified live with `qwen3:8b` on Ollama (1–3.5 s per message) | `test/sanitizer.test.ts`, manual runs |
| Tor routing and per-conversation isolation | Implemented and tested; verified live: one conversation keeps its exit, three conversations got three exits | `test/tor.test.ts`, manual run |
| Cover traffic | Implemented and tested; run live: 24 decoys through Tor in one minute, 0 failures, automatic stop | `test/privacy.test.ts`, manual run |
| Agent sandbox (QuickJS/WASM) | Implemented and tested: infinite loop interrupted, memory bomb stopped, no network/host APIs reachable | `test/privacy.test.ts`, manual run |
| zkAPI wallet | Implemented, **partially verified**: the SDK starts in full mode (operator manifest fetched and matched through Tor). Deposit, lease and withdrawal **not run**: they need your MetaMask, Sepolia ETH and the testnet password | `test/server.test.ts` (relay policy), browser run |
| OpenAI-compatible endpoint | Implemented and tested with a mock provider; **not yet run against OpenRouter** (needs a key) | `test/privacy.test.ts` |
| Chat UI | Implemented; review flow and wallet start verified in a browser; streaming send verified with a mock provider only | screenshots |
| bubblewrap shell (`run_shell`) | Implemented and tested with a stand-in process: policy flags, isolation probe, stdin-only script, time and output limits, gating in the agent loop. **Not yet run against a real bwrap**: this Windows machine has no WSL; the probe correctly reports it unavailable and the shell stays off. A live test runs automatically where bwrap exists | `test/bwrap.test.ts` |
| microVM | Not implemented | — |

## Third-party code and attribution

Logic ported from `zkapi-clientd` (github.com/vbuterin/zkapi, branch `feat/client-concession-local` @ `0fb263b`, MIT License, Copyright 2026 Open Anonymity Team): SOCKS5 isolation handshake (`internal/relay/socks5.go`), conversation prefix continuity (`internal/zkapi/conversation.go`), rewrite response contract and style-reconstruction wording (`internal/rewriter/rewriter.go`), cover-traffic behaviour (`internal/cover`). Vendored: the zkAPI browser SDK build (ethereum/zkapi, MIT OR Apache-2.0) and QuickJS via quickjs-emscripten (MIT). PARANOID is not affiliated with Vitalik Buterin, the Ethereum Foundation or Open Anonymity.
