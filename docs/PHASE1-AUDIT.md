# PARANOID — Phase 1 audit (2026-11-04)

## 1. Existing PARANOID repository (`~/paranoid2`)

| Item | Finding |
|---|---|
| Stack | Static mirror of a Framer template. No Next.js, no React source, no TypeScript. `build/build.js` rewrites curl-ed SSR HTML (`src/`) and Framer bundles (`orig/sites/`) into `site/`. |
| Routes | `/` (Framer home, rebranded), `/app` (hand-written demo console, `app/app.html`). 34 template routes removed and redirected to `/` in `site/vercel.json`. |
| Backend | None. No API routes, no server actions, no functions. |
| Auth | None. |
| Wallet / payments | None. |
| Chat / agent UI | None. `/app` is a demo console: sanitization is real (regex rules in the browser); vault, proofs, Tor circuits, cover traffic and runtime policy are simulated and labelled "Simulated". |
| Deployment | Vercel project `paranoid2` (team `draftsifys-projects`), static output from `site/`, `cleanUrls`. |
| Secrets | None in the repo. |
| Simulated UI | Home page dashboards (Payment Console, Network Isolation, Traffic Obfuscation) are marketing illustrations; `/app` sections 04–08. |

Consequence: the backend is new code, and the hosted Vercel site can only be a frontend/documentation surface. Prompts and wallet state must never go through Vercel.

## 2. Upstream references (cloned read-only in `upstream/`)

- `ethereum/zkapi` main @ `6fb229a` (2026-11-02), version 0.2.0.
- `vbuterin/zkapi` `feat/client-concession-local` @ `0fb263b` (2026-10-16), 263 commits ahead of `045b444`.

### Confirmed capabilities

| Capability | Where | Notes |
|---|---|---|
| OpenAI-compatible local daemon | `zkapi-clientd` (Go) | `127.0.0.1:8787`, `GET /v1/models`, `POST /v1/chat/completions` (SSE passthrough), `GET /healthz`, `/admin/*` (funding, withdrawal, escape). Loopback only; rejects any request with an `Origin` header (no direct browser access). |
| Tor routing + per-conversation isolation | `internal/relay` | External Tor daemon on `tor://127.0.0.1:9050` with `IsolateSOCKSAuth`; SOCKS5 username = random 32-byte identity per conversation; remote DNS; no direct fallback; HTTPS only. Conversation = message-prefix continuity (SHA-256 of canonical messages). |
| Cover traffic | `internal/cover` | Poisson GETs to user-supplied HTTPS URLs (none by default), rate 0.01–5/s, concurrency 1–8, each worker its own Tor identity, 64 KiB cap. **No byte or spending budget in code** (docs warn >1 GiB/h). |
| Local prompt rewriter | `internal/rewriter` | Any OpenAI-compatible endpoint, HTTP allowed on loopback only, temperature 0, fail-closed (HTTP 502 `rewrite_failed`, original never sent). No default model (docs use `qwen3.8-flash-next` on `localhost:8012`, not a public identifier). |
| zkAPI payments | `zkapi-walletd` (Rust companion, `crates/zkapi-companion`) | Groth16/BN254 (arkworks) proof per lease; lease = short-lived OpenRouter key; settlement and signed state; mutual close / escape withdrawals. |
| Sandbox | — | **Not found upstream.** No bubblewrap, microVM or torsocks code. |

### Deployment status (blocking facts)

- **Mainnet: not deployed.** `deployments/mainnet.json` is `"deployment_status": "not_deployed"`, null addresses.
- **Sepolia staging only**: vault `0x67EB750d9C0D63A99684AC3F3e65f0C610276993` (manifest `docs/deployments/sepolia-leaf-v4-20261020.json`), protocol server `https://zkapi-sepolia.openanonymity.ai/v0.4`, may require a shared testnet password (`X-ZKAPI-Testnet-Password`).
- **Proving keys are development keys** (`setup_id: "dev"`, single-party). The MPC ceremony (`v2-concession`, `mpc-1`) has not run. Release builds refuse to start without it. Anyone holding the dev setup could forge proofs: test funds only.
- Inference upstream is **OpenRouter only** (lease keys); no direct OpenAI/Anthropic path.
- Upstream states: experimental, not a production release, no independent audit of vault, adapter, paymaster or Poseidon runtime.

### Platform

- `zkapi-clientd`: Linux and macOS only (`syscall.Flock`, `_linux.go`/`_darwin.go` files, release targets linux/darwin). No Windows support.
- Toolchain: Go 1.25+, Rust 1.99.0 (+ OpenSSL dev libs for the companion), Foundry for local chains, Node ≥ 24.
- Licenses: `zkapi-clientd` MIT (Open Anonymity Team); Rust workspace MIT OR Apache-2.0. Attribution to be kept in `docs/` and the local runtime's NOTICE.

## 3. This machine

Windows 11, no WSL, no Docker, no Go, no Rust, no Tor, no Ollama, no bubblewrap. Node 24, Python 3.12, git, gh. RTX 5070 12 GB, 16 GB RAM (enough for a 4–8B local sanitizer model).

## 4. Compatibility matrix

| Subsystem | Upstream reuse | Can run here today | Path |
|---|---|---|---|
| OpenAI-compatible gateway | clientd | No (Linux/macOS) | WSL2 Ubuntu, or a PARANOID gateway in Node that runs natively |
| Tor isolation | clientd relay | Tor runs on Windows; clientd does not | WSL2 (Tor + clientd) |
| Local sanitizer | clientd rewriter + local model server | Ollama/llama.cpp run on Windows with the GPU | Model on Windows host, reached via loopback |
| Cover traffic | clientd cover | No | WSL2; PARANOID wrapper adds byte/request budgets missing upstream |
| zkAPI payments | walletd companion | No (Rust, Linux) | WSL2; **Sepolia test ETH only**, dev keys |
| Sandbox | none | bubblewrap needs Linux | WSL2 bubblewrap; microVM not planned |
| Chat UI | — | Yes | Served by the local PARANOID daemon on loopback (same origin), same design as the site |

## 5. Proposed architecture

```
Browser ── http://127.0.0.1:7700 (PARANOID daemon, Node/TS, serves the chat UI)
              │  sessions, privacy profiles, fail-closed checks, budgets,
              │  sanitizer preview/approve, status APIs (/api/privacy/*, /api/payment/*)
              ├── local model server (Ollama, GPU) ── sanitizer preview
              ├── zkapi-clientd 127.0.0.1:8787 (pinned commit) ── Tor 9050 (IsolateSOCKSAuth)
              │        └── zkapi-walletd (proofs, notes, state)  ── Sepolia staging server
              │        └── OpenRouter (lease key, through Tor)
              └── bubblewrap sandbox (agent runtime, egress only via Tor)
Vercel site: marketing + docs + "run locally" instructions. Never sees prompts or wallet state.
```

The browser talks only to the PARANOID daemon on loopback (same origin, token-protected state changes); the daemon talks to clientd, which refuses browser origins by design.
