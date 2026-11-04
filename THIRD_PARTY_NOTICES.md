# Third-party notices

## zkapi-clientd (ported logic)

Source: https://github.com/vbuterin/zkapi, branch `feat/client-concession-local` @ `0fb263b`. Ported: SOCKS5 isolation handshake, conversation prefix continuity, rewrite response contract and style-reconstruction wording, cover-traffic behaviour. See the files in `src/` that cite it.

```
MIT License

Copyright (c) 2026 Open Anonymity Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## zkAPI browser SDK (vendored in `vendor/zkapi/v2c`)

Source: https://github.com/ethereum/zkapi @ `6fb229a`. The workspace declares `MIT OR Apache-2.0` (root `Cargo.toml`); the SDK's own `package.json` has no license field. Build details and the one host change are in `vendor/zkapi/SOURCE.md`.

## QuickJS via quickjs-emscripten

`quickjs-emscripten-core@0.32.0` and `@jitl/quickjs-wasmfile-release-sync@0.32.0`, MIT License (installed by `npm install`, not vendored).

## Tor

Not included. `scripts/install-tor.mjs` downloads the official Tor Expert Bundle and verifies its signature.

PARANOID is not affiliated with Vitalik Buterin, the Ethereum Foundation, Open Anonymity or the Tor Project.
