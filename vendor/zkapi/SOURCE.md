# Vendored zkAPI browser SDK

- Source: https://github.com/ethereum/zkapi @ 6fb229af085f3156b5f25466c20de605cdcac476 (main), `npm run build:browser` (= `node scripts/build-sdk.mjs --network sepolia`), checked out with LF line endings so the SDK's own asset integrity check passes.
- `v2c/sdk.js`: esbuild 0.27.2 bundle of `sdk/index.js` (configureBrowserSdk, zkapiClient, CHAT_SPENDING_TIER_USD).
- Other files: the build output unchanged; hashes in `v2c/sdk-assets.json`.
- Network: Sepolia staging, `setup_id: "dev"` (single-party development proving keys). Test funds only.
- License: MIT OR Apache-2.0 (zkAPI workspace). Not affiliated with the Ethereum Foundation or Open Anonymity.
- Host change: `v2c/browser-config.json` sets `deployment_manifest_url` and `allowed_deployment_manifest_urls` to `https://zkapi-sepolia.openanonymity.ai/v0.4/config.json`, the operator manifest named in `docs/deployments/sepolia-leaf-v4-20261020.md` (the repository profile leaves it null for each host to set). The SDK still requires the served manifest to equal the build-pinned `trusted_deployment`.
