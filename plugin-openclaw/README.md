# TrustNet OpenClaw Plugin (v0.7 Local-First Migration)

This package is the OpenClaw enforcement surface for TrustNet.

v0.7 default target:
- `local-lite` (L0) local-first decisions with no mandatory chain dependency
- `local-verifiable` optional proof/root verification path

Current implementation status in this repo:
- mode-based config is implemented (`local-lite`, `local-verifiable`)
- `local-lite` is now the default and does not require chain RPC or RootRegistry config
- local SQLite trust store is implemented (`edges_latest`, `receipts`, `agents`)
- local decision engine module is implemented with Rust-equivalent scoring semantics (`TN-005`)
- anchored verification runs only in `local-verifiable` mode while `before_tool_call` still uses API decision compatibility flow (`TN-006` through `TN-009`)

The plugin uses OpenClaw lifecycle hooks:
- `before_tool_call`: map tool -> context, fetch decision/root, optionally verify anchoring (`local-verifiable`), enforce ALLOW/ASK/DENY
- `after_tool_call`: emit ActionReceipt via `trustnet receipt`
- `tool_result_persist`: attach TrustNet receipt metadata to persisted tool result messages

## Files

- `index.js`: production plugin runtime entrypoint
- `openclaw.plugin.json`: plugin manifest + config schema
- `tool_map.example.json`: deterministic tool -> context mapping
- `config.example.json5`: OpenClaw plugin config example
- `test/integration.test.js`: runtime integration tests (mock server + mock trustnet CLI)

## Requirements

- OpenClaw with plugin support (`openclaw.plugin.json` + package `openclaw.extensions` contract)
- `trustnet` CLI on PATH (or set `trustnetBinary` in plugin config)
- Node runtime with `node:sqlite` support for local trust store persistence
- reachable TrustNet API (`/v1/root`, `/v1/decision`) for current compatibility flow
- chain RPC URL, RootRegistry, and publisher address only when `mode: "local-verifiable"` is enabled

## Install in OpenClaw

1. Install plugin package:
```bash
openclaw plugins install file:./plugin-openclaw
```
2. Add plugin entry config in OpenClaw config.
3. Restart OpenClaw and check:
```bash
openclaw plugins list --json
openclaw plugins doctor
```

If config is missing or invalid, the plugin loads in an inactive mode and logs a warning instead of enforcing decisions.

Mode-based config snippet:

```json5
{
  "plugins": {
    "entries": {
      "trustnet-openclaw": {
        "enabled": true,
        "config": {
          "mode": "local-lite",
          "apiBaseUrl": "http://127.0.0.1:8088",
          "decider": "0xDECIDER...",
          "targetPrincipalId": "0xTARGET...",
          "toolMapPath": "./plugin-openclaw/tool_map.example.json",
          // local-verifiable only:
          // "rpcUrl": "https://sepolia.infura.io/v3/YOUR_KEY",
          // "rootRegistry": "0xROOTREGISTRY...",
          // "publisherAddress": "0xPUBLISHER...",
          "policyManifestHash": "0x...",
          "receiptOutDir": "./.trustnet/receipts",
          "trustStorePath": "./.trustnet/local-trust.db",
          "askMode": "block",
          "unmappedDecision": "deny",
          "failOpen": false
        }
      }
    }
  }
}
```

Local path mode (without `plugins install`): set
`plugins.load.paths: ["./plugin-openclaw"]` and keep the same `entries.trustnet-openclaw.config` block.
Do not use both install mode and local path mode at the same time.

## Current enforcement flow (TN-002)

1. OpenClaw calls `before_tool_call`.
2. Plugin resolves tool mapping (`tool_map.example.json`) to `contextId`.
3. Plugin calls:
   - `GET /v1/root`
   - `GET /v1/decision?decider=...&target=...&contextId=...`
4. Plugin runs anchored verify only when `mode = local-verifiable`:

```bash
trustnet verify \
  --root /tmp/root.json \
  --bundle /tmp/decision.json \
  --publisher 0xPUBLISHER... \
  --rpc-url https://sepolia.infura.io/v3/YOUR_KEY \
  --root-registry 0xROOTREGISTRY...
```

5. In `local-lite`, step 4 is skipped. Plugin then enforces decision:
   - `allow`: execution proceeds
   - `ask`: blocked by default (`askMode: "block"`) unless explicitly configured to allow
   - `deny`: blocked
6. OpenClaw calls `after_tool_call`.
7. Plugin emits ActionReceipt via `trustnet receipt`, writes it to SQLite `receipts`, and optionally persists JSON to `receiptOutDir`.
8. On `tool_result_persist`, plugin attaches receipt summary metadata to the transcript message.

## Run tests

```bash
cd plugin-openclaw
npm test
```

The integration tests validate both:
- `local-verifiable` anchored compatibility behavior (verify invocation + decision enforcement + receipt emission)
- `local-lite` behavior without chain config (verify skipped + decision enforcement + receipt emission)
