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
- `before_tool_call` now computes decisions directly from local `edges_latest` in `local-lite` (`TN-006`)
- ASK action flow is implemented with ticketed retries and edge writes (`allow_once`, `allow_ttl`, `allow_always`, `block`) (`TN-007`)
- receipt persistence now emits `trustnet.receipt.v1` local receipts with decision/why snapshots for high-risk mappings (`TN-008`)
- `local-verifiable` keeps API decision/root compatibility flow plus anchored verification until sidecar work (`TN-013+`)

The plugin uses OpenClaw lifecycle hooks:
- `before_tool_call`: map tool -> context, compute local decision in `local-lite` (or fetch decision/root in `local-verifiable`), enforce ALLOW/ASK/DENY
- `after_tool_call`: persist high-risk `trustnet.receipt.v1` metadata (with optional `trustnet receipt` attachment in `local-verifiable`)
- `tool_result_persist`: attach TrustNet receipt metadata to persisted tool result messages

## Files

- `index.js`: production plugin runtime entrypoint
- `src/ask-actions.js`: ASK ticket + action normalization utilities
- `openclaw.plugin.json`: plugin manifest + config schema
- `tool_map.example.json`: deterministic tool -> context mapping
- `config.example.json5`: OpenClaw plugin config example
- `test/integration.test.js`: runtime integration tests (mock server + mock trustnet CLI)
- `test/ask-actions.test.js`: ASK action behavior tests

## Requirements

- OpenClaw with plugin support (`openclaw.plugin.json` + package `openclaw.extensions` contract)
- `trustnet` CLI on PATH (or set `trustnetBinary`) for `local-verifiable` ActionReceipt path
- Node runtime with `node:sqlite` support for local trust store persistence
- reachable TrustNet API (`/v1/root`, `/v1/decision`) only for `local-verifiable` compatibility flow
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

## Current enforcement flow (TN-008)

1. OpenClaw calls `before_tool_call`.
2. Plugin resolves tool mapping (`tool_map.example.json`) to `contextId`.
3. Decision source by mode:
   - `local-lite`: compute decision from local SQLite `edges_latest` using TrustNet scoring semantics.
   - `local-verifiable`: call `GET /v1/root` and `GET /v1/decision?...` (compatibility flow).
4. Plugin runs anchored verify only when `mode = local-verifiable`:

```bash
trustnet verify \
  --root /tmp/root.json \
  --bundle /tmp/decision.json \
  --publisher 0xPUBLISHER... \
  --rpc-url https://sepolia.infura.io/v3/YOUR_KEY \
  --root-registry 0xROOTREGISTRY...
```

5. Plugin enforces decision:
   - `allow`: execution proceeds
   - `ask`: if `askMode: "block"` plugin returns `trustnetAsk` prompt metadata with a one-time `ticket`
   - host retries same call with `trustnetAskAction` (`allow_once`, `allow_ttl`, `allow_always`, `block`) and the ticket
   - `allow_ttl`/`allow_always`/`block` write direct `D->T` edges; `allow_once` does not
   - reused/expired/mismatched tickets are rejected
   - `deny`: blocked
6. OpenClaw calls `after_tool_call`.
7. For `riskTier: "high"` mappings, plugin records `trustnet.receipt.v1` metadata in SQLite `receipts` and optional JSON at `receiptOutDir`:
   - includes `argsHash`/`resultHash`, `decision`, `userApproved`, and decision/why snapshots
   - `local-verifiable` additionally runs `trustnet receipt` and embeds that output as optional verifiable metadata
8. On `tool_result_persist`, plugin attaches receipt summary metadata to the transcript message.

## Run tests

```bash
cd plugin-openclaw
npm test
```

The integration tests validate both:
- `local-verifiable` anchored compatibility behavior (verify invocation + decision enforcement + receipt emission)
- `local-lite` local-only behavior (no API dependency, local decision enforcement, local receipt persistence)
