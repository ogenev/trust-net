# TrustNet OpenClaw Plugin (MVP Production Package)

This package is the OpenClaw enforcement surface for TrustNet MVP:
- OpenClaw-first runtime integration
- `trustnet:ctx:code-exec:v1` as first high-risk context
- mandatory RootRegistry anchoring checks before allow

This plugin now uses OpenClaw's real plugin lifecycle hooks:
- `before_tool_call`: map tool -> context, fetch decision/root, verify anchoring, enforce ALLOW/ASK/DENY
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
- reachable TrustNet API (`/v1/root`, `/v1/decision`)
- chain RPC URL and deployed `RootRegistry` for anchored verification

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

Example config snippet:

```json5
{
  "plugins": {
    "entries": {
      "trustnet-openclaw": {
        "enabled": true,
        "config": {
          "apiBaseUrl": "http://127.0.0.1:8088",
          "decider": "0xDECIDER...",
          "targetPrincipalId": "0xTARGET...",
          "toolMapPath": "./plugin-openclaw/tool_map.example.json",
          "rpcUrl": "https://sepolia.infura.io/v3/YOUR_KEY",
          "rootRegistry": "0xROOTREGISTRY...",
          "publisherAddress": "0xPUBLISHER...",
          "policyManifestHash": "0x...",
          "receiptOutDir": "./.trustnet/receipts",
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

## Enforcement and verification flow

1. OpenClaw calls `before_tool_call`.
2. Plugin resolves tool mapping (`tool_map.example.json`) to `contextId`.
3. Plugin calls:
   - `GET /v1/root`
   - `GET /v1/decision?decider=...&target=...&contextId=...`
4. Plugin runs anchored verify:

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
   - `ask`: blocked by default (`askMode: "block"`) unless explicitly configured to allow
   - `deny`: blocked
6. OpenClaw calls `after_tool_call`.
7. Plugin emits ActionReceipt via `trustnet receipt` and optionally persists it to `receiptOutDir`.
8. On `tool_result_persist`, plugin attaches receipt summary metadata to the transcript message.

## Run tests

```bash
cd plugin-openclaw
npm test
```

The integration tests validate anchored verify invocation, decision enforcement, and receipt emission behavior.
