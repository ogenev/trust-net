# TrustNet OpenClaw Plugin (Reference Stub)

This folder contains a minimal, **non-production** reference stub for integrating TrustNet v0.6 with OpenClaw.
It demonstrates:

- Mapping tools to TrustNet contexts
- Fetching TrustNet decision bundles
- Enforcing ALLOW / ASK / DENY
- Emitting ActionReceipts using the `trustnet-verify` CLI

Files:
- `plugin_stub.ts`: reference implementation (TypeScript) with stubbed OpenClaw hooks
- `tool_map.example.json`: deterministic tool → context mapping
- `config.example.json5`: example TrustNet plugin config (from spec Appendix C, extended)

## High-level flow

1. `before_tool_call`:
   - Map `tool.name` to a context via `tool_map.example.json`.
   - Call `/v1/decision` and enforce the decision.
2. `after_tool_call` / `tool_result_persist`:
   - Call `emitActionReceipt` to create a signed receipt.
   - Store or upload the receipt (evidence).

## ActionReceipt emission

The stub uses the `trustnet-verify receipt` CLI (in `crates/verifier`) to generate receipts.
This keeps hashing and signing behavior consistent with the Rust verifier.

Example CLI invocation:

```bash
trustnet-verify receipt \
  --root /tmp/root.json \
  --bundle /tmp/decision.json \
  --tool payments.send \
  --args /tmp/args.json \
  --result /tmp/result.json \
  --policy-manifest-hash 0x... \
  --signer-key 0x... \
  --out /tmp/receipt.json
```

Set `TRUSTNET_RECEIPT_SIGNER_KEY` in the environment if you do not want to pass `--signer-key`.

## Notes

- This is a **reference** only. Wire it to OpenClaw's actual plugin API and
  replace the placeholder types with OpenClaw interfaces.
- Use a secure signer. Do not expose signing keys to the LLM runtime.
- Keep a deterministic tool mapping; do not allow the model to override it.
