# Chain-Mode Smoke Test (Anvil, End-to-End)

> v1.1 note: This runbook validates the ERC-8004 + on-chain-root MVP path.

This smoke test validates the chain-mode MVP flow end-to-end:

1. Emit ERC-8004 `NewFeedback` + `ResponseAppended` on-chain
2. Ingest events into TrustNet indexer (`feedback_raw`, `feedback_responses_raw`, `edges_latest`)
3. Publish an epoch root to `RootRegistry`
4. Fetch `/v1/root` + `/v1/score` from API
5. Verify score bundle cryptographically (`trustnet verify`)
6. Cross-check `graphRoot` + `manifestHash` + `manifestUri` against on-chain `RootRegistry`

By default, the script exercises the `trustnet:ctx:code-exec:v1` context to match the initial OpenClaw-focused MVP profile.

For Base Sepolia public-traffic release rehearsal (multi-epoch + crash/recovery), use [Base_Sepolia_Dress_Rehearsal.md](Base_Sepolia_Dress_Rehearsal.md) and `./scripts/base_sepolia_public_rehearsal.sh`.

## Prerequisites

- Rust toolchain (Cargo)
- Foundry (`anvil`, `forge`, `cast`)
- `jq`
- `sqlite3`

## Run

```bash
./scripts/chain_smoke_anvil.sh
```

Optional environment overrides:

- `ANVIL_PORT` (default: `8545`)
- `API_PORT` (default: `18080`)
- `CHAIN_SMOKE_DECIDER_ADDR`
- `CHAIN_SMOKE_ENDORSER_ADDR`
- `CHAIN_SMOKE_TARGET_ADDR`
- `CHAIN_SMOKE_KEEP_TMP=1` (keeps temp artifacts/logs on exit)

## Expected Result

The script exits `0` and prints:

- ingested row counts for `feedback_raw`, `feedback_responses_raw`, `edges_latest`
- published root epoch
- deployed `RootRegistry` address used for chain anchor checks
