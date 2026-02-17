# Base Sepolia Dress Rehearsal (Public ERC-8004 Traffic, MVP A0+)

This runbook validates release readiness for the initial MVP profile on Base Sepolia using real traffic on official ERC-8004 contracts:

1. Register/reuse public ERC-8004 agents on official IdentityRegistry.
2. Submit public `giveFeedback` and `appendResponse` transactions on official ReputationRegistry.
3. Ingest chain events, publish multiple roots, and cross-check against RootRegistry.
4. Verify decision bundle with anchored CLI verification.
5. Exercise indexer crash/restart catch-up.

No mock ERC-8004 contracts are used in this flow.

## Prerequisites

- Rust toolchain (Cargo)
- `cast`, `jq`, `curl`, `sqlite3`
- Base Sepolia RPC endpoint
- Funded wallets for:
  - publisher (root publish txs)
  - decider (D->E feedback)
  - endorser (E->T feedback + optional agent registration)
  - target (optional agent registration)
- Deployed TrustNet contracts:
  - `RootRegistry`
  - `TrustGraph`

## 1. Configure release profile

Copy the profile template:

```bash
cp scripts/base_sepolia_release.env.example scripts/base_sepolia_release.env
```

Required values:

- `TRUSTNET_CHAIN_ID=84532`
- `TRUSTNET_RPC_URL`
- `TRUSTNET_ROOT_REGISTRY`
- `TRUSTNET_TRUST_GRAPH`
- `TRUSTNET_PUBLISHER_PRIVATE_KEY`
- `TRUSTNET_DECIDER_PRIVATE_KEY`
- `TRUSTNET_ENDORSER_PRIVATE_KEY`
- `TRUSTNET_TARGET_PRIVATE_KEY`
- `TRUSTNET_MANIFEST_PUBLIC_BASE_URI`

Optional values:

- `TRUSTNET_START_BLOCK` (if unset, script snapshots current block)
- `TRUSTNET_ENDORSER_AGENT_ID` + `TRUSTNET_TARGET_AGENT_ID` (reuse existing public agents)
- `TRUSTNET_ERC8004_IDENTITY` + `TRUSTNET_ERC8004_REPUTATION` (defaults to official Base Sepolia addresses)

## 2. Run public rehearsal

```bash
./scripts/base_sepolia_public_rehearsal.sh
```

Optional profile override:

```bash
TRUSTNET_RELEASE_PROFILE=/path/to/base_sepolia_release.env ./scripts/base_sepolia_public_rehearsal.sh
```

Artifacts are written to:

`artifacts/dress-rehearsal/base-sepolia-public-<timestamp>/`

Key outputs:

- `report.json`
- `root.json`
- `decision.json`
- `api.log`
- `indexer.log`
- `publish.log`

## 3. Pass / fail criteria

Pass requires all of the following:

1. Public ERC-8004 traffic is submitted (agent registration if needed, D->E feedback, E->T feedback, response append).
2. At least two epochs are published in one run.
3. For each published epoch, DB `graph_root` + `manifest_hash` + `manifest_uri` match RootRegistry.
4. `/v1/root` has non-inline `manifestUri` and matches RootRegistry at the same epoch.
5. `trustnet verify` succeeds with `--rpc-url --root-registry --epoch`.
6. After forced indexer crash (`SIGKILL`) and restart, ingestion catches up and publish still succeeds.

Fail if any check above fails, or if the script exits non-zero.
