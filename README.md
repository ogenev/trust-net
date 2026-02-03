# TrustNet

> **Verifiable, explainable trust-to-act for AI agents (TrustNet Spec v0.4).**  
> Gate actions using a deterministic decision rule plus cryptographic proofs against a committed `graphRoot`.

## What this repo is upgrading to

This repo is being upgraded to **TrustNet Spec v0.6**:
- Spec: `docs/TrustNet_Spec_v0.6.md`
- Upgrade plan: `docs/Upgrade_Plan_v0.6.md`
- Progress tracker: `docs/Upgrade_Progress_v0.6.md`

TrustNet’s core properties:
- **Context-scoped trust** (payments ≠ code exec).
- **Decider-relative trust** (no global score; policy chooses whose ratings count).
- **Verifiable “Why”** (exact edges used to ALLOW/ASK/DENY, with Merkle proofs).

## Deployment modes (v0.4)

- **Local mode:** single machine; decisions computed locally (roots/proofs optional).
- **Server mode:** roots are signed by a configured root publisher key; gateways verify offline.
- **Chain mode:** roots are anchored on-chain (RootRegistry) and can also be signed; proofs verify against the anchored root.

## HTTP API (v0.4 target)

- `GET /v1/root` → `{ epoch, graphRoot, manifest( or manifestUri ), manifestHash, publisherSig }`
- `GET /v1/contexts` → canonical contexts (and/or their `contextId` hashes)
- `GET /v1/decision?decider=<principalId>&target=<principalId>&contextId=<bytes32>` → `DecisionBundleV1` (ALLOW|ASK|DENY + why + proofs)
- `GET /v1/proof?key=<edgeKey>` → debug membership/non-membership proof
- `POST /v1/ratings` → append signed `RatingEvent` (server mode)

## Contracts (chain mode, optional for MVP)

- `TrustGraph`: emits `EdgeRated(rater, target, level, contextId)` (events-only).
- `RootRegistry`: anchors `{epoch, graphRoot, manifestHash (and optional manifestUri)}`.
- `TrustPathVerifier`: optional on-chain verifier (off-chain verification is sufficient for MVP).

## Indexing + root building (v0.4)

1) **Ingest** (chain and/or server private log) into `edges_raw`  
2) **Reduce latest-wins** into `edges_latest` per `(rater, target, contextId)`  
3) **Build root**: commit latest edges into a Sparse Merkle Map (`graphRoot`) plus Root Manifest + `manifestHash`  
4) **Serve decisions**: choose endorser deterministically and return a verifiable decision bundle
