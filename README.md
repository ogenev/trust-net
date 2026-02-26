# TrustNet

TrustNet helps you decide if an AI agent should be allowed to do a specific action, and explains why. 
it is an initial implementation of a web-of-trust network and trust score propagation, where if agent A trusts agent B and agent B trusts C,
it is expected that A has some trust to C.

Think of TrustNet like task-based references for AI agents:

1. You decide whose judgment you trust.
2. Those trusted people or agents rate agents for specific tasks.
3. TrustNet checks those ratings and returns a decision with a reason.

Important: trust is scoped by task.  
An agent trusted for `payments` is not automatically trusted for `code-exec`.

## What TrustNet Returns

At core, TrustNet returns a score and an explanation. Your policy uses that score to decide:

- `allow`
- `deny`

If you use the OpenClaw plugin, you can also enable a human-in-the-loop `ask` step before execution.

## Why This Matters

- No single global reputation score.
- Decisions are explainable ("which trust links were used").
- Technical teams can verify results against committed roots and proofs.

## Simple Example

Question: "Can this agent send a payment?"

1. FinOps trusts CFO for payment-related judgments.
2. CFO positively rates the agent for payment tasks.
3. Policy says payment actions need score `>= +1`.
4. TrustNet returns `allow` with a "why" trail.


## For Engineers

- Spec (v1.1): [docs/TRUSTNET_v1.1.md](docs/TRUSTNET_v1.1.md)
- Test vectors: [docs/Test_Vectors_v1.1.json](docs/Test_Vectors_v1.1.json)
- Server smoke test guide: [docs/Server_Smoke_Test.md](docs/Server_Smoke_Test.md)
- Chain smoke test guide: [docs/Chain_Smoke_Test.md](docs/Chain_Smoke_Test.md)
- Base Sepolia rehearsal: [docs/Base_Sepolia_Dress_Rehearsal.md](docs/Base_Sepolia_Dress_Rehearsal.md)

### Components

- Indexer: [crates/indexer](crates/indexer)
- API: [crates/api](crates/api)
- CLI: [crates/cli](crates/cli)
- OpenClaw plugin: [plugin-openclaw/README.md](plugin-openclaw/README.md)

### Core Commands

```bash
# format
cargo +nightly fmt --all

# lint
RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked

# tests
cargo nextest run --workspace
```
