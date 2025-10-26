# TrustNet — Verifiable, Explainable Reputation for AI Agents

## Project Overview
TrustNet is a reputation layer that turns ERC‑8004 agent feedback + curator ratings into a single Merkle root and portable proofs.
Gateways and contracts use these proofs to allow/deny agent actions (payments, code‑exec, writes, DeFi) and always show a short “Why?” (two edges + direct override).

Whitepaper: ./WHITEPAPER.md

## ERC-8004
Specs: https://eips.ethereum.org/EIPS/eip-8004

## Quick Reference

### Essential Commands

```bash
# Format code
cargo +nightly fmt --all

# Run lints
RUSTFLAGS="-D warnings" cargo +nightly clippy --workspace --all-features --locked

# Run tests
cargo nextest run --workspace

# Run specific benchmark
cargo bench --bench bench_name

# Build optimized binary
cargo build --release --features "jemalloc asm-keccak"

# Check compilation for all features
cargo check --workspace --all-features

# Check documentation
cargo docs --document-private-items 
```