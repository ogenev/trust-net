# TrustNet — Verifiable, Explainable Reputation for AI Agents

## Project Overview
**TrustNet** is an auditable “trust-to-act” layer for agent gateways and (optionally) smart contracts:

- **Context-scoped trust** (trust for payments ≠ trust for code execution).
- **Decider-relative trust** (no global score; each gateway chooses whose ratings count).
- **Verifiable proofs** (tiny bundles verifiable against a committed `graphRoot`).
- **Why-by-default** explainability (the exact edges used to allow/ask/deny).

Current specs: docs/TrustNet_Spec_v0.7.md

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
