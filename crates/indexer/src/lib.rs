//! ERC-8004 and EdgeRated event ingestion for TrustNet.
//!
//! This crate provides:
//! - Event listeners for ERC-8004 feedback events
//! - EdgeRated event processing
//! - Edge storage and management with latest-wins semantics
//! - Sparse Merkle Map building
//! - Root publishing to RootRegistry
//!
//! # Architecture (Modular)
//!
//! The TrustNet system is split into separate services:
//!
//! ```text
//! ┌──────────────────────────────┐
//! │  trustnet-indexer (this)    │
//! │                              │
//! │  ┌─────────────────┐         │
//! │  │  Event Listener │ ← Ethereum RPC
//! │  │   (tokio task)  │   EdgeRated + NewFeedback
//! │  └────────┬────────┘         │
//! │           │                  │
//! │      ┌────▼──────┐           │
//! │      │  Storage  │ ← SQLite  │
//! │      │  (edges)  │   latest-wins
//! │      └────┬──────┘           │
//! │           │                  │
//! │      ┌────▼──────────┐       │
//! │      │ Root Publisher│       │
//! │      │ (tokio task)  │       │
//! │      │ Hourly + manual       │
//! │      └───────┬───────┘       │
//! │              │               │
//! │              ▼               │
//! │        RootRegistry          │
//! │        (on-chain)            │
//! └──────────────────────────────┘
//!          │
//!          │ Shared DB
//!          │
//! ┌────────▼──────────────────────┐
//! │   trustnet-api (separate)    │
//! │                               │
//! │   ┌───────────────┐           │
//! │   │  API Server   │           │
//! │   │  (axum)       │           │
//! │   └───────┬───────┘           │
//! │           │                   │
//! │   ┌───────▼────────┐          │
//! │   │ Storage (read) │          │
//! │   │ + Prover       │          │
//! │   └────────────────┘          │
//! │                               │
//! │   Endpoints:                  │
//! │   • GET /v1/root              │
//! │   • GET /v1/score             │
//! │   • GET /v1/context           │
//! └───────────────────────────────┘
//!
//! ┌───────────────────────────────┐
//! │  trustnet-cli (offline)      │
//! │  • build-root                 │
//! │  • prove                      │
//! │  • verify                     │
//! │  • seed                       │
//! └───────────────────────────────┘
//! ```
//!
//! # Separation of Concerns
//!
//! - **indexer**: Writes edges, builds and publishes roots (this crate)
//! - **api**: Reads edges, generates proofs, serves HTTP API (trustnet-api)
//! - **prover**: Library for proof generation (trustnet-prover)
//! - **cli**: Offline tools for testing and seeding (trustnet-cli)

#![warn(missing_docs)]
#![warn(clippy::all)]

// Module declarations (will be implemented in phases)

// Phase 2: Database and storage
pub mod storage;

// Phase 3: Configuration
pub mod config;

// Phase 4: Event listening
pub mod listener;

// Phase 5: Event processing
// pub mod processor;

// Phase 6: SMM service (periodic tree building)
pub mod smm_service;

// Phase 7: Root publishing
// pub mod publisher;

// Re-export common types
pub use trustnet_core::{types::*, *};
