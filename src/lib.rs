/// clob-service library crate.
///
/// This lib target re-exports all internal modules so that integration tests
/// in `tests/` can import production types (e.g. `PublicTrade`, `AppState`,
/// `PrivacyStateService`) for Router::oneshot tests and precise type assertions.
///
/// The binary entry-point (`src/main.rs`) keeps its own independent `mod`
/// declarations for its compilation unit; the two crates share source files
/// but compile independently.

// ─── Re-exported modules ────────────────────────────────────────────────────

pub mod auth;
pub mod balance_service;
pub mod chain_types;
pub mod circuit_breaker;
pub mod config;
pub mod database;
pub mod eip712;
pub mod epoch_service;
pub mod error;
pub mod error_recovery;
pub mod evm_relayer;
pub mod market_lifecycle;
pub mod market_oracle_service;
pub mod market_resolution_policy;
pub mod matching;
pub mod metrics;
pub mod models;
pub mod monitoring;
pub mod oracle;
pub mod orderbook;
pub mod pm_claim_worker;
pub mod pm_settlement_worker;
pub mod poseidon2;
pub mod poseidon_bn254;
pub mod prediction_market_claims;
pub mod prediction_market_relayer;
pub mod prediction_market_settlement;
pub mod private_core;
pub mod privacy;
pub mod proof_batcher;
pub mod proof_generation;
pub mod proof_observability;
pub mod rate_limiter;
pub mod redis_store;
pub mod routes;
pub mod settlement;
pub mod state;
pub mod user_rate_limiter;
pub mod websocket;
pub mod withdrawal_service;

/// Convenience re-export: `use clob_service::AppState;`
pub use state::AppState;
