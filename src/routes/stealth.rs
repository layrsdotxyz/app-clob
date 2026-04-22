//! G15 — Stealth payment announcement endpoints.
//!
//! Stealth announcements allow payers to broadcast ephemeral keys that only the
//! intended recipient can recognise using their private viewing key (ERC-5564
//! style).  The server records **only** the ephemeral public key and viewing tag;
//! the recipient's address is deliberately never accepted, stored, or returned.
//!
//! ## Endpoints
//! * `GET  /v1/stealth/announcements?from_block=N` — public, no auth required.
//! * `POST /v1/stealth/announce`                   — public; operator or payer posts.
//!
//! ## Redis layout
//! Announcements are appended to the JSON-array at key `stealth:announcements`
//! via `RedisStore::append_json_array_value`.  Each element is a serialised
//! `StealthAnnouncement`.

use crate::{error::ClobResult, AppState};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// ── Redis storage key ─────────────────────────────────────────────────────────
const STEALTH_ANNOUNCE_KEY: &str = "stealth:announcements";

// ── Data models ───────────────────────────────────────────────────────────────

/// A stealth announcement stored at rest — no recipient address is ever persisted
/// or returned (G15 guarantee).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAnnouncement {
    /// Server-generated unique identifier.
    pub announcement_id: String,
    /// Compressed EC point (33 bytes hex) — the ephemeral public key the sender
    /// generated for this payment.  Only the holder of the matching private
    /// viewing key can determine whether this announcement is addressed to them.
    pub ephemeral_pubkey: String,
    /// 1-byte viewing tag (2 hex chars) for fast O(n) scan without full ECDH
    /// per announcement.
    pub viewing_tag: String,
    /// On-chain block number at which the payment was made.
    pub block_number: u64,
}

/// Request body for `POST /v1/stealth/announce`.
/// NOTE: no `recipient` field — that is the privacy guarantee (G15).
#[derive(Debug, Deserialize)]
pub struct CreateAnnouncementRequest {
    pub ephemeral_pubkey: String,
    pub viewing_tag: String,
    pub block_number: u64,
}

/// Query parameters for `GET /v1/stealth/announcements`.
#[derive(Debug, Deserialize)]
pub struct AnnouncementsQuery {
    #[serde(default)]
    pub from_block: u64,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /v1/stealth/announcements?from_block=N`
///
/// Returns all stealth announcements with `block_number >= from_block`.
/// No authentication required — recipients scan announcements against their
/// own private key locally.
pub async fn list_announcements(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AnnouncementsQuery>,
) -> ClobResult<impl IntoResponse> {
    let raw_items = state
        .redis_store
        .get_json_array_values(STEALTH_ANNOUNCE_KEY, 10_000)
        .await?;

    let announcements: Vec<StealthAnnouncement> = raw_items
        .iter()
        .filter_map(|s| serde_json::from_str::<StealthAnnouncement>(s).ok())
        .filter(|a| a.block_number >= query.from_block)
        .collect();

    Ok((StatusCode::OK, Json(announcements)))
}

/// `POST /v1/stealth/announce`
///
/// Records a new stealth announcement.  Only the ephemeral public key and
/// viewing tag are stored — the recipient address is deliberately not accepted.
pub async fn create_announcement(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAnnouncementRequest>,
) -> ClobResult<impl IntoResponse> {
    let announcement = StealthAnnouncement {
        announcement_id: Uuid::new_v4().to_string(),
        ephemeral_pubkey: req.ephemeral_pubkey,
        viewing_tag: req.viewing_tag,
        block_number: req.block_number,
    };

    let payload = serde_json::to_string(&announcement)?;
    state
        .redis_store
        .append_json_array_value(STEALTH_ANNOUNCE_KEY, &payload)
        .await?;

    Ok((StatusCode::CREATED, Json(announcement)))
}
