use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    pub session_id: String,
    pub sequence: u64,
    pub issued_at_millis: i64,
    pub expires_at_millis: i64,
    pub request_hash: [u8; 32],
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionGuard {
    last_sequences: BTreeMap<String, u64>,
}

impl SessionGuard {
    pub fn accept(&mut self, request: &SessionRequest, now_millis: i64) -> CoreResult<()> {
        if request.expires_at_millis <= now_millis
            || request.issued_at_millis > now_millis + 30_000
            || request.session_id.is_empty()
        {
            return Err(CoreError::ExpiredSession);
        }
        let last = self
            .last_sequences
            .get(&request.session_id)
            .copied()
            .unwrap_or(0);
        if request.sequence == 0 || request.sequence <= last {
            return Err(CoreError::ReplayedSequence);
        }
        self.last_sequences
            .insert(request.session_id.clone(), request.sequence);
        Ok(())
    }

    pub fn revoke(&mut self, session_id: &str) {
        self.last_sequences.insert(session_id.to_owned(), u64::MAX);
    }
}
