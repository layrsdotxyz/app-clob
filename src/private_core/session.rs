use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSessionRequest {
    #[serde(flatten)]
    pub request: SessionRequest,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisteredSession {
    private_user_id: String,
    public_key: [u8; 32],
    expires_at_millis: i64,
    revoked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionGuard {
    last_sequences: BTreeMap<String, u64>,
    registered: BTreeMap<String, RegisteredSession>,
}

impl SessionGuard {
    pub(crate) fn offline_counts(&self) -> (usize, usize) {
        (self.registered.len(), self.last_sequences.len())
    }

    pub(crate) fn registered_owner(&self, session_id: &str) -> Option<&str> {
        self.registered
            .get(session_id)
            .map(|session| session.private_user_id.as_str())
    }

    pub(crate) fn active_owner(&self, session_id: &str, now_millis: i64) -> Option<&str> {
        self.registered.get(session_id).and_then(|session| {
            (!session.revoked && session.expires_at_millis > now_millis)
                .then_some(session.private_user_id.as_str())
        })
    }

    /// Removes sessions that can no longer authorize a command. This keeps the
    /// authenticated enclave state bounded by active sessions instead of every
    /// browser session ever issued.
    pub fn prune_expired(&mut self, now_millis: i64) {
        self.registered
            .retain(|_, session| session.expires_at_millis > now_millis);
        self.last_sequences
            .retain(|session_id, _| self.registered.contains_key(session_id));
    }

    pub fn register(
        &mut self,
        session_id: String,
        private_user_id: String,
        public_key: [u8; 32],
        expires_at_millis: i64,
        now_millis: i64,
    ) -> CoreResult<()> {
        if session_id.is_empty() || private_user_id.is_empty() || expires_at_millis <= now_millis {
            return Err(CoreError::ExpiredSession);
        }
        if self.registered.contains_key(&session_id) {
            return Err(CoreError::DuplicateCommand);
        }
        VerifyingKey::from_bytes(&public_key).map_err(|_| CoreError::InvalidSessionSignature)?;
        self.registered.insert(
            session_id,
            RegisteredSession {
                private_user_id,
                public_key,
                expires_at_millis,
                revoked: false,
            },
        );
        Ok(())
    }

    pub fn accept_signed(
        &mut self,
        signed: &SignedSessionRequest,
        now_millis: i64,
    ) -> CoreResult<String> {
        let private_user_id = self.verify_signed(signed, now_millis)?;
        self.accept(&signed.request, now_millis)?;
        Ok(private_user_id)
    }

    /// Authenticates a read-only request without advancing durable session state.
    /// Transport replay protection still rejects a duplicated encrypted envelope,
    /// while a subsequent mutating command may safely use any greater sequence.
    pub fn verify_signed_readonly(
        &self,
        signed: &SignedSessionRequest,
        now_millis: i64,
    ) -> CoreResult<String> {
        let private_user_id = self.verify_signed(signed, now_millis)?;
        self.validate_sequence(&signed.request, now_millis)?;
        Ok(private_user_id)
    }

    fn verify_signed(&self, signed: &SignedSessionRequest, now_millis: i64) -> CoreResult<String> {
        let registered = self
            .registered
            .get(&signed.request.session_id)
            .ok_or(CoreError::UnknownSession)?;
        if registered.revoked || registered.expires_at_millis <= now_millis {
            return Err(CoreError::UnknownSession);
        }
        if signed.request.expires_at_millis > registered.expires_at_millis {
            return Err(CoreError::ExpiredSession);
        }
        let verifying_key = VerifyingKey::from_bytes(&registered.public_key)
            .map_err(|_| CoreError::InvalidSessionSignature)?;
        let signature_bytes: [u8; 64] = signed
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidSessionSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&signing_payload(&signed.request), &signature)
            .map_err(|_| CoreError::InvalidSessionSignature)?;
        Ok(registered.private_user_id.clone())
    }

    pub fn accept(&mut self, request: &SessionRequest, now_millis: i64) -> CoreResult<()> {
        self.validate_sequence(request, now_millis)?;
        self.last_sequences
            .insert(request.session_id.clone(), request.sequence);
        Ok(())
    }

    fn validate_sequence(&self, request: &SessionRequest, now_millis: i64) -> CoreResult<()> {
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
        Ok(())
    }

    pub fn revoke(&mut self, session_id: &str) {
        self.last_sequences.insert(session_id.to_owned(), u64::MAX);
        if let Some(session) = self.registered.get_mut(session_id) {
            session.revoked = true;
        }
    }
}

pub fn signing_payload(request: &SessionRequest) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96 + request.session_id.len());
    payload.extend_from_slice(b"layrs.private-session.v1\0");
    payload.extend_from_slice(&(request.session_id.len() as u32).to_be_bytes());
    payload.extend_from_slice(request.session_id.as_bytes());
    payload.extend_from_slice(&request.sequence.to_be_bytes());
    payload.extend_from_slice(&request.issued_at_millis.to_be_bytes());
    payload.extend_from_slice(&request.expires_at_millis.to_be_bytes());
    payload.extend_from_slice(&request.request_hash);
    payload
}

#[cfg(test)]
mod tests {
    use super::SessionGuard;
    use ed25519_dalek::SigningKey;

    #[test]
    fn expired_sessions_and_sequences_are_pruned_without_removing_active_sessions() {
        let mut guard = SessionGuard::default();
        let key_a = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let key_b = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
        let key_c = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        guard
            .register("expired".into(), "user-a".into(), key_a, 2_000, 1_000)
            .unwrap();
        guard
            .register("active".into(), "user-b".into(), key_b, 4_000, 1_000)
            .unwrap();
        guard.last_sequences.insert("expired".into(), 9);
        guard.last_sequences.insert("active".into(), 4);

        guard.prune_expired(2_000);

        assert!(!guard.registered.contains_key("expired"));
        assert!(!guard.last_sequences.contains_key("expired"));
        assert!(guard.registered.contains_key("active"));
        assert_eq!(guard.last_sequences.get("active"), Some(&4));
        guard
            .register("expired".into(), "user-c".into(), key_c, 5_000, 2_000)
            .unwrap();
    }
}
