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
        let private_user_id = registered.private_user_id.clone();
        self.accept(&signed.request, now_millis)?;
        Ok(private_user_id)
    }

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
