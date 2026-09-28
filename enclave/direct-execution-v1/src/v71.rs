//! Non-authoritative v71 runtime candidate path.
//!
//! This module proves the bounded commit mechanics without changing the active
//! v70 writer. Financial state is cloned for rollback safety, but historical
//! request results are absent; idempotency is committed by one sparse root.

use thiserror::Error;

use crate::{
    journal::{canonical_receipt_hash, canonical_result_hash, DirectJournalRecord, JournalError},
    migration::{MigratedTerminalRecord, MigrationError, V70MigrationBundle},
    request_hash,
    request_index::{
        RequestIndexError, SparseRequestProof, TerminalRequestLeaf, TerminalResultLocator,
    },
    sha256, DirectRequest, DirectResult, DirectRuntime, RuntimeError,
};

const GENESIS_RECORD_DOMAIN: &[u8] = b"layrs.direct-execution.journal-genesis.v71\0";
const MIGRATION_TRANSITION_DOMAIN: &[u8] = b"layrs.direct-execution.migration-transition.v71\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum V71Error {
    #[error(transparent)]
    Runtime(#[from] RuntimeError),
    #[error(transparent)]
    RequestIndex(#[from] RequestIndexError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Migration(#[from] MigrationError),
    #[error("an authenticated archived result is required for exact replay")]
    ReplayProofRequired,
    #[error("candidate does not succeed the current v71 head")]
    StaleCandidate,
}

#[derive(Clone)]
pub struct DirectV71Runtime {
    runtime: DirectRuntime,
    writer_epoch: String,
    sequence: u64,
    record_hash: String,
    transition_root: String,
    request_index_root: String,
}

pub struct DirectV71Candidate {
    runtime: DirectV71Runtime,
    record: DirectJournalRecord,
    terminal_leaf: TerminalRequestLeaf,
    result: DirectResult,
}

impl DirectV71Candidate {
    pub fn record(&self) -> &DirectJournalRecord {
        &self.record
    }

    pub fn terminal_leaf(&self) -> &TerminalRequestLeaf {
        &self.terminal_leaf
    }

    pub fn result(&self) -> &DirectResult {
        &self.result
    }
}

impl DirectV71Runtime {
    /// Starts an empty v71 lineage. Migration from a non-empty v70 lineage is
    /// a separate operation that must authenticate every terminal leaf before
    /// dropping the v70 request map.
    pub fn new_empty(runtime: DirectRuntime, writer_epoch: String) -> Result<Self, V71Error> {
        if writer_epoch.is_empty() || writer_epoch.len() > 128 || !runtime.requests.is_empty() {
            return Err(V71Error::StaleCandidate);
        }
        let transition_root = runtime.committed_state_hash();
        let mut genesis = Vec::with_capacity(GENESIS_RECORD_DOMAIN.len() + transition_root.len());
        genesis.extend_from_slice(GENESIS_RECORD_DOMAIN);
        genesis.extend_from_slice(transition_root.as_bytes());
        Ok(Self {
            runtime,
            writer_epoch,
            sequence: 0,
            record_hash: sha256(&genesis),
            transition_root,
            request_index_root: crate::request_index::empty_request_index_root(),
        })
    }

    /// Converts an exact authenticated v70 head into bounded v71 live state.
    /// No request history is dropped until every migrated terminal record,
    /// leaf, root, and manifest signature has verified against that same head.
    #[allow(clippy::too_many_arguments)]
    pub fn from_v70_migration(
        mut runtime: DirectRuntime,
        bundle: &V70MigrationBundle,
        writer_epoch: String,
        state_key: &[u8],
        migration_verification_key: &[u8],
    ) -> Result<Self, V71Error> {
        if writer_epoch.is_empty()
            || writer_epoch.len() > 128
            || runtime.committed_sequence() != bundle.manifest.source_sequence
            || runtime.committed_state_hash() != bundle.manifest.source_state_hash
        {
            return Err(V71Error::StaleCandidate);
        }
        bundle.verify_complete(state_key, migration_verification_key, &runtime.receipt_key)?;
        let manifest_hash = bundle.manifest.manifest_hash()?;
        let mut transition = Vec::with_capacity(
            MIGRATION_TRANSITION_DOMAIN.len()
                + manifest_hash.len()
                + bundle.manifest.source_state_hash.len()
                + bundle.manifest.request_index_root.len(),
        );
        transition.extend_from_slice(MIGRATION_TRANSITION_DOMAIN);
        transition.extend_from_slice(manifest_hash.as_bytes());
        transition.extend_from_slice(bundle.manifest.source_state_hash.as_bytes());
        transition.extend_from_slice(bundle.manifest.request_index_root.as_bytes());
        runtime.requests.clear();
        Ok(Self {
            runtime,
            writer_epoch,
            sequence: bundle.manifest.source_sequence,
            record_hash: manifest_hash,
            transition_root: sha256(&transition),
            request_index_root: bundle.manifest.request_index_root.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_candidate(
        &self,
        request: DirectRequest,
        request_proof: &SparseRequestProof,
        state_key: &[u8],
        journal_signing_key: &[u8],
    ) -> Result<DirectV71Candidate, V71Error> {
        if request.request_hash != request_hash(&request) {
            return Err(RuntimeError::InvalidRequest.into());
        }
        if let Some(terminal) = &request_proof.leaf {
            if !request_proof.verifies(
                &self.request_index_root,
                &request.account_id,
                &request.request_id,
            ) {
                return Err(RequestIndexError::Proof.into());
            }
            return if terminal.request_hash == request.request_hash {
                Err(V71Error::ReplayProofRequired)
            } else {
                Err(RuntimeError::RequestReuse.into())
            };
        }
        if !request_proof.verifies(
            &self.request_index_root,
            &request.account_id,
            &request.request_id,
        ) {
            return Err(RequestIndexError::Proof.into());
        }

        let mut next_runtime = self.runtime.clone();
        let result = next_runtime.execute(request.clone())?;
        let request_key = (request.account_id.clone(), request.request_id.clone());
        let removed = next_runtime
            .requests
            .remove(&request_key)
            .ok_or(V71Error::StaleCandidate)?;
        if removed.0 != request.request_hash
            || removed.1 != result
            || !next_runtime.requests.is_empty()
        {
            return Err(V71Error::StaleCandidate);
        }

        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(V71Error::StaleCandidate)?;
        let result_hash = canonical_result_hash(&result)?;
        let receipt_hash = canonical_receipt_hash(&result)?;
        let terminal_leaf = TerminalRequestLeaf {
            account_id: request.account_id.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash.clone(),
            result_hash,
            receipt_hash,
            locator: TerminalResultLocator::Journal {
                writer_epoch: self.writer_epoch.clone(),
                sequence,
            },
        };
        let next_request_index_root =
            request_proof.insert(&self.request_index_root, &terminal_leaf)?;
        let record = DirectJournalRecord::seal(
            &self.writer_epoch,
            sequence,
            &self.record_hash,
            &self.transition_root,
            &self.request_index_root,
            &next_request_index_root,
            request,
            result.clone(),
            state_key,
            journal_signing_key,
            &self.runtime.receipt_key,
        )?;
        let next = DirectV71Runtime {
            runtime: next_runtime,
            writer_epoch: self.writer_epoch.clone(),
            sequence,
            record_hash: record.record_hash()?,
            transition_root: record.transition_root.clone(),
            request_index_root: next_request_index_root,
        };
        Ok(DirectV71Candidate {
            runtime: next,
            record,
            terminal_leaf,
            result,
        })
    }

    pub fn replay(
        &self,
        request: &DirectRequest,
        request_proof: &SparseRequestProof,
        archived_record: &DirectJournalRecord,
        state_key: &[u8],
        journal_verification_key: &[u8],
    ) -> Result<DirectResult, V71Error> {
        if request.request_hash != request_hash(request) {
            return Err(RuntimeError::InvalidRequest.into());
        }
        let terminal = request_proof.terminal_leaf(
            &self.request_index_root,
            &request.account_id,
            &request.request_id,
        )?;
        if terminal.request_hash != request.request_hash {
            return Err(RuntimeError::RequestReuse.into());
        }
        let TerminalResultLocator::Journal {
            writer_epoch,
            sequence,
        } = &terminal.locator
        else {
            return Err(V71Error::ReplayProofRequired);
        };
        let payload = archived_record.open_replay(
            writer_epoch,
            *sequence,
            &terminal.account_id,
            &terminal.request_id,
            &terminal.request_hash,
            &terminal.result_hash,
            &terminal.receipt_hash,
            state_key,
            journal_verification_key,
            &self.runtime.receipt_key,
        )?;
        Ok(payload.result)
    }

    pub fn replay_migrated(
        &self,
        request: &DirectRequest,
        request_proof: &SparseRequestProof,
        archived_record: &MigratedTerminalRecord,
        state_key: &[u8],
        migration_verification_key: &[u8],
    ) -> Result<DirectResult, V71Error> {
        if request.request_hash != request_hash(request) {
            return Err(RuntimeError::InvalidRequest.into());
        }
        let terminal = request_proof.terminal_leaf(
            &self.request_index_root,
            &request.account_id,
            &request.request_id,
        )?;
        if terminal.request_hash != request.request_hash {
            return Err(RuntimeError::RequestReuse.into());
        }
        let TerminalResultLocator::Migration {
            migration_id,
            ordinal,
        } = &terminal.locator
        else {
            return Err(V71Error::ReplayProofRequired);
        };
        archived_record
            .open_replay(
                migration_id,
                *ordinal,
                &terminal.account_id,
                &terminal.request_id,
                &terminal.request_hash,
                &terminal.result_hash,
                &terminal.receipt_hash,
                state_key,
                migration_verification_key,
                &self.runtime.receipt_key,
            )
            .map_err(Into::into)
    }

    /// Adoption is called only after the parent has durably appended and read
    /// back the exact journal record. A stale concurrent candidate cannot be
    /// adopted after another head has won.
    pub fn adopt_candidate(
        &mut self,
        candidate: DirectV71Candidate,
    ) -> Result<DirectResult, V71Error> {
        if candidate.record.writer_epoch != self.writer_epoch
            || candidate.record.sequence != self.sequence + 1
            || candidate.record.previous_record_hash != self.record_hash
            || candidate.record.previous_transition_root != self.transition_root
            || candidate.record.previous_request_index_root != self.request_index_root
            || candidate.runtime.record_hash != candidate.record.record_hash()?
            || candidate.runtime.transition_root != candidate.record.transition_root
            || candidate.runtime.request_index_root != candidate.record.request_index_root
        {
            return Err(V71Error::StaleCandidate);
        }
        let result = candidate.result.clone();
        *self = candidate.runtime;
        Ok(result)
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn record_hash(&self) -> &str {
        &self.record_hash
    }

    pub fn transition_root(&self) -> &str {
        &self.transition_root
    }

    pub fn request_index_root(&self) -> &str {
        &self.request_index_root
    }

    pub fn financial_runtime(&self) -> &DirectRuntime {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        identity_commitment_for, journal::journal_verifying_key, DirectAction, RuntimeMode,
        SealedEpoch,
    };

    fn runtime() -> DirectV71Runtime {
        let epoch = SealedEpoch {
            identities: BTreeMap::new(),
            identity_subjects: BTreeMap::new(),
            subject_identities: BTreeMap::new(),
            subject_wallets: BTreeMap::<String, BTreeSet<String>>::new(),
        };
        DirectV71Runtime::new_empty(
            DirectRuntime::new(epoch, RuntimeMode::IsolatedTest, vec![9; 32]).unwrap(),
            "writer-epoch-1".into(),
        )
        .unwrap()
    }

    fn admission(subject: &str, request_id: &str, wallet: &str) -> DirectRequest {
        let mut request = DirectRequest {
            account_id: subject.into(),
            identity_commitment: identity_commitment_for(subject, wallet),
            request_id: request_id.into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::AdmitIdentity {
                wallet_address: wallet.into(),
            },
        };
        request.request_hash = request_hash(&request);
        request
    }

    #[test]
    fn candidate_is_bounded_and_adopted_only_after_explicit_ack_boundary() {
        let mut runtime = runtime();
        let opening_record = runtime.record_hash().to_string();
        let opening_index = runtime.request_index_root().to_string();
        let request = admission(
            &"a".repeat(64),
            "request-1",
            "0x1111111111111111111111111111111111111111",
        );
        let candidate = runtime
            .prepare_candidate(
                request,
                &SparseRequestProof::empty_tree(),
                &[7; 32],
                &[8; 32],
            )
            .unwrap();
        assert!(serde_cbor::to_vec(candidate.record()).unwrap().len() < 32 * 1024);
        assert_eq!(runtime.sequence(), 0);
        assert_eq!(runtime.record_hash(), opening_record);
        assert_eq!(runtime.request_index_root(), opening_index);
        assert!(runtime.financial_runtime().requests.is_empty());

        let result = runtime.adopt_candidate(candidate).unwrap();
        assert_eq!(result.effect, "IDENTITY_ADMITTED");
        assert_eq!(runtime.sequence(), 1);
        assert!(runtime.financial_runtime().requests.is_empty());
        assert_ne!(runtime.request_index_root(), opening_index);
    }

    #[test]
    fn terminal_membership_requires_archive_replay_and_conflicts_fail_closed() {
        let mut runtime = runtime();
        let request = admission(
            &"a".repeat(64),
            "request-1",
            "0x1111111111111111111111111111111111111111",
        );
        let candidate = runtime
            .prepare_candidate(
                request.clone(),
                &SparseRequestProof::empty_tree(),
                &[7; 32],
                &[8; 32],
            )
            .unwrap();
        let archived_record = candidate.record().clone();
        let membership = SparseRequestProof {
            leaf: Some(candidate.terminal_leaf().clone()),
            siblings: SparseRequestProof::empty_tree().siblings,
        };
        runtime.adopt_candidate(candidate).unwrap();
        let replayed = runtime
            .replay(
                &request,
                &membership,
                &archived_record,
                &[7; 32],
                &journal_verifying_key(&[8; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(replayed.effect, "IDENTITY_ADMITTED");
        assert_eq!(runtime.sequence(), 1);
        assert!(matches!(
            runtime.prepare_candidate(request.clone(), &membership, &[7; 32], &[8; 32]),
            Err(V71Error::ReplayProofRequired)
        ));

        let mut conflict = request;
        conflict.action = DirectAction::AdmitIdentity {
            wallet_address: "0x2222222222222222222222222222222222222222".into(),
        };
        conflict.request_hash = request_hash(&conflict);
        assert!(matches!(
            runtime.prepare_candidate(conflict, &membership, &[7; 32], &[8; 32]),
            Err(V71Error::Runtime(RuntimeError::RequestReuse))
        ));
    }

    #[test]
    fn stale_parallel_candidate_cannot_replace_the_winning_head() {
        let mut runtime = runtime();
        let first = runtime
            .prepare_candidate(
                admission(
                    &"a".repeat(64),
                    "request-1",
                    "0x1111111111111111111111111111111111111111",
                ),
                &SparseRequestProof::empty_tree(),
                &[7; 32],
                &[8; 32],
            )
            .unwrap();
        let stale = runtime
            .prepare_candidate(
                admission(
                    &"b".repeat(64),
                    "request-2",
                    "0x2222222222222222222222222222222222222222",
                ),
                &SparseRequestProof::empty_tree(),
                &[7; 32],
                &[8; 32],
            )
            .unwrap();
        runtime.adopt_candidate(first).unwrap();
        assert_eq!(
            runtime.adopt_candidate(stale),
            Err(V71Error::StaleCandidate)
        );
        assert_eq!(runtime.sequence(), 1);
    }

    #[test]
    fn authenticated_v70_migration_preserves_exact_replay_then_drops_full_history() {
        let epoch = SealedEpoch {
            identities: BTreeMap::new(),
            identity_subjects: BTreeMap::new(),
            subject_identities: BTreeMap::new(),
            subject_wallets: BTreeMap::<String, BTreeSet<String>>::new(),
        };
        let mut v70 = DirectRuntime::new(epoch, RuntimeMode::IsolatedTest, vec![9; 32]).unwrap();
        let request = admission(
            &"a".repeat(64),
            "request-1",
            "0x1111111111111111111111111111111111111111",
        );
        let expected = v70.execute(request.clone()).unwrap();
        let source_hash = v70.committed_state_hash();
        let bundle = V70MigrationBundle::seal(&v70, &[7; 32], &[8; 32]).unwrap();
        let leaf = bundle.leaves[0].clone();
        let record = bundle.records[0].clone();
        let proof = SparseRequestProof {
            leaf: Some(leaf),
            siblings: SparseRequestProof::empty_tree().siblings,
        };

        let migrated = DirectV71Runtime::from_v70_migration(
            v70,
            &bundle,
            "writer-epoch-2".into(),
            &[7; 32],
            &journal_verifying_key(&[8; 32]).unwrap(),
        )
        .unwrap();
        assert_eq!(migrated.sequence(), 1);
        assert!(migrated.financial_runtime().requests.is_empty());
        assert_ne!(
            migrated.financial_runtime().committed_state_hash(),
            source_hash
        );
        assert_eq!(
            migrated
                .replay_migrated(
                    &request,
                    &proof,
                    &record,
                    &[7; 32],
                    &journal_verifying_key(&[8; 32]).unwrap(),
                )
                .unwrap(),
            expected
        );
    }
}
