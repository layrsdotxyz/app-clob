//! Parent-side acceleration for rebuilding v71 sparse request proofs.
//!
//! This snapshot is not financial authority and is never trusted by the
//! enclave. It is content-addressed by the parent and accepted only when its
//! complete leaf set reproduces the request-index root authenticated by the
//! enclave checkpoint. Keeping it outside the checkpoint preserves bounded
//! enclave state and bounded commit records.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    request_index::{request_index_root, SparseRequestTree, TerminalRequestLeaf},
    EPOCH_ID,
};

pub const DIRECT_REQUEST_INDEX_SNAPSHOT_PROTOCOL: &str =
    "layrs.direct-execution.request-index-snapshot.v71";
pub const MAX_REQUEST_INDEX_SNAPSHOT_LEAVES: usize = 250_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RequestIndexSnapshotError {
    #[error("request-index snapshot is invalid")]
    Invalid,
    #[error("request-index snapshot root does not match the authenticated checkpoint")]
    RootMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectRequestIndexSnapshot {
    pub protocol: String,
    pub epoch_id: String,
    pub sequence: u64,
    pub request_index_root: String,
    pub leaves: Vec<TerminalRequestLeaf>,
}

impl DirectRequestIndexSnapshot {
    pub fn from_leaves(
        sequence: u64,
        expected_root: &str,
        leaves: impl IntoIterator<Item = TerminalRequestLeaf>,
    ) -> Result<Self, RequestIndexSnapshotError> {
        let mut leaves = leaves.into_iter().collect::<Vec<_>>();
        leaves.sort_by(|left, right| {
            (&left.account_id, &left.request_id).cmp(&(&right.account_id, &right.request_id))
        });
        let snapshot = Self {
            protocol: DIRECT_REQUEST_INDEX_SNAPSHOT_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            sequence,
            request_index_root: expected_root.into(),
            leaves,
        };
        snapshot.verify(sequence, expected_root)?;
        Ok(snapshot)
    }

    pub fn verify(
        &self,
        expected_sequence: u64,
        expected_root: &str,
    ) -> Result<(), RequestIndexSnapshotError> {
        if self.protocol != DIRECT_REQUEST_INDEX_SNAPSHOT_PROTOCOL
            || self.epoch_id != EPOCH_ID
            || self.sequence == 0
            || self.sequence != expected_sequence
            || u64::try_from(self.leaves.len()).ok() != Some(self.sequence)
            || self.leaves.len() > MAX_REQUEST_INDEX_SNAPSHOT_LEAVES
            || self.request_index_root != expected_root
            || !digest(expected_root)
        {
            return Err(RequestIndexSnapshotError::Invalid);
        }
        let mut identities = BTreeSet::new();
        let mut prior: Option<(&str, &str)> = None;
        for leaf in &self.leaves {
            let identity = (leaf.account_id.as_str(), leaf.request_id.as_str());
            if !leaf.validate()
                || prior.is_some_and(|prior| prior >= identity)
                || !identities.insert(leaf.key_hash())
            {
                return Err(RequestIndexSnapshotError::Invalid);
            }
            prior = Some(identity);
        }
        if request_index_root(&self.leaves).map_err(|_| RequestIndexSnapshotError::Invalid)?
            != self.request_index_root
        {
            return Err(RequestIndexSnapshotError::RootMismatch);
        }
        Ok(())
    }

    pub fn into_tree(
        self,
        expected_sequence: u64,
        expected_root: &str,
    ) -> Result<SparseRequestTree, RequestIndexSnapshotError> {
        self.verify(expected_sequence, expected_root)?;
        let tree = SparseRequestTree::from_leaves(&self.leaves)
            .map_err(|_| RequestIndexSnapshotError::Invalid)?;
        if tree
            .root()
            .map_err(|_| RequestIndexSnapshotError::Invalid)?
            != expected_root
        {
            return Err(RequestIndexSnapshotError::RootMismatch);
        }
        Ok(tree)
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{request_index::TerminalResultLocator, sha256};

    fn leaf(account: char, sequence: u64) -> TerminalRequestLeaf {
        TerminalRequestLeaf {
            account_id: account.to_string().repeat(64),
            request_id: format!("request-{sequence}"),
            request_hash: sha256(format!("request-{sequence}").as_bytes()),
            result_hash: sha256(format!("result-{sequence}").as_bytes()),
            receipt_hash: sha256(format!("receipt-{sequence}").as_bytes()),
            locator: TerminalResultLocator::Journal {
                writer_epoch: "writer-1".into(),
                sequence,
            },
        }
    }

    #[test]
    fn snapshot_is_canonical_and_rebuilds_the_authenticated_tree() {
        let leaves = vec![leaf('b', 2), leaf('a', 1)];
        let root = request_index_root(&leaves).unwrap();
        let snapshot = DirectRequestIndexSnapshot::from_leaves(2, &root, leaves).unwrap();
        assert_eq!(snapshot.leaves[0].account_id, "a".repeat(64));
        let tree = snapshot.into_tree(2, &root).unwrap();
        assert_eq!(tree.root().unwrap(), root);
        assert!(tree
            .proof(&"a".repeat(64), "request-1")
            .unwrap()
            .leaf
            .is_some());
        assert!(tree
            .proof(&"c".repeat(64), "request-3")
            .unwrap()
            .leaf
            .is_none());
    }

    #[test]
    fn snapshot_rejects_missing_duplicate_reordered_and_wrong_root() {
        let leaves = vec![leaf('a', 1), leaf('b', 2)];
        let root = request_index_root(&leaves).unwrap();
        let snapshot = DirectRequestIndexSnapshot::from_leaves(2, &root, leaves).unwrap();

        let mut changed = snapshot.clone();
        changed.leaves.pop();
        assert_eq!(
            changed.verify(2, &root),
            Err(RequestIndexSnapshotError::Invalid)
        );

        let mut changed = snapshot.clone();
        changed.leaves[1] = changed.leaves[0].clone();
        assert_eq!(
            changed.verify(2, &root),
            Err(RequestIndexSnapshotError::Invalid)
        );

        let mut changed = snapshot.clone();
        changed.leaves.swap(0, 1);
        assert_eq!(
            changed.verify(2, &root),
            Err(RequestIndexSnapshotError::Invalid)
        );

        assert_eq!(
            snapshot.verify(2, &"f".repeat(64)),
            Err(RequestIndexSnapshotError::Invalid)
        );
    }
}
