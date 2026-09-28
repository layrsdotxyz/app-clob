//! Parent-side receipt lineage used to rebuild disposable projections after a
//! v71 restart.
//!
//! Receipts were already plaintext in every v70 artifact. In v71, terminal
//! results are encrypted, so the parent persists this separate acceleration
//! object at checkpoint cadence. It is accepted only when every canonical
//! receipt hash matches the complete leaf set committed by the enclave's
//! authenticated request-index root.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    request_index_snapshot::{DirectRequestIndexSnapshot, MAX_REQUEST_INDEX_SNAPSHOT_LEAVES},
    sha256, DirectReceipt, EPOCH_ID,
};

pub const DIRECT_RECEIPT_SNAPSHOT_PROTOCOL: &str = "layrs.direct-execution.receipt-snapshot.v71";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReceiptSnapshotError {
    #[error("receipt snapshot is invalid")]
    Invalid,
    #[error("receipt snapshot does not match the authenticated request index")]
    IndexMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectReceiptSnapshot {
    pub protocol: String,
    pub epoch_id: String,
    pub sequence: u64,
    pub request_index_root: String,
    pub receipts: Vec<DirectReceipt>,
}

impl DirectReceiptSnapshot {
    pub fn from_receipts(
        index: &DirectRequestIndexSnapshot,
        receipts: impl IntoIterator<Item = DirectReceipt>,
    ) -> Result<Self, ReceiptSnapshotError> {
        let mut receipts = receipts.into_iter().collect::<Vec<_>>();
        receipts.sort_by(|left, right| {
            (&left.account_id, &left.request_id).cmp(&(&right.account_id, &right.request_id))
        });
        let snapshot = Self {
            protocol: DIRECT_RECEIPT_SNAPSHOT_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            sequence: index.sequence,
            request_index_root: index.request_index_root.clone(),
            receipts,
        };
        snapshot.verify(index)?;
        Ok(snapshot)
    }

    pub fn verify(&self, index: &DirectRequestIndexSnapshot) -> Result<(), ReceiptSnapshotError> {
        index
            .verify(index.sequence, &index.request_index_root)
            .map_err(|_| ReceiptSnapshotError::Invalid)?;
        if self.protocol != DIRECT_RECEIPT_SNAPSHOT_PROTOCOL
            || self.epoch_id != EPOCH_ID
            || self.sequence == 0
            || self.sequence != index.sequence
            || self.request_index_root != index.request_index_root
            || self.receipts.len() != index.leaves.len()
            || self.receipts.len() > MAX_REQUEST_INDEX_SNAPSHOT_LEAVES
        {
            return Err(ReceiptSnapshotError::Invalid);
        }
        let leaves = index
            .leaves
            .iter()
            .map(|leaf| ((leaf.account_id.as_str(), leaf.request_id.as_str()), leaf))
            .collect::<BTreeMap<_, _>>();
        let mut prior: Option<(&str, &str)> = None;
        for receipt in &self.receipts {
            let identity = (receipt.account_id.as_str(), receipt.request_id.as_str());
            if prior.is_some_and(|prior| prior >= identity) {
                return Err(ReceiptSnapshotError::Invalid);
            }
            let leaf = leaves
                .get(&identity)
                .ok_or(ReceiptSnapshotError::IndexMismatch)?;
            let receipt_hash = serde_cbor::to_vec(receipt)
                .map(|bytes| sha256(&bytes))
                .map_err(|_| ReceiptSnapshotError::Invalid)?;
            if receipt.request_hash != leaf.request_hash || receipt_hash != leaf.receipt_hash {
                return Err(ReceiptSnapshotError::IndexMismatch);
            }
            prior = Some(identity);
        }
        Ok(())
    }

    pub fn into_receipts(
        self,
        index: &DirectRequestIndexSnapshot,
    ) -> Result<Vec<DirectReceipt>, ReceiptSnapshotError> {
        self.verify(index)?;
        Ok(self.receipts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        request_index::{TerminalRequestLeaf, TerminalResultLocator},
        request_index_snapshot::DirectRequestIndexSnapshot,
        DirectReceipt, TerminalStatus,
    };

    fn receipt(account: char, sequence: u64) -> DirectReceipt {
        DirectReceipt {
            receipt_id: sha256(format!("receipt-id-{sequence}").as_bytes()),
            account_id: account.to_string().repeat(64),
            identity_commitment: sha256(format!("identity-{sequence}").as_bytes()),
            request_id: format!("request-{sequence}"),
            request_hash: sha256(format!("request-{sequence}").as_bytes()),
            status: TerminalStatus::Applied,
            effect: "IDENTITY_ADMITTED".into(),
            amount_atomic: None,
            custody_reference: None,
            execution: None,
            resolution: None,
            projection_balance_updates: vec![],
            genesis_ordinal: sequence,
            signature: sha256(format!("signature-{sequence}").as_bytes()),
        }
    }

    fn leaf(receipt: &DirectReceipt, sequence: u64) -> TerminalRequestLeaf {
        TerminalRequestLeaf {
            account_id: receipt.account_id.clone(),
            request_id: receipt.request_id.clone(),
            request_hash: receipt.request_hash.clone(),
            result_hash: sha256(format!("result-{sequence}").as_bytes()),
            receipt_hash: sha256(&serde_cbor::to_vec(receipt).unwrap()),
            locator: TerminalResultLocator::Journal {
                writer_epoch: "writer-1".into(),
                sequence,
            },
        }
    }

    fn fixtures() -> (DirectRequestIndexSnapshot, Vec<DirectReceipt>) {
        let receipts = vec![receipt('b', 2), receipt('a', 1)];
        let leaves = receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| leaf(receipt, index as u64 + 1))
            .collect::<Vec<_>>();
        let root = crate::request_index::request_index_root(&leaves).unwrap();
        (
            DirectRequestIndexSnapshot::from_leaves(2, &root, leaves).unwrap(),
            receipts,
        )
    }

    #[test]
    fn receipt_snapshot_sorts_and_matches_every_authenticated_leaf() {
        let (index, receipts) = fixtures();
        let snapshot = DirectReceiptSnapshot::from_receipts(&index, receipts).unwrap();
        assert_eq!(snapshot.receipts[0].account_id, "a".repeat(64));
        assert_eq!(snapshot.clone().into_receipts(&index).unwrap().len(), 2);
    }

    #[test]
    fn receipt_snapshot_rejects_missing_reordered_and_modified_receipts() {
        let (index, receipts) = fixtures();
        let snapshot = DirectReceiptSnapshot::from_receipts(&index, receipts).unwrap();

        let mut changed = snapshot.clone();
        changed.receipts.pop();
        assert_eq!(changed.verify(&index), Err(ReceiptSnapshotError::Invalid));

        let mut changed = snapshot.clone();
        changed.receipts.swap(0, 1);
        assert_eq!(changed.verify(&index), Err(ReceiptSnapshotError::Invalid));

        let mut changed = snapshot;
        changed.receipts[0].effect = "TAMPERED".into();
        assert_eq!(
            changed.verify(&index),
            Err(ReceiptSnapshotError::IndexMismatch)
        );
    }
}
