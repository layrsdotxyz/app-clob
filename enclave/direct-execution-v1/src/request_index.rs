//! Bounded authenticated index for terminal request identities.
//!
//! The enclave retains only a root. The untrusted parent supplies a complete
//! 256-level proof for either the existing terminal leaf or an empty leaf.
//! Consequently, omitting an old request cannot turn an exact replay into a
//! new command, and live enclave state does not grow with request history.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::sha256;

const KEY_DOMAIN: &[u8] = b"layrs.direct-execution.request-index-key.v1\0";
const LEAF_DOMAIN: &[u8] = b"layrs.direct-execution.request-index-leaf.v1\0";
const EMPTY_LEAF_DOMAIN: &[u8] = b"layrs.direct-execution.request-index-empty.v1\0";
const BRANCH_DOMAIN: &[u8] = b"layrs.direct-execution.request-index-branch.v1\0";
pub const REQUEST_INDEX_DEPTH: usize = 256;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RequestIndexError {
    #[error("request-index input is invalid")]
    Invalid,
    #[error("request-index proof does not match the committed root")]
    Proof,
    #[error("request id is already terminal")]
    Occupied,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum TerminalResultLocator {
    Journal { writer_epoch: String, sequence: u64 },
    Migration { migration_id: String, ordinal: u64 },
}

impl TerminalResultLocator {
    fn validate(&self) -> bool {
        match self {
            Self::Journal {
                writer_epoch,
                sequence,
            } => !writer_epoch.is_empty() && writer_epoch.len() <= 128 && *sequence > 0,
            Self::Migration {
                migration_id,
                ordinal,
            } => valid_digest(migration_id) && *ordinal > 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalRequestLeaf {
    pub account_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub result_hash: String,
    pub receipt_hash: String,
    pub locator: TerminalResultLocator,
}

impl TerminalRequestLeaf {
    pub fn validate(&self) -> bool {
        !self.account_id.is_empty()
            && !self.request_id.is_empty()
            && self.locator.validate()
            && [
                self.request_hash.as_str(),
                self.result_hash.as_str(),
                self.receipt_hash.as_str(),
            ]
            .into_iter()
            .all(valid_digest)
    }

    pub fn key_hash(&self) -> String {
        request_index_key(&self.account_id, &self.request_id)
    }

    pub fn leaf_hash(&self) -> Result<String, RequestIndexError> {
        if !self.validate() {
            return Err(RequestIndexError::Invalid);
        }
        let mut bytes = Vec::from(LEAF_DOMAIN);
        bytes.extend_from_slice(&serde_cbor::to_vec(self).map_err(|_| RequestIndexError::Invalid)?);
        Ok(sha256(&bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SparseRequestProof {
    /// The terminal leaf at this exact key, or `None` for non-membership.
    pub leaf: Option<TerminalRequestLeaf>,
    /// Sibling hashes from the leaf level to the root level.
    pub siblings: Vec<String>,
}

/// Compact in-memory form of the 256-level sparse tree. Unary paths are
/// implicit, so storage is O(number of terminal requests), while generated
/// proofs remain the fixed-format 256-sibling proofs verified by the enclave.
#[derive(Debug, Clone, Default)]
pub struct SparseRequestTree {
    root: Option<Box<PatriciaNode>>,
    len: usize,
}

#[derive(Debug, Clone)]
enum PatriciaNode {
    Leaf {
        key: [u8; 32],
        hash: String,
        leaf: TerminalRequestLeaf,
    },
    Branch {
        depth: usize,
        key: [u8; 32],
        hash: String,
        left: Box<PatriciaNode>,
        right: Box<PatriciaNode>,
    },
}

impl SparseRequestProof {
    pub fn empty_tree() -> Self {
        Self {
            leaf: None,
            siblings: empty_hashes()[..REQUEST_INDEX_DEPTH].to_vec(),
        }
    }

    pub fn verifies(&self, root: &str, account_id: &str, request_id: &str) -> bool {
        if !valid_digest(root)
            || account_id.is_empty()
            || request_id.is_empty()
            || self.siblings.len() != REQUEST_INDEX_DEPTH
            || !self.siblings.iter().all(|hash| valid_digest(hash))
            || self.leaf.as_ref().is_some_and(|leaf| {
                !leaf.validate() || leaf.account_id != account_id || leaf.request_id != request_id
            })
        {
            return false;
        }
        self.calculated_root(account_id, request_id)
            .is_ok_and(|calculated| calculated == root)
    }

    pub fn insert(
        &self,
        root: &str,
        leaf: &TerminalRequestLeaf,
    ) -> Result<String, RequestIndexError> {
        if self.leaf.is_some() {
            return Err(RequestIndexError::Occupied);
        }
        if !leaf.validate() || !self.verifies(root, &leaf.account_id, &leaf.request_id) {
            return Err(RequestIndexError::Proof);
        }
        root_from_path(
            &decode_digest(&leaf.key_hash())?,
            &leaf.leaf_hash()?,
            &self.siblings,
        )
    }

    pub fn terminal_leaf(
        &self,
        root: &str,
        account_id: &str,
        request_id: &str,
    ) -> Result<&TerminalRequestLeaf, RequestIndexError> {
        if !self.verifies(root, account_id, request_id) {
            return Err(RequestIndexError::Proof);
        }
        self.leaf.as_ref().ok_or(RequestIndexError::Invalid)
    }

    fn calculated_root(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<String, RequestIndexError> {
        let key = request_index_key(account_id, request_id);
        let leaf_hash = match &self.leaf {
            Some(leaf) => leaf.leaf_hash()?,
            None => empty_hashes()[0].clone(),
        };
        root_from_path(&decode_digest(&key)?, &leaf_hash, &self.siblings)
    }
}

impl SparseRequestTree {
    pub fn from_leaves(leaves: &[TerminalRequestLeaf]) -> Result<Self, RequestIndexError> {
        let mut tree = Self::default();
        for leaf in leaves {
            tree.insert(leaf.clone())?;
        }
        Ok(tree)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn root(&self) -> Result<String, RequestIndexError> {
        match &self.root {
            Some(root) => root.hash_at_depth(0),
            None => Ok(empty_request_index_root()),
        }
    }

    pub fn proof(
        &self,
        account_id: &str,
        request_id: &str,
    ) -> Result<SparseRequestProof, RequestIndexError> {
        if account_id.is_empty() || request_id.is_empty() {
            return Err(RequestIndexError::Invalid);
        }
        let key = decode_digest(&request_index_key(account_id, request_id))?;
        let mut proof = SparseRequestProof::empty_tree();
        if let Some(root) = &self.root {
            proof.leaf = root.prove(&key, &mut proof.siblings)?;
        }
        if !proof.verifies(&self.root()?, account_id, request_id) {
            return Err(RequestIndexError::Proof);
        }
        Ok(proof)
    }

    pub fn insert(&mut self, leaf: TerminalRequestLeaf) -> Result<String, RequestIndexError> {
        if !leaf.validate() {
            return Err(RequestIndexError::Invalid);
        }
        if !self.is_empty()
            && self
                .proof(&leaf.account_id, &leaf.request_id)?
                .leaf
                .is_some()
        {
            return Err(RequestIndexError::Occupied);
        }
        let key = decode_digest(&leaf.key_hash())?;
        let node = PatriciaNode::Leaf {
            key,
            hash: leaf.leaf_hash()?,
            leaf,
        };
        self.root = Some(match self.root.take() {
            Some(root) => Box::new(root.insert(node)?),
            None => Box::new(node),
        });
        self.len = self.len.checked_add(1).ok_or(RequestIndexError::Invalid)?;
        self.root()
    }
}

impl PatriciaNode {
    fn depth(&self) -> usize {
        match self {
            Self::Leaf { .. } => REQUEST_INDEX_DEPTH,
            Self::Branch { depth, .. } => *depth,
        }
    }

    fn key(&self) -> &[u8; 32] {
        match self {
            Self::Leaf { key, .. } | Self::Branch { key, .. } => key,
        }
    }

    fn hash(&self) -> &str {
        match self {
            Self::Leaf { hash, .. } | Self::Branch { hash, .. } => hash,
        }
    }

    fn hash_at_depth(&self, target_depth: usize) -> Result<String, RequestIndexError> {
        let mut depth = self.depth();
        if target_depth > depth || depth > REQUEST_INDEX_DEPTH {
            return Err(RequestIndexError::Invalid);
        }
        let mut hash = self.hash().to_string();
        while depth > target_depth {
            let parent_depth = depth - 1;
            let empty = &empty_hashes()[REQUEST_INDEX_DEPTH - depth];
            hash = if bit(self.key(), parent_depth) == 0 {
                branch_hash(&hash, empty)?
            } else {
                branch_hash(empty, &hash)?
            };
            depth = parent_depth;
        }
        Ok(hash)
    }

    fn insert(self: Box<Self>, new: PatriciaNode) -> Result<Self, RequestIndexError> {
        let divergence = common_prefix_bits(self.key(), new.key());
        if divergence < self.depth() {
            return Self::branch(divergence, *self, new);
        }
        match *self {
            Self::Leaf { .. } => Err(RequestIndexError::Occupied),
            Self::Branch {
                depth,
                key: _,
                hash: _,
                left,
                right,
            } => {
                let (left, right) = if bit(new.key(), depth) == 0 {
                    (Box::new(left.insert(new)?), right)
                } else {
                    (left, Box::new(right.insert(new)?))
                };
                Self::branch_with_children(depth, left, right)
            }
        }
    }

    fn branch(
        depth: usize,
        existing: PatriciaNode,
        new: PatriciaNode,
    ) -> Result<Self, RequestIndexError> {
        if depth >= REQUEST_INDEX_DEPTH || bit(existing.key(), depth) == bit(new.key(), depth) {
            return Err(RequestIndexError::Invalid);
        }
        let (left, right) = if bit(existing.key(), depth) == 0 {
            (Box::new(existing), Box::new(new))
        } else {
            (Box::new(new), Box::new(existing))
        };
        Self::branch_with_children(depth, left, right)
    }

    fn branch_with_children(
        depth: usize,
        left: Box<PatriciaNode>,
        right: Box<PatriciaNode>,
    ) -> Result<Self, RequestIndexError> {
        if depth >= REQUEST_INDEX_DEPTH
            || bit(left.key(), depth) != 0
            || bit(right.key(), depth) != 1
            || left.depth() <= depth
            || right.depth() <= depth
        {
            return Err(RequestIndexError::Invalid);
        }
        let left_hash = left.hash_at_depth(depth + 1)?;
        let right_hash = right.hash_at_depth(depth + 1)?;
        Ok(Self::Branch {
            depth,
            key: *left.key(),
            hash: branch_hash(&left_hash, &right_hash)?,
            left,
            right,
        })
    }

    fn prove(
        &self,
        target: &[u8; 32],
        siblings: &mut [String],
    ) -> Result<Option<TerminalRequestLeaf>, RequestIndexError> {
        let divergence = common_prefix_bits(self.key(), target);
        if divergence < self.depth() {
            siblings[REQUEST_INDEX_DEPTH - 1 - divergence] = self.hash_at_depth(divergence + 1)?;
            return Ok(None);
        }
        match self {
            Self::Leaf { key, leaf, .. } => {
                if key == target {
                    Ok(Some(leaf.clone()))
                } else {
                    Err(RequestIndexError::Invalid)
                }
            }
            Self::Branch {
                depth, left, right, ..
            } => {
                let proof_level = REQUEST_INDEX_DEPTH - 1 - depth;
                if bit(target, *depth) == 0 {
                    siblings[proof_level] = right.hash_at_depth(depth + 1)?;
                    left.prove(target, siblings)
                } else {
                    siblings[proof_level] = left.hash_at_depth(depth + 1)?;
                    right.prove(target, siblings)
                }
            }
        }
    }
}

pub fn request_index_key(account_id: &str, request_id: &str) -> String {
    let mut bytes = Vec::with_capacity(KEY_DOMAIN.len() + account_id.len() + request_id.len() + 16);
    bytes.extend_from_slice(KEY_DOMAIN);
    bytes.extend_from_slice(&(account_id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(account_id.as_bytes());
    bytes.extend_from_slice(&(request_id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(request_id.as_bytes());
    sha256(&bytes)
}

pub fn empty_request_index_root() -> String {
    empty_hashes()[REQUEST_INDEX_DEPTH].clone()
}

/// Builds the canonical sparse root for a complete set of terminal leaves.
/// This O(256*N) routine is intended for one-time v70 migration and offline
/// verification. The live parent maintains an incremental proof index.
pub fn request_index_root(leaves: &[TerminalRequestLeaf]) -> Result<String, RequestIndexError> {
    if leaves.is_empty() {
        return Ok(empty_request_index_root());
    }
    let mut current = BTreeMap::<[u8; 32], String>::new();
    for leaf in leaves {
        if !leaf.validate()
            || current
                .insert(decode_digest(&leaf.key_hash())?, leaf.leaf_hash()?)
                .is_some()
        {
            return Err(RequestIndexError::Invalid);
        }
    }
    for level in 0..REQUEST_INDEX_DEPTH {
        let bit_index = REQUEST_INDEX_DEPTH - 1 - level;
        let byte = bit_index / 8;
        let mask = 1 << (7 - (bit_index % 8));
        let mut consumed = BTreeSet::new();
        let mut next = BTreeMap::new();
        for (key, hash) in &current {
            if consumed.contains(key) {
                continue;
            }
            let mut sibling_key = *key;
            sibling_key[byte] ^= mask;
            let sibling = current
                .get(&sibling_key)
                .cloned()
                .unwrap_or_else(|| empty_hashes()[level].clone());
            let parent_hash = if key[byte] & mask == 0 {
                branch_hash(hash, &sibling)?
            } else {
                branch_hash(&sibling, hash)?
            };
            consumed.insert(*key);
            consumed.insert(sibling_key);
            let mut parent_key = *key;
            parent_key[byte] &= !mask;
            if next.insert(parent_key, parent_hash).is_some() {
                return Err(RequestIndexError::Invalid);
            }
        }
        current = next;
    }
    if current.len() != 1 {
        return Err(RequestIndexError::Invalid);
    }
    current.remove(&[0; 32]).ok_or(RequestIndexError::Invalid)
}

fn root_from_path(
    key: &[u8; 32],
    leaf_hash: &str,
    siblings: &[String],
) -> Result<String, RequestIndexError> {
    if siblings.len() != REQUEST_INDEX_DEPTH
        || !valid_digest(leaf_hash)
        || !siblings.iter().all(|hash| valid_digest(hash))
    {
        return Err(RequestIndexError::Invalid);
    }
    let mut current = leaf_hash.to_string();
    for (level, sibling) in siblings.iter().enumerate() {
        let bit_index = REQUEST_INDEX_DEPTH - 1 - level;
        let byte = bit_index / 8;
        let shift = 7 - (bit_index % 8);
        current = if (key[byte] >> shift) & 1 == 0 {
            branch_hash(&current, sibling)?
        } else {
            branch_hash(sibling, &current)?
        };
    }
    Ok(current)
}

fn common_prefix_bits(left: &[u8; 32], right: &[u8; 32]) -> usize {
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        let difference = left ^ right;
        if difference != 0 {
            return index * 8 + difference.leading_zeros() as usize;
        }
    }
    REQUEST_INDEX_DEPTH
}

fn bit(key: &[u8; 32], depth: usize) -> u8 {
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

fn empty_hashes() -> &'static Vec<String> {
    static HASHES: OnceLock<Vec<String>> = OnceLock::new();
    HASHES.get_or_init(|| {
        let mut hashes = Vec::with_capacity(REQUEST_INDEX_DEPTH + 1);
        hashes.push(sha256(EMPTY_LEAF_DOMAIN));
        for level in 0..REQUEST_INDEX_DEPTH {
            hashes.push(
                branch_hash(&hashes[level], &hashes[level])
                    .expect("fixed empty request-index hash is valid"),
            );
        }
        hashes
    })
}

fn branch_hash(left: &str, right: &str) -> Result<String, RequestIndexError> {
    let left = decode_digest(left)?;
    let right = decode_digest(right)?;
    let mut bytes = Vec::with_capacity(BRANCH_DOMAIN.len() + 64);
    bytes.extend_from_slice(BRANCH_DOMAIN);
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    Ok(sha256(&bytes))
}

fn decode_digest(value: &str) -> Result<[u8; 32], RequestIndexError> {
    let bytes = hex::decode(value).map_err(|_| RequestIndexError::Invalid)?;
    bytes.try_into().map_err(|_| RequestIndexError::Invalid)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(request_hash: &str) -> TerminalRequestLeaf {
        TerminalRequestLeaf {
            account_id: "account".into(),
            request_id: "request-1".into(),
            request_hash: request_hash.into(),
            result_hash: "b".repeat(64),
            receipt_hash: "c".repeat(64),
            locator: TerminalResultLocator::Journal {
                writer_epoch: "writer-epoch-1".into(),
                sequence: 1,
            },
        }
    }

    #[test]
    fn empty_proof_inserts_terminal_leaf_and_then_proves_membership() {
        let empty = SparseRequestProof::empty_tree();
        assert!(empty.verifies(&empty_request_index_root(), "account", "request-1"));
        let terminal = leaf(&"a".repeat(64));
        let root = empty
            .insert(&empty_request_index_root(), &terminal)
            .unwrap();
        assert_ne!(root, empty_request_index_root());

        let membership = SparseRequestProof {
            leaf: Some(terminal.clone()),
            siblings: empty.siblings,
        };
        assert!(membership.verifies(&root, "account", "request-1"));
        assert_eq!(
            membership
                .terminal_leaf(&root, "account", "request-1")
                .unwrap(),
            &terminal
        );
    }

    #[test]
    fn occupied_or_modified_proofs_fail_closed() {
        let empty = SparseRequestProof::empty_tree();
        let terminal = leaf(&"a".repeat(64));
        let root = empty
            .insert(&empty_request_index_root(), &terminal)
            .unwrap();
        let mut membership = SparseRequestProof {
            leaf: Some(terminal),
            siblings: empty.siblings,
        };
        assert_eq!(
            membership.insert(&root, &leaf(&"d".repeat(64))),
            Err(RequestIndexError::Occupied)
        );
        membership.siblings[17] = "e".repeat(64);
        assert!(!membership.verifies(&root, "account", "request-1"));
    }

    #[test]
    fn request_identity_and_terminal_hashes_are_all_committed() {
        let first = leaf(&"a".repeat(64));
        let mut changed = first.clone();
        changed.account_id.push('x');
        assert_ne!(first.key_hash(), changed.key_hash());
        assert_ne!(first.leaf_hash().unwrap(), changed.leaf_hash().unwrap());

        let mut changed = first.clone();
        changed.receipt_hash = "d".repeat(64);
        assert_eq!(first.key_hash(), changed.key_hash());
        assert_ne!(first.leaf_hash().unwrap(), changed.leaf_hash().unwrap());
    }

    #[test]
    fn proof_is_bounded_and_wrong_depth_fails_closed() {
        let mut proof = SparseRequestProof::empty_tree();
        assert!(serde_cbor::to_vec(&proof).unwrap().len() < 20 * 1024);
        proof.siblings.pop();
        assert!(!proof.verifies(&empty_request_index_root(), "account", "request-1"));
        assert_eq!(
            proof.insert(&empty_request_index_root(), &leaf(&"a".repeat(64))),
            Err(RequestIndexError::Proof)
        );
    }

    #[test]
    fn complete_root_matches_single_leaf_proof_and_rejects_duplicate_keys() {
        let terminal = leaf(&"a".repeat(64));
        let expected = SparseRequestProof::empty_tree()
            .insert(&empty_request_index_root(), &terminal)
            .unwrap();
        assert_eq!(request_index_root(&[terminal.clone()]).unwrap(), expected);
        assert_eq!(
            request_index_root(&[terminal.clone(), terminal]),
            Err(RequestIndexError::Invalid)
        );
    }

    #[test]
    fn compact_tree_matches_complete_root_and_proves_membership_and_absence() {
        let leaves = (0..64)
            .map(|index| TerminalRequestLeaf {
                account_id: format!("account-{index}"),
                request_id: format!("request-{index}"),
                request_hash: sha256(format!("request-hash-{index}").as_bytes()),
                result_hash: sha256(format!("result-hash-{index}").as_bytes()),
                receipt_hash: sha256(format!("receipt-hash-{index}").as_bytes()),
                locator: TerminalResultLocator::Journal {
                    writer_epoch: "writer-epoch-1".into(),
                    sequence: index + 1,
                },
            })
            .collect::<Vec<_>>();
        let expected = request_index_root(&leaves).unwrap();
        let mut tree = SparseRequestTree::default();
        for (index, leaf) in leaves.iter().enumerate() {
            let before = tree.proof(&leaf.account_id, &leaf.request_id).unwrap();
            assert!(before.leaf.is_none());
            tree.insert(leaf.clone()).unwrap();
            assert_eq!(tree.len(), index + 1);
        }
        assert_eq!(tree.root().unwrap(), expected);
        for leaf in &leaves {
            let proof = tree.proof(&leaf.account_id, &leaf.request_id).unwrap();
            assert_eq!(proof.leaf.as_ref(), Some(leaf));
            assert!(proof.verifies(&expected, &leaf.account_id, &leaf.request_id));
        }
        let absent = tree.proof("missing-account", "missing-request").unwrap();
        assert!(absent.leaf.is_none());
        assert!(absent.verifies(&expected, "missing-account", "missing-request"));
        assert_eq!(
            tree.insert(leaves[0].clone()),
            Err(RequestIndexError::Occupied)
        );
    }
}
