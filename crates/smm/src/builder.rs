//! Builder for constructing Sparse Merkle Maps (256-bit keys).

use alloy_primitives::B256;
use std::collections::HashMap;

use crate::error::{Result, SmmError};
use crate::node::Node;
use crate::tree::Smm;

/// Build default subtree hashes for heights 0..=256.
///
/// - `defaults[0]` is the empty leaf hash `keccak256(0x02)`.
/// - `defaults[h+1] = keccak256(0x01 || defaults[h] || defaults[h])`.
pub(crate) fn build_default_hashes() -> [B256; 257] {
    let mut defaults = [B256::ZERO; 257];
    defaults[0] = trustnet_core::hashing::compute_empty_hash();
    for height in 0..256 {
        defaults[height + 1] =
            trustnet_core::hashing::compute_internal_hash(&defaults[height], &defaults[height]);
    }
    defaults
}

/// Builder for constructing a Sparse Merkle Map.
#[derive(Debug, Clone)]
pub struct SmmBuilder {
    /// Collected leaves: key -> leafValue bytes
    leaves: HashMap<B256, Vec<u8>>,
}

impl SmmBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
        }
    }

    /// Insert a key-value pair into the builder.
    ///
    /// `leaf_value` must be non-empty to avoid ambiguity with non-membership (empty leaf).
    pub fn insert(&mut self, key: B256, leaf_value: Vec<u8>) -> Result<&mut Self> {
        if leaf_value.is_empty() {
            return Err(SmmError::EmptyLeafValue);
        }
        self.leaves.insert(key, leaf_value);
        Ok(self)
    }

    /// Get the number of leaves in the builder.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the builder is empty (no leaves).
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Build the Sparse Merkle Map.
    ///
    /// This constructs a full 256-level Sparse Merkle Tree commitment (sparse representation),
    /// using default subtree hashes for empty branches.
    pub fn build(self) -> Smm {
        let default_hashes = build_default_hashes();
        let mut root = Node::empty(default_hashes[256]);

        for (key, leaf_value) in self.leaves {
            root = Self::insert_leaf(root, key, leaf_value, 0, &default_hashes);
        }

        Smm::from_root(root, default_hashes)
    }

    fn insert_leaf(
        node: Node,
        key: B256,
        leaf_value: Vec<u8>,
        depth: usize,
        default_hashes: &[B256; 257],
    ) -> Node {
        if depth == 256 {
            return Node::leaf(key, leaf_value);
        }

        let bit = get_bit(&key, depth);
        let child_height = 256 - (depth + 1);

        match node {
            Node::Empty { .. } => {
                if bit == 0 {
                    let left = Self::insert_leaf(
                        Node::empty(default_hashes[child_height]),
                        key,
                        leaf_value,
                        depth + 1,
                        default_hashes,
                    );
                    let right = Node::empty(default_hashes[child_height]);
                    Node::internal(left, right)
                } else {
                    let left = Node::empty(default_hashes[child_height]);
                    let right = Self::insert_leaf(
                        Node::empty(default_hashes[child_height]),
                        key,
                        leaf_value,
                        depth + 1,
                        default_hashes,
                    );
                    Node::internal(left, right)
                }
            }

            Node::Internal { left, right, .. } => {
                if bit == 0 {
                    let new_left =
                        Self::insert_leaf(*left, key, leaf_value, depth + 1, default_hashes);
                    Node::internal(new_left, *right)
                } else {
                    let new_right =
                        Self::insert_leaf(*right, key, leaf_value, depth + 1, default_hashes);
                    Node::internal(*left, new_right)
                }
            }

            Node::Leaf {
                key: existing_key,
                leaf_value: existing_leaf_value,
                ..
            } => {
                // Should not occur in a correctly constructed full-depth tree, but be robust:
                // rebuild this subtree from scratch at this depth.
                let mut subtree = Node::empty(default_hashes[256 - depth]);
                subtree = Self::insert_leaf(
                    subtree,
                    existing_key,
                    existing_leaf_value,
                    depth,
                    default_hashes,
                );
                Self::insert_leaf(subtree, key, leaf_value, depth, default_hashes)
            }
        }
    }
}

impl Default for SmmBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn get_bit(key: &B256, index: usize) -> u8 {
    let byte_index = index / 8;
    let bit_index = 7 - (index % 8);
    (key[byte_index] >> bit_index) & 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn test_new_builder() {
        let builder = SmmBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
    }

    #[test]
    fn test_insert_single() {
        let mut builder = SmmBuilder::new();
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        builder.insert(key, vec![2u8]).unwrap();
        assert_eq!(builder.len(), 1);
    }

    #[test]
    fn test_insert_reject_empty_leaf_value() {
        let mut builder = SmmBuilder::new();
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert!(matches!(
            builder.insert(key, vec![]).unwrap_err(),
            SmmError::EmptyLeafValue
        ));
    }

    #[test]
    fn test_build_deterministic() {
        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        let mut b1 = SmmBuilder::new();
        b1.insert(key1, vec![2u8]).unwrap();
        b1.insert(key2, vec![3u8]).unwrap();

        let mut b2 = SmmBuilder::new();
        b2.insert(key2, vec![3u8]).unwrap();
        b2.insert(key1, vec![2u8]).unwrap();

        assert_eq!(b1.build().root(), b2.build().root());
    }
}
