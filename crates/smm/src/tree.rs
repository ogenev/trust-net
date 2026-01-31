//! Sparse Merkle Map - the main tree structure.

use alloy_primitives::B256;

use crate::error::Result;
use crate::node::Node;
use crate::proof::SmmProof;

/// A Sparse Merkle Map - an immutable cryptographic data structure.
#[derive(Debug, Clone)]
pub struct Smm {
    root: Node,
    default_hashes: [B256; 257],
}

impl Smm {
    pub(crate) fn from_root(root: Node, default_hashes: [B256; 257]) -> Self {
        Self {
            root,
            default_hashes,
        }
    }

    /// Get the root hash of the tree.
    pub fn root(&self) -> B256 {
        self.root.hash()
    }

    /// Get default subtree hashes for heights 0..=256.
    pub fn default_hashes(&self) -> &[B256; 257] {
        &self.default_hashes
    }

    /// Generate a membership/non-membership proof for a key.
    ///
    /// - Membership: `is_membership=true` and includes `leaf_value`.
    /// - Non-membership: `is_membership=false` and `leaf_value` is empty; the leaf hash is the
    ///   empty leaf hash (bytes32(0)).
    pub fn prove(&self, key: B256) -> Result<SmmProof> {
        let mut siblings = Vec::with_capacity(256);
        let (leaf_value, is_membership) =
            Self::collect_siblings(&self.root, &key, 0, &mut siblings, &self.default_hashes);

        debug_assert_eq!(siblings.len(), 256, "Proof must have 256 siblings");
        Ok(SmmProof::new(
            key,
            leaf_value.unwrap_or_default(),
            siblings,
            is_membership,
        ))
    }

    fn collect_siblings(
        node: &Node,
        key: &B256,
        depth: usize,
        siblings: &mut Vec<B256>,
        default_hashes: &[B256; 257],
    ) -> (Option<Vec<u8>>, bool) {
        if depth == 256 {
            return match node {
                Node::Leaf {
                    key: leaf_key,
                    leaf_value,
                    ..
                } if leaf_key == key => (Some(leaf_value.clone()), true),
                _ => (None, false),
            };
        }

        match node {
            Node::Empty { .. } => {
                // Empty subtree at this depth. Fill remaining siblings with default subtree hashes.
                // siblings[depth] corresponds to sibling subtree at height (255 - depth).
                for d in depth..256 {
                    siblings.push(default_hashes[255 - d]);
                }
                (None, false)
            }

            Node::Leaf { .. } => {
                // Should not happen in full-depth tree; treat as empty for proof purposes.
                for d in depth..256 {
                    siblings.push(default_hashes[255 - d]);
                }
                (None, false)
            }

            Node::Internal { left, right, .. } => {
                let bit = get_bit(key, depth);
                if bit == 0 {
                    siblings.push(right.hash());
                    Self::collect_siblings(left, key, depth + 1, siblings, default_hashes)
                } else {
                    siblings.push(left.hash());
                    Self::collect_siblings(right, key, depth + 1, siblings, default_hashes)
                }
            }
        }
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
    use crate::builder::build_default_hashes;
    use crate::node::Node;

    #[test]
    fn test_empty_tree_root_is_default_root() {
        let defaults = build_default_hashes();
        let smm = Smm::from_root(Node::empty(defaults[256]), defaults);
        assert_eq!(smm.root(), smm.default_hashes()[256]);
        assert_ne!(smm.root(), B256::ZERO);
    }
}
