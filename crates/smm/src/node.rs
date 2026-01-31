//! Node types for the Sparse Merkle Map.

use alloy_primitives::B256;
use trustnet_core::hashing::{compute_internal_hash, compute_leaf_hash};

/// A node in the Sparse Merkle Tree.
///
/// The tree uses three node types:
/// - `Empty`: Represents an empty subtree at a specific height (hash is precomputed).
/// - `Leaf`: Contains a key and its leaf value bytes.
/// - `Internal`: Contains two children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Empty subtree (hash depends on height and is precomputed by the builder).
    Empty {
        /// Cached hash for this empty subtree.
        hash: B256,
    },

    /// Leaf node containing a key and leaf value bytes.
    Leaf {
        /// The key (32 bytes)
        key: B256,
        /// The leaf value bytes (format defined by higher layers)
        leaf_value: Vec<u8>,
        /// Cached hash: keccak256(0x00 || key || leafValueBytes)
        hash: B256,
    },

    /// Internal node with two children.
    Internal {
        /// Left child (represents key bit = 0)
        left: Box<Node>,
        /// Right child (represents key bit = 1)
        right: Box<Node>,
        /// Cached hash: keccak256(0x01 || left.hash || right.hash)
        hash: B256,
    },
}

impl Node {
    /// Create a new empty subtree node with a precomputed hash.
    pub fn empty(hash: B256) -> Self {
        Self::Empty { hash }
    }

    /// Create a new leaf node.
    pub fn leaf(key: B256, leaf_value: Vec<u8>) -> Self {
        assert!(!leaf_value.is_empty(), "Leaf value must not be empty");
        let hash = compute_leaf_hash(&key, &leaf_value);
        Self::Leaf {
            key,
            leaf_value,
            hash,
        }
    }

    /// Create a new internal node from two children.
    pub fn internal(left: Node, right: Node) -> Self {
        let left_hash = left.hash();
        let right_hash = right.hash();
        let hash = compute_internal_hash(&left_hash, &right_hash);

        Self::Internal {
            left: Box::new(left),
            right: Box::new(right),
            hash,
        }
    }

    /// Get the hash of this node.
    pub fn hash(&self) -> B256 {
        match self {
            Node::Empty { hash } => *hash,
            Node::Leaf { hash, .. } => *hash,
            Node::Internal { hash, .. } => *hash,
        }
    }

    /// Check if this node is empty.
    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty { .. })
    }

    /// Get the key and leaf value if this is a leaf node.
    pub fn as_leaf(&self) -> Option<(B256, &[u8])> {
        match self {
            Node::Leaf {
                key, leaf_value, ..
            } => Some((*key, leaf_value.as_slice())),
            _ => None,
        }
    }

    /// Get references to children if this is an internal node.
    pub fn as_internal(&self) -> Option<(&Node, &Node)> {
        match self {
            Node::Internal { left, right, .. } => Some((left, right)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn test_empty_node() {
        let node = Node::empty(B256::ZERO);
        assert!(node.is_empty());
        assert_eq!(node.hash(), B256::ZERO);
    }

    #[test]
    fn test_leaf_node() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let leaf_value = vec![2u8];
        let node = Node::leaf(key, leaf_value.clone());

        let (k, v) = node.as_leaf().unwrap();
        assert_eq!(k, key);
        assert_eq!(v, leaf_value.as_slice());
        assert_ne!(node.hash(), B256::ZERO);
    }

    #[test]
    fn test_internal_node() {
        let left = Node::leaf(
            b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            vec![2u8],
        );
        let right = Node::leaf(
            b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            vec![3u8],
        );

        let internal = Node::internal(left.clone(), right.clone());
        let (int_left, int_right) = internal.as_internal().unwrap();
        assert_eq!(int_left, &left);
        assert_eq!(int_right, &right);
        assert_ne!(internal.hash(), B256::ZERO);
    }
}
