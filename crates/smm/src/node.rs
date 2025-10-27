//! Node types for the Sparse Merkle Tree.

use alloy_primitives::B256;
use trustnet_core::hashing::{compute_internal_hash, compute_leaf_hash};

/// A node in the Sparse Merkle Tree.
///
/// The tree uses three node types:
/// - `Empty`: Represents absence of data (hash = 0x000...000)
/// - `Leaf`: Contains a key-value pair with precomputed hash
/// - `Internal`: Contains two children with precomputed hash
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Empty node - represents absence of data.
    /// Hash is always zero.
    Empty,

    /// Leaf node containing a key-value pair.
    Leaf {
        /// The key (32 bytes)
        key: B256,
        /// The value (0-4, representing trust level -2 to +2)
        value: u8,
        /// Cached hash: keccak256(0x00 || key || value)
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
    /// Create a new empty node.
    pub fn empty() -> Self {
        Node::Empty
    }

    /// Create a new leaf node.
    ///
    /// # Arguments
    ///
    /// * `key` - The key (32 bytes)
    /// * `value` - The value (must be 0-4)
    ///
    /// # Panics
    ///
    /// Panics if value > 4.
    pub fn leaf(key: B256, value: u8) -> Self {
        assert!(value <= 4, "Value must be 0-4, got {}", value);
        let hash = compute_leaf_hash(&key, value);
        Node::Leaf { key, value, hash }
    }

    /// Create a new internal node from two children.
    ///
    /// Automatically computes the hash based on children.
    pub fn internal(left: Node, right: Node) -> Self {
        let left_hash = left.hash();
        let right_hash = right.hash();
        let hash = compute_internal_hash(&left_hash, &right_hash);

        Node::Internal {
            left: Box::new(left),
            right: Box::new(right),
            hash,
        }
    }

    /// Get the hash of this node.
    ///
    /// - Empty: 0x000...000
    /// - Leaf: keccak256(0x00 || key || value)
    /// - Internal: keccak256(0x01 || left.hash || right.hash)
    pub fn hash(&self) -> B256 {
        match self {
            Node::Empty => B256::ZERO,
            Node::Leaf { hash, .. } => *hash,
            Node::Internal { hash, .. } => *hash,
        }
    }

    /// Check if this node is empty.
    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }

    /// Check if this node is a leaf.
    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf { .. })
    }

    /// Check if this node is internal.
    pub fn is_internal(&self) -> bool {
        matches!(self, Node::Internal { .. })
    }

    /// Get the key and value if this is a leaf node.
    pub fn as_leaf(&self) -> Option<(B256, u8)> {
        match self {
            Node::Leaf { key, value, .. } => Some((*key, *value)),
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

    /// Compute the hash of an internal node from two child hashes.
    ///
    /// This is a helper for proof verification that doesn't require
    /// constructing actual Node objects.
    ///
    /// Returns: keccak256(0x01 || left_hash || right_hash)
    #[allow(dead_code)]
    pub(crate) fn internal_hash(left_hash: &B256, right_hash: &B256) -> B256 {
        compute_internal_hash(left_hash, right_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn test_empty_node() {
        let node = Node::empty();
        assert!(node.is_empty());
        assert_eq!(node.hash(), B256::ZERO);
        assert!(!node.is_leaf());
        assert!(!node.is_internal());
    }

    #[test]
    fn test_leaf_node() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 2u8;
        let node = Node::leaf(key, value);

        assert!(node.is_leaf());
        assert!(!node.is_empty());
        assert!(!node.is_internal());

        let (leaf_key, leaf_value) = node.as_leaf().unwrap();
        assert_eq!(leaf_key, key);
        assert_eq!(leaf_value, value);

        // Hash should be non-zero
        assert_ne!(node.hash(), B256::ZERO);
    }

    #[test]
    #[should_panic(expected = "Value must be 0-4")]
    fn test_leaf_node_invalid_value() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        Node::leaf(key, 5); // Should panic
    }

    #[test]
    fn test_leaf_node_all_valid_values() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        for value in 0..=4 {
            let node = Node::leaf(key, value);
            assert!(node.is_leaf());
            assert_eq!(node.as_leaf().unwrap().1, value);
        }
    }

    #[test]
    fn test_internal_node() {
        let left = Node::leaf(
            b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            2,
        );
        let right = Node::leaf(
            b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            3,
        );

        let internal = Node::internal(left.clone(), right.clone());

        assert!(internal.is_internal());
        assert!(!internal.is_empty());
        assert!(!internal.is_leaf());

        let (int_left, int_right) = internal.as_internal().unwrap();
        assert_eq!(int_left, &left);
        assert_eq!(int_right, &right);

        // Hash should be computed from children
        assert_ne!(internal.hash(), B256::ZERO);
        assert_ne!(internal.hash(), left.hash());
        assert_ne!(internal.hash(), right.hash());
    }

    #[test]
    fn test_internal_with_empty_children() {
        let left = Node::empty();
        let right = Node::empty();
        let internal = Node::internal(left, right);

        assert!(internal.is_internal());
        // Hash of internal(empty, empty) should be hash of (0x00...00, 0x00...00)
        assert_ne!(internal.hash(), B256::ZERO);
    }

    #[test]
    fn test_internal_mixed_children() {
        let left = Node::leaf(
            b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            1,
        );
        let right = Node::empty();
        let internal = Node::internal(left, right);

        assert!(internal.is_internal());
        let (int_left, int_right) = internal.as_internal().unwrap();
        assert!(int_left.is_leaf());
        assert!(int_right.is_empty());
    }

    #[test]
    fn test_hash_determinism() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 2u8;

        let node1 = Node::leaf(key, value);
        let node2 = Node::leaf(key, value);

        assert_eq!(node1.hash(), node2.hash());
    }

    #[test]
    fn test_different_values_different_hashes() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        let node0 = Node::leaf(key, 0);
        let node1 = Node::leaf(key, 1);
        let node2 = Node::leaf(key, 2);

        assert_ne!(node0.hash(), node1.hash());
        assert_ne!(node1.hash(), node2.hash());
        assert_ne!(node0.hash(), node2.hash());
    }

    #[test]
    fn test_different_keys_different_hashes() {
        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");
        let value = 2u8;

        let node1 = Node::leaf(key1, value);
        let node2 = Node::leaf(key2, value);

        assert_ne!(node1.hash(), node2.hash());
    }
}
