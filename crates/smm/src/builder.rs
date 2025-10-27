//! Builder for constructing Sparse Merkle Maps.

use alloy_primitives::B256;
use std::collections::HashMap;

use crate::error::{Result, SmmError};
use crate::node::Node;
use crate::Smm;

/// Builder for constructing a Sparse Merkle Map.
///
/// The builder collects key-value pairs and then constructs
/// the complete tree when `build()` is called.
///
/// # Examples
///
/// ```
/// use trustnet_smm::SmmBuilder;
/// use alloy_primitives::B256;
///
/// let mut builder = SmmBuilder::new();
/// builder.insert(B256::from([0x01; 32]), 2).unwrap();
/// builder.insert(B256::from([0x02; 32]), 3).unwrap();
/// let smm = builder.build();
/// ```
#[derive(Debug, Clone)]
pub struct SmmBuilder {
    /// Collected leaves: key -> value
    leaves: HashMap<B256, u8>,
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
    /// If the key already exists, the value is updated.
    ///
    /// # Arguments
    ///
    /// * `key` - The key (32 bytes)
    /// * `value` - The value (must be 0-4, representing trust levels -2 to +2)
    ///
    /// # Errors
    ///
    /// Returns `SmmError::InvalidValue` if value > 4.
    ///
    /// # Examples
    ///
    /// ```
    /// use trustnet_smm::SmmBuilder;
    /// use alloy_primitives::B256;
    ///
    /// let mut builder = SmmBuilder::new();
    /// builder.insert(B256::from([0x01; 32]), 2).unwrap();
    /// ```
    pub fn insert(&mut self, key: B256, value: u8) -> Result<&mut Self> {
        if value > 4 {
            return Err(SmmError::InvalidValue(value));
        }
        self.leaves.insert(key, value);
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
    /// This constructs a full 256-level Sparse Merkle Tree from all inserted leaves.
    /// Every leaf is placed at depth 256, with a complete path of Internal nodes
    /// from root to leaf. This ensures proofs are always exactly 256 siblings.
    ///
    /// # Examples
    ///
    /// ```
    /// use trustnet_smm::SmmBuilder;
    /// use alloy_primitives::B256;
    ///
    /// let mut builder = SmmBuilder::new();
    /// builder.insert(B256::from([0x01; 32]), 2).unwrap();
    /// let smm = builder.build();
    /// let root = smm.root();
    /// ```
    pub fn build(self) -> Smm {
        let mut root = Node::empty();

        // Insert each leaf into the tree
        for (key, value) in self.leaves {
            root = Self::insert_leaf(root, key, value, 0);
        }

        Smm::from_root(root)
    }

    /// Insert a leaf into a full 256-level Sparse Merkle Tree.
    ///
    /// This creates a complete path of Internal nodes from root to leaf (depth 256).
    /// At each level, we follow the key bit to determine left (0) or right (1).
    fn insert_leaf(node: Node, key: B256, value: u8, depth: usize) -> Node {
        // Base case: at depth 256, place the leaf
        if depth == 256 {
            return Node::leaf(key, value);
        }

        let bit = Self::get_bit(&key, depth);

        match node {
            Node::Empty => {
                // Create a full path to the leaf
                if bit == 0 {
                    let left = Self::insert_leaf(Node::empty(), key, value, depth + 1);
                    Node::internal(left, Node::empty())
                } else {
                    let right = Self::insert_leaf(Node::empty(), key, value, depth + 1);
                    Node::internal(Node::empty(), right)
                }
            }

            Node::Leaf {
                key: existing_key,
                value: existing_value,
                ..
            } => {
                // We hit a leaf before depth 256 - this shouldn't happen in a full SMT
                // But handle it anyway: push the existing leaf down and insert new one
                if existing_key == key {
                    // Same key - update by creating new path with new value
                    return Self::insert_leaf(Node::empty(), key, value, depth);
                }

                // Different keys - push existing leaf down and insert both
                let existing_bit = Self::get_bit(&existing_key, depth);

                if bit == existing_bit {
                    // Same bit - recurse deeper
                    let existing_node =
                        Self::insert_leaf(Node::empty(), existing_key, existing_value, depth + 1);
                    let child = Self::insert_leaf(existing_node, key, value, depth + 1);

                    if bit == 0 {
                        Node::internal(child, Node::empty())
                    } else {
                        Node::internal(Node::empty(), child)
                    }
                } else {
                    // Different bits - place both leaves at their positions
                    let left = if bit == 0 {
                        Self::insert_leaf(Node::empty(), key, value, depth + 1)
                    } else {
                        Self::insert_leaf(Node::empty(), existing_key, existing_value, depth + 1)
                    };

                    let right = if bit == 1 {
                        Self::insert_leaf(Node::empty(), key, value, depth + 1)
                    } else {
                        Self::insert_leaf(Node::empty(), existing_key, existing_value, depth + 1)
                    };

                    Node::internal(left, right)
                }
            }

            Node::Internal { left, right, .. } => {
                // Recurse into the correct child based on bit
                if bit == 0 {
                    let new_left = Self::insert_leaf(*left, key, value, depth + 1);
                    Node::internal(new_left, *right)
                } else {
                    let new_right = Self::insert_leaf(*right, key, value, depth + 1);
                    Node::internal(*left, new_right)
                }
            }
        }
    }

    /// Get the bit at the given index in the key.
    ///
    /// Bits are numbered 0-255, with 0 being the MSB.
    fn get_bit(key: &B256, index: usize) -> u8 {
        let byte_index = index / 8;
        let bit_index = 7 - (index % 8); // MSB first within each byte
        (key[byte_index] >> bit_index) & 1
    }
}

impl Default for SmmBuilder {
    fn default() -> Self {
        Self::new()
    }
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
        builder.insert(key, 2).unwrap();

        assert!(!builder.is_empty());
        assert_eq!(builder.len(), 1);
    }

    #[test]
    fn test_insert_multiple() {
        let mut builder = SmmBuilder::new();
        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        builder.insert(key1, 2).unwrap();
        builder.insert(key2, 3).unwrap();

        assert_eq!(builder.len(), 2);
    }

    #[test]
    fn test_insert_overwrite() {
        let mut builder = SmmBuilder::new();
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        builder.insert(key, 2).unwrap();
        assert_eq!(builder.len(), 1);

        builder.insert(key, 3).unwrap();
        assert_eq!(builder.len(), 1); // Still 1, not 2
    }

    #[test]
    fn test_insert_all_valid_values() {
        let mut builder = SmmBuilder::new();
        let base_key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        for value in 0..=4 {
            // Create unique key for each value
            let mut key_bytes = base_key.0;
            key_bytes[31] = value;
            let key = B256::from(key_bytes);

            let result = builder.insert(key, value);
            assert!(result.is_ok());
        }

        assert_eq!(builder.len(), 5);
    }

    #[test]
    fn test_insert_invalid_value() {
        let mut builder = SmmBuilder::new();
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        let result = builder.insert(key, 5);
        assert!(result.is_err());

        match result {
            Err(SmmError::InvalidValue(5)) => (),
            _ => panic!("Expected InvalidValue(5) error"),
        }

        assert_eq!(builder.len(), 0); // Should not have inserted
    }

    #[test]
    fn test_insert_invalid_values() {
        let mut builder = SmmBuilder::new();
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        for invalid_value in [5, 10, 100, 255] {
            let result = builder.insert(key, invalid_value);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_insert_chainable() {
        let mut builder = SmmBuilder::new();
        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        builder.insert(key1, 2).unwrap().insert(key2, 3).unwrap();

        assert_eq!(builder.len(), 2);
    }

    #[test]
    fn test_build_empty() {
        let builder = SmmBuilder::new();
        let smm = builder.build();
        // Empty tree should have zero root
        assert_eq!(smm.root(), B256::ZERO);
        assert!(smm.is_empty());
    }

    #[test]
    fn test_build_single_leaf() {
        let mut builder = SmmBuilder::new();
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        builder.insert(key, 2).unwrap();

        let smm = builder.build();
        // Single leaf tree should have non-zero root
        assert!(!smm.is_empty());
        assert_ne!(smm.root(), B256::ZERO);

        // In a full 256-level SMT, root is always Internal (not a leaf)
        let root_node = smm.root_node();
        assert!(root_node.is_internal());

        // But we should be able to prove the leaf exists
        let proof = smm.prove(key).unwrap();
        assert_eq!(proof.value(), 2);
        assert!(proof.verify(smm.root()));
    }

    #[test]
    fn test_build_two_leaves_different_first_bit() {
        let mut builder = SmmBuilder::new();
        // Keys with different first bits: 0xxx vs 1xxx
        let key1 = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let key2 = b256!("8000000000000000000000000000000000000000000000000000000000000002");

        builder.insert(key1, 2).unwrap();
        builder.insert(key2, 3).unwrap();

        let smm = builder.build();
        assert!(!smm.is_empty());

        // Root should be an internal node
        let root_node = smm.root_node();
        assert!(root_node.is_internal());

        // In a full 256-level SMT, children of root are also Internal nodes
        // (not leaves directly at depth 1)
        let (left, right) = root_node.as_internal().unwrap();
        assert!(left.is_internal());
        assert!(right.is_internal());

        // But we can prove both keys exist
        let proof1 = smm.prove(key1).unwrap();
        let proof2 = smm.prove(key2).unwrap();
        assert_eq!(proof1.value(), 2);
        assert_eq!(proof2.value(), 3);
        assert!(proof1.verify(smm.root()));
        assert!(proof2.verify(smm.root()));
    }

    #[test]
    fn test_build_two_leaves_same_first_bit() {
        let mut builder = SmmBuilder::new();
        // Both start with 0, but differ at bit 1
        let key1 = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        let key2 = b256!("4000000000000000000000000000000000000000000000000000000000000002");

        builder.insert(key1, 2).unwrap();
        builder.insert(key2, 3).unwrap();

        let smm = builder.build();

        // Root should be internal with left child (bit 0 = 0)
        let root_node = smm.root_node();
        assert!(root_node.is_internal());

        let (left, right) = root_node.as_internal().unwrap();
        // Both keys start with 0, so left should be internal, right should be empty
        assert!(left.is_internal());
        assert!(right.is_empty());
    }

    #[test]
    fn test_build_multiple_leaves() {
        let mut builder = SmmBuilder::new();
        let keys = [
            b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            b256!("3333333333333333333333333333333333333333333333333333333333333333"),
            b256!("4444444444444444444444444444444444444444444444444444444444444444"),
        ];

        for (i, key) in keys.iter().enumerate() {
            builder.insert(*key, i as u8).unwrap();
        }

        let smm = builder.build();
        assert!(!smm.is_empty());
        assert_ne!(smm.root(), B256::ZERO);

        // Root should be internal
        assert!(smm.root_node().is_internal());
    }

    #[test]
    fn test_build_deterministic() {
        let keys = [
            b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            b256!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        ];

        // Build tree 1
        let mut builder1 = SmmBuilder::new();
        for (i, key) in keys.iter().enumerate() {
            builder1.insert(*key, (i % 5) as u8).unwrap();
        }
        let smm1 = builder1.build();

        // Build tree 2 with same data
        let mut builder2 = SmmBuilder::new();
        for (i, key) in keys.iter().enumerate() {
            builder2.insert(*key, (i % 5) as u8).unwrap();
        }
        let smm2 = builder2.build();

        // Should produce same root hash
        assert_eq!(smm1.root(), smm2.root());
    }

    #[test]
    fn test_build_different_insertion_order() {
        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        // Build tree 1: insert key1 then key2
        let mut builder1 = SmmBuilder::new();
        builder1.insert(key1, 2).unwrap();
        builder1.insert(key2, 3).unwrap();
        let smm1 = builder1.build();

        // Build tree 2: insert key2 then key1
        let mut builder2 = SmmBuilder::new();
        builder2.insert(key2, 3).unwrap();
        builder2.insert(key1, 2).unwrap();
        let smm2 = builder2.build();

        // Should produce same root hash regardless of insertion order
        assert_eq!(smm1.root(), smm2.root());
    }

    #[test]
    fn test_build_update_value() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        // Insert with value 2
        let mut builder1 = SmmBuilder::new();
        builder1.insert(key, 2).unwrap();
        let smm1 = builder1.build();

        // Insert with value 3
        let mut builder2 = SmmBuilder::new();
        builder2.insert(key, 3).unwrap();
        let smm2 = builder2.build();

        // Different values should produce different roots
        assert_ne!(smm1.root(), smm2.root());
    }

    #[test]
    fn test_build_overwrite_in_builder() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        let mut builder = SmmBuilder::new();
        builder.insert(key, 2).unwrap();
        builder.insert(key, 3).unwrap(); // Overwrite
        let smm = builder.build();

        // Should have single leaf with value 3 (at depth 256)
        let proof = smm.prove(key).unwrap();
        assert_eq!(proof.value(), 3);
        assert!(proof.verify(smm.root()));
    }

    #[test]
    fn test_get_bit() {
        // Test bit extraction
        let key = b256!("8000000000000000000000000000000000000000000000000000000000000000");
        // 0x80 = 10000000, so first bit is 1
        assert_eq!(SmmBuilder::get_bit(&key, 0), 1);
        assert_eq!(SmmBuilder::get_bit(&key, 1), 0);

        let key = b256!("4000000000000000000000000000000000000000000000000000000000000000");
        // 0x40 = 01000000, so first bit is 0, second is 1
        assert_eq!(SmmBuilder::get_bit(&key, 0), 0);
        assert_eq!(SmmBuilder::get_bit(&key, 1), 1);

        let key = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        // All zeros except last bit
        assert_eq!(SmmBuilder::get_bit(&key, 0), 0);
        assert_eq!(SmmBuilder::get_bit(&key, 255), 1);
    }

    #[test]
    fn test_default() {
        let builder = SmmBuilder::default();
        assert!(builder.is_empty());
    }

    /// Demonstrates the Alice→Bob→Charlie two-hop trust scenario.
    ///
    /// This test shows how the SMM stores trust edges and generates
    /// proofs for verification.
    #[test]
    fn test_two_hop_trust_scenario() {
        use alloy_primitives::keccak256;

        // Setup: Three agents
        let alice = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let bob = b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let charlie = b256!("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

        // Edge 1: Alice trusts Bob at level +1 (value=3)
        let alice_bob_key = keccak256([alice.as_slice(), bob.as_slice()].concat());
        let alice_bob_level = 3u8; // +1

        // Edge 2: Bob trusts Charlie at level +2 (value=4)
        let bob_charlie_key = keccak256([bob.as_slice(), charlie.as_slice()].concat());
        let bob_charlie_level = 4u8; // +2

        // Build the SMM with both edges
        let mut builder = SmmBuilder::new();
        builder.insert(alice_bob_key, alice_bob_level).unwrap();
        builder.insert(bob_charlie_key, bob_charlie_level).unwrap();

        let smm = builder.build();

        // The root hash commits to both trust edges
        let root = smm.root();
        assert_ne!(root, B256::ZERO);

        // Generate proofs for both edges
        let proof_alice_bob = smm.prove(alice_bob_key).unwrap();
        let proof_bob_charlie = smm.prove(bob_charlie_key).unwrap();

        // Verify both proofs
        assert!(proof_alice_bob.verify(root));
        assert!(proof_bob_charlie.verify(root));

        // Extract trust levels
        assert_eq!(proof_alice_bob.value(), 3); // lOB = +1
        assert_eq!(proof_bob_charlie.value(), 4); // lBC = +2

        // In the contract, this would compute:
        // score = (2 * lOB + lBC * lBC) / 2
        //       = (2 * 1  + 2 * 2)  / 2
        //       = (2 + 4) / 2
        //       = 3 → clamped to +2
        //
        // This proves Alice trusts Charlie at effective level +2 (via Bob)
    }

    /// Demonstrates non-membership proof scenario (Alice has no opinion about Charlie).
    #[test]
    fn test_non_membership_scenario() {
        use alloy_primitives::keccak256;

        let alice = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let bob = b256!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let charlie = b256!("1111111111111111111111111111111111111111111111111111111111111111");

        // Only add Alice→Bob edge
        let alice_bob_key = keccak256([alice.as_slice(), bob.as_slice()].concat());
        let mut builder = SmmBuilder::new();
        builder.insert(alice_bob_key, 3).unwrap();
        let smm = builder.build();

        // Alice→Charlie edge does NOT exist
        let alice_charlie_key = keccak256([alice.as_slice(), charlie.as_slice()].concat());

        // Generate proof for non-existent key
        let proof = smm.prove(alice_charlie_key).unwrap();

        // Should prove default value (level 0)
        assert_eq!(proof.value(), 2);

        // Should verify against the root
        assert!(proof.verify(smm.root()));

        // The proof cryptographically proves that alice_charlie_key
        // either leads to an Empty node OR to a different leaf (alice_bob_key).
        // Either way, the default value of 2 (level 0) is proven.
    }
}
