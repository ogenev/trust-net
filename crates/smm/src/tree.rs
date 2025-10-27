//! Sparse Merkle Map - the main tree structure.

use alloy_primitives::B256;

use crate::error::Result;
use crate::node::Node;
use crate::proof::SmmProof;

/// A Sparse Merkle Map - an immutable cryptographic data structure.
///
/// The SMM provides:
/// - Deterministic root computation from key-value pairs
/// - Compact membership and non-membership proofs
/// - Default value handling (missing keys default to value 2, representing level 0)
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
#[derive(Debug, Clone)]
pub struct Smm {
    /// The root node of the tree
    root: Node,
}

impl Smm {
    /// Create an SMM from a root node.
    ///
    /// This is internal - users should use `SmmBuilder` instead.
    pub(crate) fn from_root(root: Node) -> Self {
        Self { root }
    }

    /// Get the root hash of the tree.
    ///
    /// This is the cryptographic commitment to the entire tree.
    ///
    /// # Examples
    ///
    /// ```
    /// use trustnet_smm::SmmBuilder;
    /// use alloy_primitives::B256;
    ///
    /// let smm = SmmBuilder::new().build();
    /// let root = smm.root();
    /// assert_eq!(root, B256::ZERO); // Empty tree has zero root
    /// ```
    pub fn root(&self) -> B256 {
        self.root.hash()
    }

    /// Check if the tree is empty (no leaves).
    pub fn is_empty(&self) -> bool {
        self.root.is_empty()
    }

    /// Get a reference to the root node (for internal use).
    #[allow(dead_code)]
    pub(crate) fn root_node(&self) -> &Node {
        &self.root
    }

    /// Generate a membership proof for a key.
    ///
    /// This proves that the key has a specific value in the tree.
    /// If the key doesn't exist, it proves the default value (2, representing level 0).
    ///
    /// # Arguments
    ///
    /// * `key` - The key to generate a proof for
    ///
    /// # Examples
    ///
    /// ```
    /// use trustnet_smm::SmmBuilder;
    /// use alloy_primitives::B256;
    ///
    /// let mut builder = SmmBuilder::new();
    /// let key = B256::from([0x01; 32]);
    /// builder.insert(key, 2).unwrap();
    /// let smm = builder.build();
    ///
    /// let proof = smm.prove(key).unwrap();
    /// assert!(proof.verify(smm.root()));
    /// assert_eq!(proof.value(), 2);
    /// ```
    pub fn prove(&self, key: B256) -> Result<SmmProof> {
        let mut siblings = Vec::with_capacity(256);
        let (value, _depth, is_membership) =
            Self::collect_siblings(&self.root, &key, 0, &mut siblings);

        // In a full 256-level SMT, we should have exactly 256 siblings
        // If we don't (due to the tree being empty or malformed), pad with zeros
        while siblings.len() < 256 {
            siblings.push(B256::ZERO);
        }

        // Sanity check
        debug_assert_eq!(siblings.len(), 256, "Proof must have exactly 256 siblings");

        Ok(SmmProof::new(key, value, siblings, is_membership))
    }

    /// Recursively collect siblings along the path to a key in a full 256-level SMT.
    ///
    /// Always collects exactly 256 siblings (one for each level).
    /// Returns (value, depth, is_membership) where:
    /// - value: the value at the key (or default value 2 if not found)
    /// - depth: the final depth reached
    /// - is_membership: true if key was actually found, false otherwise
    fn collect_siblings(
        node: &Node,
        key: &B256,
        depth: usize,
        siblings: &mut Vec<B256>,
    ) -> (u8, usize, bool) {
        // Base case: reached depth 256, should find a leaf
        if depth == 256 {
            return match node {
                Node::Leaf {
                    key: leaf_key,
                    value: leaf_value,
                    ..
                } if leaf_key == key => {
                    // Found the key!
                    (*leaf_value, depth, true) // is_membership = true
                }
                _ => {
                    // Key not found at this position
                    (2, depth, false) // Default value, is_membership = false
                }
            };
        }

        let bit = get_bit(key, depth);

        match node {
            Node::Empty => {
                // Empty subtree - key doesn't exist
                // Add zero siblings for remaining depths and continue to collect all 256
                for _ in depth..256 {
                    siblings.push(B256::ZERO);
                }
                (2, 256, false) // Default value, reached "virtual" depth 256, non-membership
            }

            Node::Leaf { .. } => {
                // Hit a leaf before depth 256 - this shouldn't happen in properly built full SMT
                // But handle it: treat as if path continues with Empty nodes
                for _ in depth..256 {
                    siblings.push(B256::ZERO);
                }
                (2, 256, false) // Default value, non-membership
            }

            Node::Internal { left, right, .. } => {
                // Navigate based on key bit
                if bit == 0 {
                    // Going left - right is sibling
                    siblings.push(right.hash());
                    Self::collect_siblings(left, key, depth + 1, siblings)
                } else {
                    // Going right - left is sibling
                    siblings.push(left.hash());
                    Self::collect_siblings(right, key, depth + 1, siblings)
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn test_empty_tree() {
        let smm = Smm::from_root(Node::empty());
        assert!(smm.is_empty());
        assert_eq!(smm.root(), B256::ZERO);
    }

    #[test]
    fn test_single_leaf_tree() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 2u8;
        let leaf = Node::leaf(key, value);
        let smm = Smm::from_root(leaf.clone());

        assert!(!smm.is_empty());
        assert_eq!(smm.root(), leaf.hash());
        assert_ne!(smm.root(), B256::ZERO);
    }

    #[test]
    fn test_internal_node_tree() {
        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        let left = Node::leaf(key1, 2);
        let right = Node::leaf(key2, 3);
        let root = Node::internal(left, right);

        let smm = Smm::from_root(root.clone());

        assert!(!smm.is_empty());
        assert_eq!(smm.root(), root.hash());
        assert_ne!(smm.root(), B256::ZERO);
    }

    #[test]
    fn test_deterministic_root() {
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let value = 2u8;
        let leaf = Node::leaf(key, value);

        let smm1 = Smm::from_root(leaf.clone());
        let smm2 = Smm::from_root(leaf);

        assert_eq!(smm1.root(), smm2.root());
    }

    #[test]
    fn test_prove_empty_tree() {
        let smm = Smm::from_root(Node::empty());
        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        let proof = smm.prove(key).unwrap();

        // Should prove default value
        assert_eq!(proof.value(), 2);
        assert_eq!(proof.siblings().len(), 256);

        // Should verify against root
        assert!(proof.verify(smm.root()));
    }

    #[test]
    fn test_prove_single_leaf_found() {
        use crate::SmmBuilder;

        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let mut builder = SmmBuilder::new();
        builder.insert(key, 3).unwrap();
        let smm = builder.build();

        let proof = smm.prove(key).unwrap();

        // Should prove the actual value
        assert_eq!(proof.value(), 3);
        assert_eq!(proof.key(), key);
        assert_eq!(proof.siblings().len(), 256);

        // Should verify against root
        assert!(proof.verify(smm.root()));
    }

    #[test]
    fn test_prove_single_leaf_not_found() {
        use crate::SmmBuilder;

        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        let mut builder = SmmBuilder::new();
        builder.insert(key1, 3).unwrap();
        let smm = builder.build();

        // Prove a key that doesn't exist
        let proof = smm.prove(key2).unwrap();

        // Should prove default value
        assert_eq!(proof.value(), 2);
        assert_eq!(proof.key(), key2);

        // Should verify against root
        assert!(proof.verify(smm.root()));
    }

    #[test]
    fn test_prove_multiple_leaves() {
        use crate::SmmBuilder;

        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");
        let key3 = b256!("3333333333333333333333333333333333333333333333333333333333333333");

        let mut builder = SmmBuilder::new();
        builder.insert(key1, 1).unwrap();
        builder.insert(key2, 2).unwrap();
        builder.insert(key3, 3).unwrap();
        let smm = builder.build();

        // Prove all three keys
        for (key, expected_value) in [(key1, 1), (key2, 2), (key3, 3)] {
            let proof = smm.prove(key).unwrap();
            assert_eq!(proof.value(), expected_value);
            assert_eq!(proof.key(), key);
            assert!(proof.verify(smm.root()));
        }
    }

    #[test]
    fn test_prove_non_existent_key() {
        use crate::SmmBuilder;

        let key1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let key2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");
        let non_existent =
            b256!("9999999999999999999999999999999999999999999999999999999999999999");

        let mut builder = SmmBuilder::new();
        builder.insert(key1, 1).unwrap();
        builder.insert(key2, 2).unwrap();
        let smm = builder.build();

        // Prove a key that doesn't exist
        let proof = smm.prove(non_existent).unwrap();

        // Should prove default value
        assert_eq!(proof.value(), 2);
        assert!(proof.verify(smm.root()));
    }

    #[test]
    fn test_proof_fails_with_wrong_root() {
        use crate::SmmBuilder;

        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let mut builder = SmmBuilder::new();
        builder.insert(key, 3).unwrap();
        let smm = builder.build();

        let proof = smm.prove(key).unwrap();

        // Should verify with correct root
        assert!(proof.verify(smm.root()));

        // Should fail with wrong root
        let wrong_root = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        assert!(!proof.verify(wrong_root));
    }

    #[test]
    fn test_proof_deterministic() {
        use crate::SmmBuilder;

        let key = b256!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

        // Build same tree twice
        let mut builder1 = SmmBuilder::new();
        builder1.insert(key, 3).unwrap();
        let smm1 = builder1.build();

        let mut builder2 = SmmBuilder::new();
        builder2.insert(key, 3).unwrap();
        let smm2 = builder2.build();

        // Proofs should be identical
        let proof1 = smm1.prove(key).unwrap();
        let proof2 = smm2.prove(key).unwrap();

        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_get_bit() {
        let key = b256!("8000000000000000000000000000000000000000000000000000000000000000");
        // 0x80 = 10000000, so first bit is 1
        assert_eq!(get_bit(&key, 0), 1);
        assert_eq!(get_bit(&key, 1), 0);

        let key = b256!("4000000000000000000000000000000000000000000000000000000000000000");
        // 0x40 = 01000000, so first bit is 0, second is 1
        assert_eq!(get_bit(&key, 0), 0);
        assert_eq!(get_bit(&key, 1), 1);

        let key = b256!("0000000000000000000000000000000000000000000000000000000000000001");
        // All zeros except last bit
        assert_eq!(get_bit(&key, 0), 0);
        assert_eq!(get_bit(&key, 255), 1);
    }
}
