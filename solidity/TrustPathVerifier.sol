// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title TrustPathVerifier
 * @notice Library for verifying two-hop trust paths and computing decider-relative trust scores
 * @dev Verifies three Sparse Merkle Map (SMM) paths against a graph root and computes
 *      deterministic trust scores using the two-hop scoring algorithm from TrustNet protocol.
 *
 *      The library verifies membership proofs for:
 *      - O→Y (Decider to Endorser)
 *      - Y→T (Endorser to Target)
 *      - O→T (Decider to Target - direct override, can be membership or non-membership)
 *
 *      All three edges must share the same contextId for capability isolation.
 *
 *      Scoring formula:
 *      sumProducts = lOY * lYT
 *      scoreNumerator = 2*lOT + sumProducts
 *      score = clamp(scoreNumerator / 2, -2, +2)
 */
library TrustPathVerifier {
    // Custom errors for gas efficiency
    error InvalidLevelRange(int8 level);
    error ContextMismatch();
    error InvalidProofLength();
    error ProofVerificationFailed();
    error ScoreBelowThreshold(int8 score, int8 required);

    /**
     * @notice Data structure for a complete two-hop proof
     * @param graphRoot The SMM root being verified against
     * @param epoch The epoch number for this root
     * @param contextId The context (capability namespace) being evaluated
     * @param decider The decider/anchor address (O)
     * @param endorser The curator/auditor address (Y)
     * @param target The agent being evaluated (T)
     * @param levelOY Edge weight: Decider → Endorser (-2 to +2)
     * @param levelYT Edge weight: Endorser → Target (-2 to +2)
     * @param levelOT Edge weight: Decider → Target (direct override, -2 to +2)
     * @param merkleOY Merkle proof path for O→Y edge
     * @param merkleYT Merkle proof path for Y→T edge
     * @param merkleOT Merkle proof path for O→T edge (siblings from leaf to root)
     * @param otIsAbsent True if O→T is a non-membership proof (defaults to level 0)
     * @param otNonMembershipData Additional data for O→T non-membership proof
     */
    struct TrustPathProof {
        bytes32 graphRoot;
        uint256 epoch;
        bytes32 contextId;
        address decider;
        address endorser;
        address target;
        int8 levelOY;
        int8 levelYT;
        int8 levelOT;
        bytes32[] merkleOY;
        bytes32[] merkleYT;
        bytes32[] merkleOT;
        bool otIsAbsent;
        NonMembershipData otNonMembershipData;
    }

    /**
     * @notice Data for non-membership proofs in Sparse Merkle Maps
     * @param divergenceHeight The tree height where the path diverges (0 = leaf level)
     * @param siblingKey If divergence is at leaf level, the key of the sibling leaf
     * @param siblingValue If divergence is at leaf level, the value of the sibling leaf
     */
    struct NonMembershipData {
        uint8 divergenceHeight;
        bytes32 siblingKey;
        uint8 siblingValue;
    }

    /**
     * @notice Result of trust path verification
     * @param isValid Whether the proof verified successfully
     * @param score The computed trust score (-2 to +2)
     * @param endorser The endorser address used in the path
     * @param levelOY Decider → Endorser level (for "Why" explanation)
     * @param levelYT Endorser → Target level (for "Why" explanation)
     * @param levelOT Decider → Target direct override level
     */
    struct VerificationResult {
        bool isValid;
        int8 score;
        address endorser;
        int8 levelOY;
        int8 levelYT;
        int8 levelOT;
    }

    // Constants for SMM leaf and inner node prefixes
    bytes1 private constant LEAF_PREFIX = 0x00;
    bytes1 private constant INNER_PREFIX = 0x01;

    // Default value for non-membership (represents level 0)
    uint8 private constant DEFAULT_VALUE = 2;

    // Maximum tree depth for SMM (256 bits)
    uint256 private constant MAX_TREE_DEPTH = 256;

    /**
     * @notice Verifies a trust path proof and computes the trust score
     * @param proof The complete trust path proof structure
     * @return result Verification result with score and path details
     */
    function verifyAndScore(TrustPathProof memory proof)
        internal
        pure
        returns (VerificationResult memory result)
    {
        // Validate input levels are in valid range [-2, +2]
        _validateLevel(proof.levelOY);
        _validateLevel(proof.levelYT);
        if (!proof.otIsAbsent) {
            _validateLevel(proof.levelOT);
        }

        // Compute edge keys for SMM
        bytes32 keyOY = computeEdgeKey(proof.decider, proof.endorser, proof.contextId);
        bytes32 keyYT = computeEdgeKey(proof.endorser, proof.target, proof.contextId);
        bytes32 keyOT = computeEdgeKey(proof.decider, proof.target, proof.contextId);

        // Verify O→Y membership
        uint8 valueOY = _levelToValue(proof.levelOY);
        bool validOY = verifyMembership(proof.graphRoot, keyOY, valueOY, proof.merkleOY);
        if (!validOY) {
            return VerificationResult(false, 0, proof.endorser, 0, 0, 0);
        }

        // Verify Y→T membership
        uint8 valueYT = _levelToValue(proof.levelYT);
        bool validYT = verifyMembership(proof.graphRoot, keyYT, valueYT, proof.merkleYT);
        if (!validYT) {
            return VerificationResult(false, 0, proof.endorser, 0, 0, 0);
        }

        // Verify O→T (can be membership or non-membership)
        bool validOT;
        if (proof.otIsAbsent) {
            // Non-membership proof - defaults to level 0
            validOT = verifyNonMembership(
                proof.graphRoot,
                keyOT,
                proof.merkleOT,
                proof.otNonMembershipData
            );
            if (validOT) {
                proof.levelOT = 0; // Default level for non-membership
            }
        } else {
            // Membership proof with explicit level
            uint8 valueOT = _levelToValue(proof.levelOT);
            validOT = verifyMembership(proof.graphRoot, keyOT, valueOT, proof.merkleOT);
        }

        if (!validOT) {
            return VerificationResult(false, 0, proof.endorser, 0, 0, 0);
        }

        // Compute the trust score
        int8 score = computeScore(proof.levelOY, proof.levelYT, proof.levelOT);

        return VerificationResult(
            true,
            score,
            proof.endorser,
            proof.levelOY,
            proof.levelYT,
            proof.levelOT
        );
    }

    /**
     * @notice Verifies a proof and requires minimum score threshold
     * @param proof The trust path proof
     * @param minScore Minimum required score (-2 to +2)
     * @return result The verification result (reverts if below threshold)
     */
    function requireMinScore(TrustPathProof memory proof, int8 minScore)
        internal
        pure
        returns (VerificationResult memory result)
    {
        result = verifyAndScore(proof);

        if (!result.isValid) {
            revert ProofVerificationFailed();
        }

        if (result.score < minScore) {
            revert ScoreBelowThreshold(result.score, minScore);
        }

        return result;
    }

    /**
     * @notice Computes the deterministic two-hop score
     * @dev Implements the scoring formula from the TrustNet whitepaper:
     *      sumProducts = lOY * lYT
     *      scoreNumerator = 2*lOT + sumProducts
     *      score = clamp(scoreNumerator / 2, -2, +2)
     * @param levelOY Decider → Endorser edge weight (-2 to +2)
     * @param levelYT Endorser → Target edge weight (-2 to +2)
     * @param levelOT Decider → Target direct override (-2 to +2)
     * @return score The computed score clamped to [-2, +2]
     */
    function computeScore(int8 levelOY, int8 levelYT, int8 levelOT)
        internal
        pure
        returns (int8 score)
    {
        // Use int16 for intermediate calculations to prevent overflow
        int16 sumProducts = int16(levelOY) * int16(levelYT);
        int16 scoreNumerator = 2 * int16(levelOT) + sumProducts;

        // Integer division toward zero (EVM default behavior)
        int16 rawScore = scoreNumerator / 2;

        // Clamp to [-2, +2]
        if (rawScore < -2) {
            return -2;
        }
        if (rawScore > 2) {
            return 2;
        }
        return int8(rawScore);
    }

    /**
     * @notice Verifies a single SMM membership proof
     * @param root The SMM root to verify against
     * @param key The edge key (keccak256(rater || target || contextId))
     * @param value The edge value (level + 2, mapped to 0-4)
     * @param proof The Merkle proof path (siblings from leaf to root)
     * @return isValid Whether the proof is valid
     */
    function verifyMembership(
        bytes32 root,
        bytes32 key,
        uint8 value,
        bytes32[] memory proof
    ) internal pure returns (bool isValid) {
        // Compute leaf hash: keccak256(0x00 || key || value)
        bytes32 currentHash = keccak256(abi.encodePacked(LEAF_PREFIX, key, value));

        // Walk up the tree using the proof path
        // Proof array contains siblings from leaf to root (deepest first)
        // So we need to check bits from deepest to shallowest
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];

            // Determine if current node is left or right child based on key bit
            // proof[0] corresponds to deepest level (bit at position proof.length - 1)
            // proof[proof.length-1] corresponds to root level (bit at position 0)
            uint256 bitPosition = proof.length - 1 - i;

            if (_getBit(key, bitPosition)) {
                // Current node is right child
                currentHash = keccak256(abi.encodePacked(INNER_PREFIX, sibling, currentHash));
            } else {
                // Current node is left child
                currentHash = keccak256(abi.encodePacked(INNER_PREFIX, currentHash, sibling));
            }
        }

        return currentHash == root;
    }

    /**
     * @notice Computes the empty subtree hash for a given height
     * @dev In SMM, empty subtrees are recursively defined:
     *      - At leaf level: zero hash (represents no data)
     *      - At height h: keccak256(0x01 || empty[h-1] || empty[h-1])
     * @param height The height in the tree (0 = leaf level)
     * @return The empty subtree hash for that height
     */
    function computeEmptySubtreeHash(uint256 height) internal pure returns (bytes32) {
        bytes32 emptyHash = bytes32(0); // Empty at leaf level

        // Build up empty subtree hashes from leaf to desired height
        for (uint256 i = 0; i < height; i++) {
            emptyHash = keccak256(abi.encodePacked(INNER_PREFIX, emptyHash, emptyHash));
        }

        return emptyHash;
    }

    /**
     * @notice Verifies SMM non-membership using sparse tree absence witness
     * @dev Proves a key is absent by showing the path contains empty subtrees or different keys
     * @param root The SMM root
     * @param key The edge key we're proving is absent
     * @param proof The Merkle proof path (siblings from leaf to root)
     * @param nonMemberData Data about the divergence point
     * @return isValid Whether non-membership is proven
     */
    function verifyNonMembership(
        bytes32 root,
        bytes32 key,
        bytes32[] memory proof,
        NonMembershipData memory nonMemberData
    ) internal pure returns (bool isValid) {
        // Validate divergence height doesn't exceed proof length
        if (nonMemberData.divergenceHeight > proof.length) {
            return false;
        }

        // Start with empty hash at leaf level (absent key)
        bytes32 currentHash = bytes32(0);

        // Build the path from leaf to root
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];
            uint256 bitPosition = proof.length - 1 - i;

            // Special handling at divergence point
            if (i == nonMemberData.divergenceHeight) {
                // At leaf level divergence, verify the sibling has a different key
                if (i == 0) {
                    // Sibling should be a leaf with different key
                    bytes32 expectedSiblingHash = keccak256(
                        abi.encodePacked(LEAF_PREFIX, nonMemberData.siblingKey, nonMemberData.siblingValue)
                    );

                    // Keys must be different for non-membership
                    if (nonMemberData.siblingKey == key) {
                        return false;
                    }

                    // Verify sibling hash matches
                    if (sibling != expectedSiblingHash) {
                        return false;
                    }
                } else {
                    // At non-leaf divergence, sibling should be an empty subtree
                    // or a non-empty subtree (handled by proof)
                    bytes32 expectedEmptyHash = computeEmptySubtreeHash(i);

                    // If sibling is not empty, it's a populated subtree (valid)
                    // If sibling is empty, it should match the computed empty hash
                    if (sibling == bytes32(0) && sibling != expectedEmptyHash) {
                        return false;
                    }
                }
            } else if (i < nonMemberData.divergenceHeight) {
                // Before divergence, siblings should be empty subtrees
                sibling = computeEmptySubtreeHash(i);
            }
            // After divergence, use siblings from proof as-is

            // Hash with sibling based on bit direction
            if (_getBit(key, bitPosition)) {
                currentHash = keccak256(abi.encodePacked(INNER_PREFIX, sibling, currentHash));
            } else {
                currentHash = keccak256(abi.encodePacked(INNER_PREFIX, currentHash, sibling));
            }
        }

        return currentHash == root;
    }

    /**
     * @notice Computes the edge key for SMM
     * @param rater The rating address
     * @param target The target address
     * @param contextId The context identifier
     * @return key The keccak256 hash used as SMM key
     */
    function computeEdgeKey(
        address rater,
        address target,
        bytes32 contextId
    ) internal pure returns (bytes32 key) {
        return keccak256(abi.encodePacked(rater, target, contextId));
    }

    /**
     * @notice Validates that a trust level is in the valid range
     * @param level The trust level to validate
     */
    function _validateLevel(int8 level) private pure {
        if (level < -2 || level > 2) {
            revert InvalidLevelRange(level);
        }
    }

    /**
     * @notice Converts a trust level (-2 to +2) to SMM value (0 to 4)
     * @param level The trust level
     * @return value The SMM value
     */
    function _levelToValue(int8 level) private pure returns (uint8) {
        // Map -2..+2 to 0..4 for storage
        return uint8(int8(level + 2));
    }

    /**
     * @notice Gets the bit at a specific position in a bytes32
     * @dev Position 0 = MSB (most significant bit), Position 255 = LSB (least significant bit)
     *      This matches the SMM tree structure where:
     *      - Root level decisions use MSB (position 0)
     *      - Leaf level decisions use LSB (position 255 for 256-bit tree)
     * @param data The bytes32 data
     * @param position The bit position (0-255, where 0 is MSB)
     * @return The bit value (true for 1, false for 0)
     */
    function _getBit(bytes32 data, uint256 position) private pure returns (bool) {
        require(position < 256, "Position out of range");
        uint256 uintData = uint256(data);
        uint256 mask = 1 << (255 - position);
        return (uintData & mask) != 0;
    }
}