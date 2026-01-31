// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title TrustPathVerifier
 * @notice TrustNet v0.4 on-chain verifier (optional for MVP).
 *
 * This library verifies uncompressed Sparse Merkle Map proofs (256 siblings)
 * and applies the v0.4 trust-to-act decision rule:
 * - Hard veto: `lDT == -2` => DENY
 * - Endorsements only contribute when both edges are positive:
 *   `base = min(lDE, lET)` where `lDE > 0 && lET > 0`
 * - Direct trust can override upwards: if `lDT > 0`, `score = max(base, lDT)`
 * - Thresholds map score => ALLOW / ASK / DENY
 *
 * Hashing (must match Rust `trustnet-core`):
 * - edgeKey = keccak256(raterPid32 || targetPid32 || contextId)
 *   where `raterPid32` is the 32-byte PrincipalId. For EVM addresses this is
 *   the address left-padded to 32 bytes.
 * - leafHash = keccak256(0x00 || edgeKey || leafValueBytes)
 * - internalHash = keccak256(0x01 || left || right)
 *
 * Leaf value encoding (v0.4 MVP) is 41 bytes:
 * - levelEnc (1 byte): uint8(level + 2) ∈ [0..4]
 * - updatedAtEnc (8 bytes): uint64 big-endian
 * - evidenceHash (32 bytes): bytes32 (zero if none)
 */
library TrustPathVerifier {
    error InvalidSiblingsLength(uint256 got);
    error InvalidLeafValueLength(uint256 expected, uint256 got);
    error InvalidLeafValueForNonMembership();
    error InvalidLevelEnc(uint8 levelEnc);
    error ProofVerificationFailed();
    error InvalidThresholds(int8 allow, int8 ask);

    /// Uncompressed Sparse Merkle Map proof.
    struct SmmProof {
        bool isMembership;
        bytes leafValue;
        bytes32[] siblings; // must be length 256, indexed by bit position 0..255 (MSB..LSB)
    }

    /// Decoded leaf value (v0.4 MVP).
    struct LeafValueV1 {
        int8 level;
        uint64 updatedAt;
        bytes32 evidenceHash;
    }

    enum Decision {
        Deny,
        Ask,
        Allow
    }

    struct DecisionResult {
        Decision decision;
        int8 score;
        LeafValueV1 edgeDE;
        LeafValueV1 edgeET;
        LeafValueV1 edgeDT;
    }

    /// Inputs for `verifyAndDecide`.
    ///
    /// Grouped into a single struct to avoid "stack too deep" in Solidity.
    struct DecisionRequest {
        bytes32 graphRoot;
        bytes32 contextId;
        address decider;
        address target;
        address endorser;
        SmmProof proofDT;
        SmmProof proofDE;
        SmmProof proofET;
        int8 allowThreshold;
        int8 askThreshold;
    }

    function _defaultLeaf() private pure returns (LeafValueV1 memory) {
        return LeafValueV1({level: 0, updatedAt: 0, evidenceHash: bytes32(0)});
    }

    /// Convert an EVM address into a PrincipalId (left-padded to 32 bytes).
    function toPrincipalId(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// Compute edgeKey = keccak256(raterPid32 || targetPid32 || contextId).
    function computeEdgeKey(address rater, address target, bytes32 contextId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(toPrincipalId(rater), toPrincipalId(target), contextId));
    }

    /// Compute leafHash = keccak256(0x00 || edgeKey || leafValueBytes).
    function computeLeafHash(bytes32 edgeKey, bytes memory leafValue) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x00), edgeKey, leafValue));
    }

    /// Compute internalHash = keccak256(0x01 || left || right).
    function computeInternalHash(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes1(0x01), left, right));
    }

    function _getBit(bytes32 key, uint256 index) private pure returns (uint8) {
        uint8 b = uint8(key[index / 8]);
        uint8 bitIndex = uint8(7 - (index % 8));
        return (b >> bitIndex) & 1;
    }

    /// Decode the v0.4 leaf value bytes (41 bytes).
    function decodeLeafValueV1(bytes memory leafValue) internal pure returns (LeafValueV1 memory v) {
        if (leafValue.length != 41) {
            revert InvalidLeafValueLength(41, leafValue.length);
        }

        uint8 levelEnc = uint8(leafValue[0]);
        if (levelEnc > 4) {
            revert InvalidLevelEnc(levelEnc);
        }
        v.level = int8(int256(uint256(levelEnc))) - 2;

        uint64 updatedAt;
        bytes32 evidenceHash;
        assembly {
            // Load bytes[1..8] as big-endian u64.
            updatedAt := shr(192, mload(add(leafValue, 33)))
            // Load bytes[9..40] as bytes32.
            evidenceHash := mload(add(leafValue, 41))
        }
        v.updatedAt = updatedAt;
        v.evidenceHash = evidenceHash;
    }

    /// Verify a single proof against a root, returning a decoded leaf value.
    ///
    /// For non-membership proofs, `leafValue` must be empty and the returned leaf value is neutral.
    function verifyProof(bytes32 root, bytes32 edgeKey, SmmProof memory proof) internal pure returns (LeafValueV1 memory leaf) {
        if (proof.siblings.length != 256) {
            revert InvalidSiblingsLength(proof.siblings.length);
        }

        bytes32 h;
        if (proof.isMembership) {
            leaf = decodeLeafValueV1(proof.leafValue);
            h = computeLeafHash(edgeKey, proof.leafValue);
        } else {
            if (proof.leafValue.length != 0) {
                revert InvalidLeafValueForNonMembership();
            }
            leaf = _defaultLeaf();
            h = bytes32(0);
        }

        // Walk from depth 255..0, with siblings indexed by bit position.
        for (uint256 depth = 256; depth > 0; depth--) {
            uint256 d = depth - 1;
            bytes32 sibling = proof.siblings[d];
            if (_getBit(edgeKey, d) == 0) {
                h = computeInternalHash(h, sibling);
            } else {
                h = computeInternalHash(sibling, h);
            }
        }

        if (h != root) {
            revert ProofVerificationFailed();
        }
    }

    /// Compute v0.4 score from decoded levels.
    function computeScore(int8 lDT, int8 lDE, int8 lET) internal pure returns (int8) {
        if (lDT == -2) {
            return -2;
        }

        int8 base = 0;
        if (lDE > 0 && lET > 0) {
            base = (lDE < lET) ? lDE : lET;
        }

        if (lDT > 0) {
            return (base > lDT) ? base : lDT;
        }

        return base;
    }

    /// Map score + thresholds to a decision.
    function decide(int8 score, int8 allowThreshold, int8 askThreshold) internal pure returns (Decision) {
        if (askThreshold > allowThreshold) {
            revert InvalidThresholds(allowThreshold, askThreshold);
        }
        if (score >= allowThreshold) {
            return Decision.Allow;
        }
        if (score >= askThreshold) {
            return Decision.Ask;
        }
        return Decision.Deny;
    }

    /// Verify DT/DE/ET proofs and compute decision.
    ///
    /// If `endorser == address(0)`, DE/ET are treated as neutral and their proofs are ignored.
    function verifyAndDecide(DecisionRequest memory req) internal pure returns (DecisionResult memory result) {
        bytes32 keyDT = computeEdgeKey(req.decider, req.target, req.contextId);
        LeafValueV1 memory dt = verifyProof(req.graphRoot, keyDT, req.proofDT);

        LeafValueV1 memory de = _defaultLeaf();
        LeafValueV1 memory et = _defaultLeaf();
        if (req.endorser != address(0)) {
            bytes32 keyDE = computeEdgeKey(req.decider, req.endorser, req.contextId);
            bytes32 keyET = computeEdgeKey(req.endorser, req.target, req.contextId);
            de = verifyProof(req.graphRoot, keyDE, req.proofDE);
            et = verifyProof(req.graphRoot, keyET, req.proofET);
        }

        int8 score = computeScore(dt.level, de.level, et.level);
        Decision d = decide(score, req.allowThreshold, req.askThreshold);

        result = DecisionResult({
            decision: d,
            score: score,
            edgeDE: de,
            edgeET: et,
            edgeDT: dt
        });
    }
}
