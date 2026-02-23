// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/**
 * @title TrustPathVerifier
 * @notice TrustNet v1.1 on-chain verifier library.
 *
 * This library verifies compact Sparse Merkle Map proofs (bitmap + packed siblings)
 * and applies the TrustNet v1.1 spec trust-to-act decision rule:
 * - `lDEpos = max(lDE, 0)` (no sign-flip)
 * - `path = lDEpos * lET`
 * - `scoreNumerator = 2*lDT + path`
 * - `score = clamp(scoreNumerator / 2, -2, +2)` (integer division toward zero)
 * - Thresholds map score => ALLOW / ASK / DENY
 *
 * Hashing (must match Rust `trustnet-core`):
 * - edgeKey = keccak256(raterPid32 || targetPid32 || contextId)
 *   where `raterPid32` is the 32-byte PrincipalId. For EVM addresses this is
 *   the address left-padded to 32 bytes.
 * - leafHash = keccak256(0x00 || edgeKey || leafValueBytes)
 * - internalHash = keccak256(0x01 || left || right)
 * - emptyHash = keccak256(0x02)
 *
 * Leaf value encoding (v1.1) is 1 byte:
 * - `V` (1 byte): uint8(level + 2) ∈ [0..4]
 */
library TrustPathVerifier {
    error InvalidPackedSiblings(uint256 consumed, uint256 provided);
    error InvalidLeafValueLength(uint256 expected, uint256 got);
    error InvalidLeafValueForNonMembership();
    error InvalidLevelEnc(uint8 levelEnc);
    error ProofVerificationFailed();
    error InvalidThresholds(int8 allow, int8 ask);
    error InvalidEndorserProof();

    /// Compact Sparse Merkle Map proof.
    struct SmmProof {
        bool isAbsent;
        bytes leafValue; // membership: one-byte V, absence: empty
        bytes32 bitmap; // bit i = 1 => siblings[i] entry present (i from leaf upward)
        bytes32[] siblings; // packed non-default siblings in ascending i order
    }

    /// Decoded leaf value (v1.1).
    struct LeafValueV1 {
        int8 level;
    }

    enum Decision {
        Deny,
        Ask,
        Allow
    }

    struct DecisionResult {
        Decision decision;
        int8 score;
        LeafValueV1 edgeDe;
        LeafValueV1 edgeEt;
        LeafValueV1 edgeDt;
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
        SmmProof proofDt;
        SmmProof proofDe;
        SmmProof proofEt;
        int8 allowThreshold;
        int8 askThreshold;
    }

    function _defaultLeaf() private pure returns (LeafValueV1 memory) {
        return LeafValueV1({level: 0});
    }

    function _defaultHashes() private pure returns (bytes32[257] memory defaults) {
        defaults[0] = computeEmptyHash();
        for (uint256 i = 0; i < 256; i++) {
            defaults[i + 1] = computeInternalHash(defaults[i], defaults[i]);
        }
    }

    function _hashBytes(bytes memory data) private pure returns (bytes32 result) {
        assembly ("memory-safe") {
            result := keccak256(add(data, 0x20), mload(data))
        }
    }

    /// Convert an EVM address into a PrincipalId (left-padded to 32 bytes).
    function toPrincipalId(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// Compute edgeKey = keccak256(raterPid32 || targetPid32 || contextId).
    function computeEdgeKey(address rater, address target, bytes32 contextId) internal pure returns (bytes32) {
        return _hashBytes(bytes.concat(toPrincipalId(rater), toPrincipalId(target), contextId));
    }

    /// Compute leafHash = keccak256(0x00 || edgeKey || leafValueBytes).
    function computeLeafHash(bytes32 edgeKey, bytes memory leafValue) internal pure returns (bytes32) {
        return _hashBytes(bytes.concat(bytes1(0x00), edgeKey, leafValue));
    }

    /// Compute internalHash = keccak256(0x01 || left || right).
    function computeInternalHash(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return _hashBytes(bytes.concat(bytes1(0x01), left, right));
    }

    /// Compute the sparse-tree empty-subtree base hash.
    function computeEmptyHash() internal pure returns (bytes32) {
        return _hashBytes(bytes.concat(bytes1(0x02)));
    }

    function _getBit(bytes32 key, uint256 index) private pure returns (uint8) {
        uint8 b = uint8(key[index / 8]);
        uint8 bitIndex = uint8(7 - (index % 8));
        return (b >> bitIndex) & 1;
    }

    /// Decode the v1.1 leaf value bytes (1 byte).
    function decodeLeafValueV1(bytes memory leafValue) internal pure returns (LeafValueV1 memory v) {
        if (leafValue.length != 1) {
            revert InvalidLeafValueLength(1, leafValue.length);
        }

        uint8 levelEnc = uint8(leafValue[0]);
        if (levelEnc > 4) {
            revert InvalidLevelEnc(levelEnc);
        }
        if (levelEnc == 0) {
            v.level = -2;
        } else if (levelEnc == 1) {
            v.level = -1;
        } else if (levelEnc == 2) {
            v.level = 0;
        } else if (levelEnc == 3) {
            v.level = 1;
        } else {
            v.level = 2;
        }
    }

    /// Verify a single proof against a root, returning a decoded leaf value.
    ///
    /// For non-membership proofs, `leafValue` must be empty and the returned leaf value is neutral.
    function verifyProof(bytes32 root, bytes32 edgeKey, SmmProof memory proof) internal pure returns (LeafValueV1 memory leaf) {
        bytes32 h;
        if (!proof.isAbsent) {
            leaf = decodeLeafValueV1(proof.leafValue);
            h = computeLeafHash(edgeKey, proof.leafValue);
        } else {
            if (proof.leafValue.length != 0) {
                revert InvalidLeafValueForNonMembership();
            }
            leaf = _defaultLeaf();
            h = computeEmptyHash();
        }

        bytes32[257] memory defaults = _defaultHashes();
        uint256 bitmap = uint256(proof.bitmap);
        uint256 packedIndex = 0;

        // i=0 is leaf-adjacent sibling, i=255 is top-most sibling.
        for (uint256 i = 0; i < 256; i++) {
            bytes32 sibling;
            if (((bitmap >> i) & 1) == 1) {
                if (packedIndex >= proof.siblings.length) {
                    revert InvalidPackedSiblings(packedIndex + 1, proof.siblings.length);
                }
                sibling = proof.siblings[packedIndex];
                unchecked {
                    packedIndex++;
                }
            } else {
                sibling = defaults[i];
            }

            uint256 depth = 255 - i;
            if (_getBit(edgeKey, depth) == 0) {
                h = computeInternalHash(h, sibling);
            } else {
                h = computeInternalHash(sibling, h);
            }
        }

        if (packedIndex != proof.siblings.length) {
            revert InvalidPackedSiblings(packedIndex, proof.siblings.length);
        }

        if (h != root) {
            revert ProofVerificationFailed();
        }
    }

    /// Compute TrustNet v1.1 spec score from decoded levels (no evidence gating).
    function computeScore(int8 lDt, int8 lDe, int8 lEt) internal pure returns (int8) {
        int16 lDePos = lDe > 0 ? int16(lDe) : int16(0);
        int16 path = lDePos * int16(lEt);
        int16 numerator = int16(2) * int16(lDt) + path;
        int16 raw = numerator / 2;

        if (raw > 2) {
            return 2;
        }
        if (raw < -2) {
            return -2;
        }
        if (raw == -2) {
            return -2;
        }
        if (raw == -1) {
            return -1;
        }
        if (raw == 0) {
            return 0;
        }
        if (raw == 1) {
            return 1;
        }
        return 2;
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
        bytes32 keyDt = computeEdgeKey(req.decider, req.target, req.contextId);
        LeafValueV1 memory dt = verifyProof(req.graphRoot, keyDt, req.proofDt);

        LeafValueV1 memory de = _defaultLeaf();
        LeafValueV1 memory et = _defaultLeaf();
        if (req.endorser != address(0)) {
            if (req.proofDe.isAbsent || req.proofEt.isAbsent) {
                revert InvalidEndorserProof();
            }
            bytes32 keyDe = computeEdgeKey(req.decider, req.endorser, req.contextId);
            bytes32 keyEt = computeEdgeKey(req.endorser, req.target, req.contextId);
            de = verifyProof(req.graphRoot, keyDe, req.proofDe);
            et = verifyProof(req.graphRoot, keyEt, req.proofEt);
        }

        int8 score = computeScore(dt.level, de.level, et.level);
        Decision d = decide(score, req.allowThreshold, req.askThreshold);

        result = DecisionResult({
            decision: d,
            score: score,
            edgeDe: de,
            edgeEt: et,
            edgeDt: dt
        });
    }
}
