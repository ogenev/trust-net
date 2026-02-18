// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";

import "../TrustNetContexts.sol";
import "../TrustPathVerifier.sol";

contract TrustPathVerifierTest is Test {
    using stdJson for string;

    function _vectorsPath() private view returns (string memory) {
        // Foundry projectRoot() is the `solidity/` folder; vectors live in `../docs/`.
        return string.concat(vm.projectRoot(), "/../docs/Test_Vectors_v0.7.json");
    }

    function _loadVectors() private view returns (string memory json) {
        json = vm.readFile(_vectorsPath());
    }

    function test_ComputeEdgeKey_MatchesRustVectors() public view {
        string memory json = _loadVectors();

        address rater = json.readAddress(".principalId.raterAddress");
        address target = json.readAddress(".principalId.targetAddress");
        bytes32 expected = json.readBytes32(".edgeKey");

        bytes32 got = TrustPathVerifier.computeEdgeKey(rater, target, TrustNetContexts.GLOBAL);
        assertEq(got, expected, "edgeKey mismatch (PrincipalId hashing)");
    }

    function test_ComputeLeafHash_MatchesRustVectors() public view {
        string memory json = _loadVectors();
        bytes32 edgeKey = json.readBytes32(".edgeKey");
        bytes32 expected = json.readBytes32(".leafHash");

        bytes memory leafValue = json.readBytes(".leafValueBytes");
        bytes32 got = TrustPathVerifier.computeLeafHash(edgeKey, leafValue);
        assertEq(got, expected, "leafHash mismatch");
    }

    function test_VerifyMembershipProof_MatchesRustVectors() public view {
        string memory json = _loadVectors();

        bytes32 graphRoot = json.readBytes32(".graphRoot");
        bytes32 edgeKey = json.readBytes32(".membershipProof.edgeKey");
        bytes memory leafValue = json.readBytes(".membershipProof.leafValueBytes");
        bytes32[] memory siblings = json.readBytes32Array(".membershipProof.siblings");

        TrustPathVerifier.SmmProof memory proof = TrustPathVerifier.SmmProof({
            isMembership: true,
            leafValue: leafValue,
            siblings: siblings
        });

        TrustPathVerifier.LeafValueV1 memory decoded =
            TrustPathVerifier.verifyProof(graphRoot, edgeKey, proof);

        assertEq(decoded.level, 2, "decoded level");
        assertEq(decoded.updatedAt, uint64(123), "decoded updatedAt");
        assertEq(decoded.evidenceHash, bytes32(0), "decoded evidenceHash");
    }

    function test_VerifyAndDecide_DirectAllow() public view {
        string memory json = _loadVectors();

        address rater = json.readAddress(".principalId.raterAddress");
        address target = json.readAddress(".principalId.targetAddress");
        bytes32 graphRoot = json.readBytes32(".graphRoot");
        bytes32 edgeKey = json.readBytes32(".membershipProof.edgeKey");
        bytes memory leafValue = json.readBytes(".membershipProof.leafValueBytes");
        bytes32[] memory siblings = json.readBytes32Array(".membershipProof.siblings");

        TrustPathVerifier.SmmProof memory dt = TrustPathVerifier.SmmProof({
            isMembership: true,
            leafValue: leafValue,
            siblings: siblings
        });

        // DE/ET ignored when endorser == address(0).
        TrustPathVerifier.SmmProof memory empty = TrustPathVerifier.SmmProof({
            isMembership: false,
            leafValue: bytes(""),
            siblings: new bytes32[](0)
        });

        TrustPathVerifier.DecisionRequest memory req = TrustPathVerifier.DecisionRequest({
            graphRoot: graphRoot,
            contextId: TrustNetContexts.GLOBAL,
            decider: rater,
            target: target,
            endorser: address(0),
            proofDT: dt,
            proofDE: empty,
            proofET: empty,
            allowThreshold: 2,
            askThreshold: 1,
            requirePositiveEtEvidence: false,
            requirePositiveDtEvidence: false
        });

        TrustPathVerifier.DecisionResult memory result = TrustPathVerifier.verifyAndDecide(req);

        assertEq(uint8(result.decision), uint8(TrustPathVerifier.Decision.Allow), "decision");
        assertEq(result.score, 2, "score");
        assertEq(result.edgeDT.level, 2, "why DT");
        assertEq(result.edgeDE.level, 0, "why DE");
        assertEq(result.edgeET.level, 0, "why ET");
    }

    function test_ComputeScore_VetoAlwaysDenies() public pure {
        assertEq(TrustPathVerifier.computeScore(-2, 2, 2), int8(-2));
        assertEq(TrustPathVerifier.computeScore(-2, 0, 0), int8(-2));
    }

    function test_ComputeScore_EndorsementsOnlyPositive() public pure {
        // Positive 2-hop contributes.
        assertEq(TrustPathVerifier.computeScore(0, 2, 1), int8(1));
        // Negative does not propagate through endorsers.
        assertEq(TrustPathVerifier.computeScore(0, -2, 2), int8(0));
        assertEq(TrustPathVerifier.computeScore(0, 2, -1), int8(0));
    }

    function test_ComputeScore_DirectOverridesUpwards() public pure {
        assertEq(TrustPathVerifier.computeScore(2, 2, 1), int8(2));
        assertEq(TrustPathVerifier.computeScore(1, 2, 2), int8(2));
    }

    function test_ComputeScoreWithEvidence_GatesMissingEvidence() public pure {
        TrustPathVerifier.LeafValueV1 memory dt = TrustPathVerifier.LeafValueV1({
            level: 1,
            updatedAt: 0,
            evidenceHash: bytes32(0)
        });
        TrustPathVerifier.LeafValueV1 memory de = TrustPathVerifier.LeafValueV1({
            level: 2,
            updatedAt: 0,
            evidenceHash: bytes32(0)
        });
        TrustPathVerifier.LeafValueV1 memory et = TrustPathVerifier.LeafValueV1({
            level: 2,
            updatedAt: 0,
            evidenceHash: bytes32(0)
        });

        int8 score = TrustPathVerifier.computeScoreWithEvidence(dt, de, et, true, true);
        assertEq(score, int8(0), "gated score");

        TrustPathVerifier.LeafValueV1 memory etEvidence = TrustPathVerifier.LeafValueV1({
            level: 2,
            updatedAt: 0,
            evidenceHash: bytes32(uint256(1))
        });
        score = TrustPathVerifier.computeScoreWithEvidence(dt, de, etEvidence, true, false);
        assertEq(score, int8(2), "score with et evidence");
    }

    function test_Decide_InvalidThresholdsReverts() public {
        vm.expectRevert(abi.encodeWithSelector(TrustPathVerifier.InvalidThresholds.selector, int8(1), int8(2)));
        TrustPathVerifier.decide(0, 1, 2);
    }
}
