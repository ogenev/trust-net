// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/StdJson.sol";

import "../TrustNetContexts.sol";
import "../TrustPathVerifier.sol";

contract TrustPathVerifierTest is Test {
    using stdJson for string;

    function _callDecide(int8 score, int8 allowThreshold, int8 askThreshold)
        external
        pure
        returns (TrustPathVerifier.Decision)
    {
        return TrustPathVerifier.decide(score, allowThreshold, askThreshold);
    }

    function _callVerifyAndDecide(TrustPathVerifier.DecisionRequest memory req)
        external
        view
        returns (TrustPathVerifier.DecisionResult memory)
    {
        return TrustPathVerifier.verifyAndDecide(req);
    }

    function _vectorsPath() private view returns (string memory) {
        // Foundry projectRoot() is the `solidity/` folder; vectors live in `../docs/`.
        return string.concat(vm.projectRoot(), "/../docs/Test_Vectors_v1.1.json");
    }

    function _loadVectors() private view returns (string memory json) {
        json = vm.readFile(_vectorsPath());
    }

    function _readMembershipProof(string memory json, string memory prefix)
        private
        view
        returns (bytes32 edgeKey, TrustPathVerifier.SmmProof memory proof)
    {
        edgeKey = json.readBytes32(string.concat(prefix, ".edgeKey"));
        uint8 v = uint8(json.readUint(string.concat(prefix, ".leaf.V")));
        bytes32 bitmap = json.readBytes32(string.concat(prefix, ".bitmap"));
        bytes32[] memory siblings = json.readBytes32Array(string.concat(prefix, ".siblings"));

        proof = TrustPathVerifier.SmmProof({
            isAbsent: false,
            leafValue: abi.encodePacked(bytes1(v)),
            bitmap: bitmap,
            siblings: siblings
        });
    }

    function _absentProof() private pure returns (TrustPathVerifier.SmmProof memory proof) {
        proof = TrustPathVerifier.SmmProof({
            isAbsent: true,
            leafValue: bytes(""),
            bitmap: bytes32(0),
            siblings: new bytes32[](0)
        });
    }

    function test_ComputeEdgeKey_MatchesRustVectors() public view {
        string memory json = _loadVectors();

        address rater = json.readAddress(".principalId.raterAddress");
        address target = json.readAddress(".principalId.targetAddress");
        bytes32 expected = json.readBytes32(".edgeKey");

        bytes32 got = TrustPathVerifier.computeEdgeKey(rater, target, TrustNetContexts.CODE_EXEC);
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
        (bytes32 edgeKey, TrustPathVerifier.SmmProof memory proof) =
            _readMembershipProof(json, ".membershipProof");

        TrustPathVerifier.LeafValueV1 memory decoded =
            TrustPathVerifier.verifyProof(graphRoot, edgeKey, proof);

        assertEq(decoded.level, 2, "decoded level");
    }

    function test_VerifyAndDecide_DirectAllow() public view {
        string memory json = _loadVectors();

        address rater = json.readAddress(".principalId.raterAddress");
        address target = json.readAddress(".principalId.targetAddress");
        bytes32 graphRoot = json.readBytes32(".graphRoot");
        (, TrustPathVerifier.SmmProof memory dt) = _readMembershipProof(json, ".membershipProof");

        // DE/ET ignored when endorser == address(0).
        TrustPathVerifier.SmmProof memory empty = _absentProof();

        TrustPathVerifier.DecisionRequest memory req = TrustPathVerifier.DecisionRequest({
            graphRoot: graphRoot,
            contextId: TrustNetContexts.CODE_EXEC,
            decider: rater,
            target: target,
            endorser: address(0),
            proofDT: dt,
            proofDE: empty,
            proofET: empty,
            allowThreshold: 2,
            askThreshold: 1
        });

        TrustPathVerifier.DecisionResult memory result = TrustPathVerifier.verifyAndDecide(req);

        assertEq(uint8(result.decision), uint8(TrustPathVerifier.Decision.Allow), "decision");
        assertEq(result.score, 2, "score");
        assertEq(result.edgeDT.level, 2, "why DT");
        assertEq(result.edgeDE.level, 0, "why DE");
        assertEq(result.edgeET.level, 0, "why ET");
    }

    function test_ComputeScore_DirectNegativeCanBeOffset() public pure {
        assertEq(TrustPathVerifier.computeScore(-2, 2, 2), int8(0));
        assertEq(TrustPathVerifier.computeScore(-2, 0, 0), int8(-2));
    }

    function test_ComputeScore_EndorsementsOnlyPositive() public pure {
        // Positive 2-hop contributes with path=lDE*lET.
        assertEq(TrustPathVerifier.computeScore(0, 2, 1), int8(1));
        // No-sign-flip: negative lDE is clamped to 0 before multiplication.
        assertEq(TrustPathVerifier.computeScore(0, -2, -2), int8(0));
    }

    function test_ComputeScore_ClampsToRange() public pure {
        // numerator = 2*2 + 2*2 = 8 -> score=4 -> clamp to +2
        assertEq(TrustPathVerifier.computeScore(2, 2, 2), int8(2));
    }

    function test_Decide_InvalidThresholdsReverts() public {
        vm.expectRevert(abi.encodeWithSelector(TrustPathVerifier.InvalidThresholds.selector, int8(1), int8(2)));
        this._callDecide(0, 1, 2);
    }

    function test_VerifyAndDecide_RevertsWhenEndorserProofsAreNonMembership() public {
        string memory json = _loadVectors();
        address decider = json.readAddress(".principalId.raterAddress");
        address target = json.readAddress(".principalId.targetAddress");
        bytes32 graphRoot = json.readBytes32(".graphRoot");
        (, TrustPathVerifier.SmmProof memory dt) = _readMembershipProof(json, ".membershipProof");
        TrustPathVerifier.SmmProof memory empty = _absentProof();

        TrustPathVerifier.DecisionRequest memory req = TrustPathVerifier.DecisionRequest({
            graphRoot: graphRoot,
            contextId: TrustNetContexts.CODE_EXEC,
            decider: decider,
            target: target,
            endorser: address(0x1234),
            proofDT: dt,
            proofDE: empty,
            proofET: empty,
            allowThreshold: 2,
            askThreshold: 1
        });

        vm.expectRevert(TrustPathVerifier.InvalidEndorserProof.selector);
        this._callVerifyAndDecide(req);
    }
}
