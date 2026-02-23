// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";

import {RootRegistry} from "../RootRegistry.sol";
import {TrustNetContexts} from "../TrustNetContexts.sol";
import {TrustNetPaymentsGuardModule} from "../TrustNetPaymentsGuardModule.sol";
import {TrustPathVerifier} from "../TrustPathVerifier.sol";

contract TrustNetPaymentsGuardModuleTest is Test {
    RootRegistry public registry;
    TrustNetPaymentsGuardModule public module;

    address public registryOwner = address(0x100);
    address public publisher = address(0x200);

    address public moduleOwner = address(0x300);
    address public decider = address(0x1);
    address public target = address(0x2);
    address public recipient = address(0x400);

    uint256 public constant BASE_EPOCH = 1;
    uint256 public constant MAX_PAYMENT = 1 ether;
    uint256 public constant MAX_ROOT_AGE = 1 days;

    function setUp() public {
        vm.prank(registryOwner);
        registry = new RootRegistry(publisher);

        module = new TrustNetPaymentsGuardModule(
            address(registry),
            moduleOwner,
            decider,
            TrustNetContexts.PAYMENTS,
            2,
            1,
            MAX_PAYMENT,
            MAX_ROOT_AGE
        );

        vm.deal(address(module), 10 ether);

        (TrustPathVerifier.SmmProof memory proofDt, bytes32 root) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            2
        );

        _publishRoot(BASE_EPOCH, root);

        // Sanity check: the generated proof must validate against the published root.
        bytes32 edgeKey = TrustPathVerifier.computeEdgeKey(decider, target, TrustNetContexts.PAYMENTS);
        TrustPathVerifier.LeafValueV1 memory leaf = TrustPathVerifier.verifyProof(root, edgeKey, proofDt);
        assertEq(leaf.level, 2);
    }

    function test_Constructor_RevertsWhenAskThresholdAboveAllow() public {
        vm.expectRevert(
            abi.encodeWithSelector(TrustNetPaymentsGuardModule.InvalidThresholds.selector, int8(1), int8(2))
        );

        new TrustNetPaymentsGuardModule(
            address(registry),
            moduleOwner,
            decider,
            TrustNetContexts.PAYMENTS,
            1,
            2,
            MAX_PAYMENT,
            MAX_ROOT_AGE
        );
    }

    function test_ExecutePayment_AllowsAndTransfersValue() public {
        (TrustPathVerifier.SmmProof memory proofDt,) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            2
        );

        bytes32 opId = keccak256("op-allow-1");
        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            BASE_EPOCH,
            opId,
            0.25 ether,
            block.timestamp + 1 hours,
            proofDt
        );

        uint256 recipientBefore = recipient.balance;

        vm.prank(moduleOwner);
        module.executePayment(req);

        assertEq(recipient.balance, recipientBefore + 0.25 ether, "recipient should receive funds");
        assertTrue(module.usedOperationIds(opId), "operation id must be marked used");
    }

    function test_ExecutePayment_RevertsOnReplay() public {
        (TrustPathVerifier.SmmProof memory proofDt,) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            2
        );

        bytes32 opId = keccak256("op-replay-1");
        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            BASE_EPOCH,
            opId,
            0.1 ether,
            block.timestamp + 1 hours,
            proofDt
        );

        vm.startPrank(moduleOwner);
        module.executePayment(req);

        vm.expectRevert(
            abi.encodeWithSelector(TrustNetPaymentsGuardModule.OperationAlreadyUsed.selector, opId)
        );
        module.executePayment(req);
        vm.stopPrank();
    }

    function test_ExecutePayment_RevertsWhenAmountTooHigh() public {
        (TrustPathVerifier.SmmProof memory proofDt,) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            2
        );

        uint256 tooHigh = MAX_PAYMENT + 1;
        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            BASE_EPOCH,
            keccak256("op-cap"),
            tooHigh,
            block.timestamp + 1 hours,
            proofDt
        );

        vm.prank(moduleOwner);
        vm.expectRevert(
            abi.encodeWithSelector(TrustNetPaymentsGuardModule.AmountExceedsPolicy.selector, tooHigh, MAX_PAYMENT)
        );
        module.executePayment(req);
    }

    function test_ExecutePayment_RevertsWhenDeadlineExpired() public {
        (TrustPathVerifier.SmmProof memory proofDt,) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            2
        );

        uint256 deadline = block.timestamp - 1;
        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            BASE_EPOCH,
            keccak256("op-expired"),
            0.1 ether,
            deadline,
            proofDt
        );

        vm.prank(moduleOwner);
        vm.expectRevert(
            abi.encodeWithSelector(TrustNetPaymentsGuardModule.DeadlineExpired.selector, deadline, block.timestamp)
        );
        module.executePayment(req);
    }

    function test_ExecutePayment_RevertsWhenEpochMissing() public {
        (TrustPathVerifier.SmmProof memory proofDt,) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            2
        );

        uint256 missingEpoch = 99;
        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            missingEpoch,
            keccak256("op-missing-epoch"),
            0.1 ether,
            block.timestamp + 1 hours,
            proofDt
        );

        vm.prank(moduleOwner);
        vm.expectRevert(
            abi.encodeWithSelector(TrustNetPaymentsGuardModule.UnknownEpoch.selector, missingEpoch)
        );
        module.executePayment(req);
    }

    function test_ExecutePayment_RevertsWhenRootTooOld() public {
        (TrustPathVerifier.SmmProof memory proofDt,) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            2
        );

        vm.warp(block.timestamp + MAX_ROOT_AGE + 1);

        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            BASE_EPOCH,
            keccak256("op-stale-root"),
            0.1 ether,
            block.timestamp + 1 hours,
            proofDt
        );

        uint256 rootTs = registry.getEpochTimestamp(BASE_EPOCH);
        vm.prank(moduleOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                TrustNetPaymentsGuardModule.RootTooOld.selector,
                BASE_EPOCH,
                rootTs,
                MAX_ROOT_AGE
            )
        );
        module.executePayment(req);
    }

    function test_ExecutePayment_RevertsWithAskDecision() public {
        uint256 askEpoch = 2;
        (TrustPathVerifier.SmmProof memory askProof, bytes32 askRoot) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            1
        );

        _publishRoot(askEpoch, askRoot);

        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            askEpoch,
            keccak256("op-ask"),
            0.1 ether,
            block.timestamp + 1 hours,
            askProof
        );

        vm.prank(moduleOwner);
        vm.expectRevert(
            abi.encodeWithSelector(TrustNetPaymentsGuardModule.DecisionAsk.selector, int8(1))
        );
        module.executePayment(req);
    }

    function test_ExecutePayment_RevertsWithDenyDecision() public {
        uint256 denyEpoch = 2;
        (TrustPathVerifier.SmmProof memory denyProof, bytes32 denyRoot) = _buildMembershipProof(
            decider,
            target,
            TrustNetContexts.PAYMENTS,
            0
        );

        _publishRoot(denyEpoch, denyRoot);

        TrustNetPaymentsGuardModule.PaymentRequest memory req = _buildRequest(
            denyEpoch,
            keccak256("op-deny"),
            0.1 ether,
            block.timestamp + 1 hours,
            denyProof
        );

        vm.prank(moduleOwner);
        vm.expectRevert(
            abi.encodeWithSelector(TrustNetPaymentsGuardModule.DecisionDeny.selector, int8(0))
        );
        module.executePayment(req);
    }

    function test_SetDecider_OwnerOnly() public {
        address newDecider = address(0x1234);

        vm.prank(address(0xDEAD));
        vm.expectRevert(TrustNetPaymentsGuardModule.Unauthorized.selector);
        module.setDecider(newDecider);

        vm.prank(moduleOwner);
        module.setDecider(newDecider);
        assertEq(module.decider(), newDecider);
    }

    function test_TransferOwnership_OwnerOnly() public {
        address newOwner = address(0xBEEF);

        vm.prank(address(0xDEAD));
        vm.expectRevert(TrustNetPaymentsGuardModule.Unauthorized.selector);
        module.transferOwnership(newOwner);

        vm.prank(moduleOwner);
        module.transferOwnership(newOwner);
        assertEq(module.owner(), newOwner);
    }

    function _publishRoot(uint256 epoch, bytes32 root) internal {
        bytes32 manifestHash = keccak256(abi.encodePacked("manifest-", epoch));
        string memory manifestURI = string.concat("ipfs://manifest-", vm.toString(epoch));

        vm.prank(publisher);
        registry.publishRoot(root, epoch, manifestHash, manifestURI);
    }

    function _buildRequest(
        uint256 epoch,
        bytes32 operationId,
        uint256 amountWei,
        uint256 deadline,
        TrustPathVerifier.SmmProof memory proofDt
    )
        internal
        view
        returns (TrustNetPaymentsGuardModule.PaymentRequest memory req)
    {
        req = TrustNetPaymentsGuardModule.PaymentRequest({
            epoch: epoch,
            deadline: deadline,
            operationId: operationId,
            target: target,
            endorser: address(0),
            to: payable(recipient),
            amountWei: amountWei,
            proofDt: proofDt,
            proofDe: _emptyProof(),
            proofEt: _emptyProof()
        });
    }

    function _emptyProof() internal pure returns (TrustPathVerifier.SmmProof memory) {
        return TrustPathVerifier.SmmProof({
            isAbsent: true,
            leafValue: bytes(""),
            bitmap: bytes32(0),
            siblings: new bytes32[](0)
        });
    }

    function _defaultHashes() internal pure returns (bytes32[] memory defaults) {
        defaults = new bytes32[](257);
        defaults[0] = TrustPathVerifier.computeEmptyHash();
        for (uint256 i = 0; i < 256; i++) {
            defaults[i + 1] = TrustPathVerifier.computeInternalHash(defaults[i], defaults[i]);
        }
    }

    function _buildMembershipProof(
        address rater,
        address proofTarget,
        bytes32 proofContext,
        int8 level
    )
        internal
        pure
        returns (TrustPathVerifier.SmmProof memory proof, bytes32 root)
    {
        bytes memory leafValue = _encodeLeafValue(level);
        bytes32[] memory siblings = new bytes32[](0);
        bytes32[] memory defaults = _defaultHashes();

        bytes32 edgeKey = TrustPathVerifier.computeEdgeKey(rater, proofTarget, proofContext);

        bytes32 h = TrustPathVerifier.computeLeafHash(edgeKey, leafValue);
        for (uint256 i = 0; i < 256; i++) {
            bytes32 sibling = defaults[i];
            uint256 depth = 255 - i;
            if (_getBit(edgeKey, depth) == 0) {
                h = TrustPathVerifier.computeInternalHash(h, sibling);
            } else {
                h = TrustPathVerifier.computeInternalHash(sibling, h);
            }
        }

        proof = TrustPathVerifier.SmmProof({
            isAbsent: false,
            leafValue: leafValue,
            bitmap: bytes32(0),
            siblings: siblings
        });
        root = h;
    }

    function _encodeLeafValue(int8 level) internal pure returns (bytes memory) {
        require(level >= -2 && level <= 2, "level out of range");
        uint8 levelEnc;
        if (level == -2) {
            levelEnc = 0;
        } else if (level == -1) {
            levelEnc = 1;
        } else if (level == 0) {
            levelEnc = 2;
        } else if (level == 1) {
            levelEnc = 3;
        } else {
            levelEnc = 4;
        }
        return abi.encodePacked(bytes1(levelEnc));
    }

    function _getBit(bytes32 key, uint256 index) internal pure returns (uint8) {
        uint8 b = uint8(key[index / 8]);
        uint8 bitIndex = uint8(7 - (index % 8));
        return (b >> bitIndex) & 1;
    }
}
