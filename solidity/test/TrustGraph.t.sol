// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Test, console} from "forge-std/Test.sol";
import {TrustGraph} from "../TrustGraph.sol";
import {TrustNetContexts} from "../TrustNetContexts.sol";

contract TrustGraphTest is Test {
    TrustGraph public trustGraph;

    // Test addresses
    address public alice = address(0x1);
    address public bob = address(0x2);
    address public charlie = address(0x3);
    address public dave = address(0x4);

    // Events for testing
    event EdgeRated(
        address indexed rater,
        address indexed target,
        int8 level,
        bytes32 indexed contextId
    );

    function _addressFromUint(uint256 value) private pure returns (address) {
        // Test values are tiny and always fit into address width.
        // forge-lint: disable-next-line(unsafe-typecast)
        return address(uint160(value));
    }

    function _cycledTrustLevel(uint256 index) private pure returns (int8) {
        int8[5] memory levels = [int8(-2), -1, 0, 1, 2];
        return levels[index % levels.length];
    }

    function setUp() public {
        trustGraph = new TrustGraph();

        // Label addresses for better trace output
        vm.label(alice, "Alice");
        vm.label(bob, "Bob");
        vm.label(charlie, "Charlie");
        vm.label(dave, "Dave");
    }

    // ============ Single Edge Rating Tests ============

    function test_RateEdge_ValidTrustLevels() public {
        // Test all valid trust levels (-2 to 2)
        int8[5] memory validLevels = [int8(-2), -1, 0, 1, 2];

        for (uint i = 0; i < validLevels.length; i++) {
            vm.startPrank(alice);

            // Expect the event
            vm.expectEmit(true, true, true, true);
            emit EdgeRated(alice, bob, validLevels[i], TrustNetContexts.GLOBAL);

            trustGraph.rateEdge(bob, validLevels[i], TrustNetContexts.GLOBAL);
            vm.stopPrank();
        }
    }

    function test_RateEdge_DifferentContexts() public {
        vm.startPrank(alice);

        // Test with different canonical contexts
        bytes32[5] memory contexts = [
            TrustNetContexts.GLOBAL,
            TrustNetContexts.PAYMENTS,
            TrustNetContexts.CODE_EXEC,
            TrustNetContexts.WRITES,
            TrustNetContexts.DEFI_EXEC
        ];

        for (uint i = 0; i < contexts.length; i++) {
            vm.expectEmit(true, true, true, true);
            emit EdgeRated(alice, bob, 1, contexts[i]);
            trustGraph.rateEdge(bob, 1, contexts[i]);
        }

        vm.stopPrank();
    }

    function test_RateEdge_CustomContext() public {
        // Test with custom context
        bytes32 customContext = keccak256("custom:context:v1");

        vm.startPrank(alice);
        vm.expectEmit(true, true, true, true);
        emit EdgeRated(alice, bob, 2, customContext);
        trustGraph.rateEdge(bob, 2, customContext);
        vm.stopPrank();
    }

    function test_RateEdge_MultipleRatersToSameTarget() public {
        // Different raters rating the same target
        vm.prank(alice);
        trustGraph.rateEdge(bob, 2, TrustNetContexts.GLOBAL);

        vm.prank(charlie);
        trustGraph.rateEdge(bob, -1, TrustNetContexts.GLOBAL);

        vm.prank(dave);
        trustGraph.rateEdge(bob, 0, TrustNetContexts.GLOBAL);
    }

    function test_RateEdge_UpdateExistingRating() public {
        vm.startPrank(alice);

        // First rating
        trustGraph.rateEdge(bob, 2, TrustNetContexts.PAYMENTS);

        // Update rating (latest-wins semantics)
        vm.expectEmit(true, true, true, true);
        emit EdgeRated(alice, bob, -1, TrustNetContexts.PAYMENTS);
        trustGraph.rateEdge(bob, -1, TrustNetContexts.PAYMENTS);

        vm.stopPrank();
    }

    function testRevert_RateEdge_InvalidTrustLevel_TooHigh() public {
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(TrustGraph.InvalidLevel.selector, int8(3)));
        trustGraph.rateEdge(bob, 3, TrustNetContexts.GLOBAL);
        vm.stopPrank();
    }

    function testRevert_RateEdge_InvalidTrustLevel_TooLow() public {
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(TrustGraph.InvalidLevel.selector, int8(-3)));
        trustGraph.rateEdge(bob, -3, TrustNetContexts.GLOBAL);
        vm.stopPrank();
    }

    function testRevert_RateEdge_ZeroAddress() public {
        vm.startPrank(alice);
        vm.expectRevert(TrustGraph.InvalidTarget.selector);
        trustGraph.rateEdge(address(0), 1, TrustNetContexts.GLOBAL);
        vm.stopPrank();
    }

    // ============ Batch Edge Rating Tests ============

    function test_RateEdgeBatch_ValidBatch() public {
        address[] memory targets = new address[](3);
        targets[0] = bob;
        targets[1] = charlie;
        targets[2] = dave;

        int8[] memory levels = new int8[](3);
        levels[0] = 2;
        levels[1] = -1;
        levels[2] = 0;

        bytes32[] memory contexts = new bytes32[](3);
        contexts[0] = TrustNetContexts.PAYMENTS;
        contexts[1] = TrustNetContexts.CODE_EXEC;
        contexts[2] = TrustNetContexts.GLOBAL;

        vm.startPrank(alice);

        // Expect all three events
        for (uint i = 0; i < targets.length; i++) {
            vm.expectEmit(true, true, true, true);
            emit EdgeRated(alice, targets[i], levels[i], contexts[i]);
        }

        trustGraph.rateEdgeBatch(targets, levels, contexts);
        vm.stopPrank();
    }

    function test_RateEdgeBatch_EmptyBatch() public {
        address[] memory targets = new address[](0);
        int8[] memory levels = new int8[](0);
        bytes32[] memory contexts = new bytes32[](0);

        vm.prank(alice);
        // Should succeed with no events
        trustGraph.rateEdgeBatch(targets, levels, contexts);
    }

    function test_RateEdgeBatch_SingleItem() public {
        address[] memory targets = new address[](1);
        targets[0] = bob;

        int8[] memory levels = new int8[](1);
        levels[0] = 1;

        bytes32[] memory contexts = new bytes32[](1);
        contexts[0] = TrustNetContexts.DEFI_EXEC;

        vm.startPrank(alice);
        vm.expectEmit(true, true, true, true);
        emit EdgeRated(alice, bob, 1, TrustNetContexts.DEFI_EXEC);
        trustGraph.rateEdgeBatch(targets, levels, contexts);
        vm.stopPrank();
    }

    function test_RateEdgeBatch_LargeBatch() public {
        uint256 batchSize = 50;
        address[] memory targets = new address[](batchSize);
        int8[] memory levels = new int8[](batchSize);
        bytes32[] memory contexts = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            targets[i] = _addressFromUint(i + 100);
            levels[i] = _cycledTrustLevel(i);
            contexts[i] = TrustNetContexts.GLOBAL;
        }

        vm.prank(alice);
        trustGraph.rateEdgeBatch(targets, levels, contexts);
    }

    function testRevert_RateEdgeBatch_MismatchedArrayLengths_TargetsLevels() public {
        address[] memory targets = new address[](2);
        targets[0] = bob;
        targets[1] = charlie;

        int8[] memory levels = new int8[](1);
        levels[0] = 1;

        bytes32[] memory contexts = new bytes32[](2);
        contexts[0] = TrustNetContexts.GLOBAL;
        contexts[1] = TrustNetContexts.GLOBAL;

        vm.prank(alice);
        vm.expectRevert("Array length mismatch");
        trustGraph.rateEdgeBatch(targets, levels, contexts);
    }

    function testRevert_RateEdgeBatch_MismatchedArrayLengths_TargetsContexts() public {
        address[] memory targets = new address[](2);
        targets[0] = bob;
        targets[1] = charlie;

        int8[] memory levels = new int8[](2);
        levels[0] = 1;
        levels[1] = 2;

        bytes32[] memory contexts = new bytes32[](1);
        contexts[0] = TrustNetContexts.GLOBAL;

        vm.prank(alice);
        vm.expectRevert("Array length mismatch");
        trustGraph.rateEdgeBatch(targets, levels, contexts);
    }

    function testRevert_RateEdgeBatch_ContainsZeroAddress() public {
        address[] memory targets = new address[](3);
        targets[0] = bob;
        targets[1] = address(0); // Invalid
        targets[2] = charlie;

        int8[] memory levels = new int8[](3);
        levels[0] = 1;
        levels[1] = 2;
        levels[2] = -1;

        bytes32[] memory contexts = new bytes32[](3);
        contexts[0] = TrustNetContexts.GLOBAL;
        contexts[1] = TrustNetContexts.GLOBAL;
        contexts[2] = TrustNetContexts.GLOBAL;

        vm.prank(alice);
        vm.expectRevert(TrustGraph.InvalidTarget.selector);
        trustGraph.rateEdgeBatch(targets, levels, contexts);
    }

    function testRevert_RateEdgeBatch_ContainsInvalidLevel() public {
        address[] memory targets = new address[](3);
        targets[0] = bob;
        targets[1] = charlie;
        targets[2] = dave;

        int8[] memory levels = new int8[](3);
        levels[0] = 1;
        levels[1] = 5; // Invalid
        levels[2] = -1;

        bytes32[] memory contexts = new bytes32[](3);
        contexts[0] = TrustNetContexts.GLOBAL;
        contexts[1] = TrustNetContexts.GLOBAL;
        contexts[2] = TrustNetContexts.GLOBAL;

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TrustGraph.InvalidLevel.selector, int8(5)));
        trustGraph.rateEdgeBatch(targets, levels, contexts);
    }

    // ============ Fuzz Tests ============

    function testFuzz_RateEdge_ValidInputs(
        address rater,
        address target,
        int8 level,
        bytes32 contextId
    ) public {
        vm.assume(rater != address(0));
        vm.assume(target != address(0));
        vm.assume(level >= -2 && level <= 2);

        vm.startPrank(rater);
        vm.expectEmit(true, true, true, true);
        emit EdgeRated(rater, target, level, contextId);
        trustGraph.rateEdge(target, level, contextId);
        vm.stopPrank();
    }

    function testFuzz_RateEdge_InvalidLevel(address target, int8 level) public {
        vm.assume(target != address(0));
        vm.assume(level < -2 || level > 2);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(TrustGraph.InvalidLevel.selector, level));
        trustGraph.rateEdge(target, level, TrustNetContexts.GLOBAL);
    }

    function testFuzz_RateEdgeBatch(
        uint8 batchSize,
        int8 baseTrustLevel
    ) public {
        vm.assume(batchSize <= 100); // Reasonable batch size
        vm.assume(baseTrustLevel >= -2 && baseTrustLevel <= 2);

        address[] memory targets = new address[](batchSize);
        int8[] memory levels = new int8[](batchSize);
        bytes32[] memory contexts = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            targets[i] = _addressFromUint(i + 1000);
            levels[i] = baseTrustLevel;
            contexts[i] = TrustNetContexts.GLOBAL;
        }

        vm.prank(alice);
        trustGraph.rateEdgeBatch(targets, levels, contexts);
    }

    // ============ Gas Usage Tests ============

    function test_GasUsage_SingleRating() public {
        vm.prank(alice);
        uint256 gasUsed = gasleft();
        trustGraph.rateEdge(bob, 1, TrustNetContexts.GLOBAL);
        gasUsed = gasUsed - gasleft();

        // Should be close to 21k gas as mentioned in docs
        console.log("Gas used for single rating:", gasUsed);
        assertLt(gasUsed, 25000, "Single rating uses too much gas");
    }

    function test_GasUsage_BatchVsSingle() public {
        // Measure single operations
        uint256 singleGasTotal = 0;
        for (uint i = 0; i < 5; i++) {
            vm.prank(alice);
            uint256 gas = gasleft();
            trustGraph.rateEdge(_addressFromUint(i + 1), 1, TrustNetContexts.GLOBAL);
            singleGasTotal += gas - gasleft();
        }

        // Measure batch operation
        address[] memory targets = new address[](5);
        int8[] memory levels = new int8[](5);
        bytes32[] memory contexts = new bytes32[](5);

        for (uint i = 0; i < 5; i++) {
            targets[i] = _addressFromUint(i + 100);
            levels[i] = 1;
            contexts[i] = TrustNetContexts.GLOBAL;
        }

        vm.prank(alice);
        uint256 batchGas = gasleft();
        trustGraph.rateEdgeBatch(targets, levels, contexts);
        batchGas = batchGas - gasleft();

        console.log("Total gas for 5 single ratings:", singleGasTotal);
        console.log("Gas for batch of 5 ratings:", batchGas);

        // Batch should be more efficient
        assertLt(batchGas, singleGasTotal, "Batch operation should be more gas efficient");
    }

    // ============ Invariant Tests ============

    function invariant_NoStateStorage() public view {
        // Contract should have no storage variables
        // Check that slot 0 is empty (would contain first storage variable)
        bytes32 slot0 = vm.load(address(trustGraph), bytes32(uint256(0)));
        assertEq(slot0, bytes32(0), "Contract should have no state storage");
    }

    // ============ Edge Cases ============

    function test_RateEdge_SelfRating() public {
        // Alice rating herself
        vm.startPrank(alice);
        vm.expectEmit(true, true, true, true);
        emit EdgeRated(alice, alice, 2, TrustNetContexts.GLOBAL);
        trustGraph.rateEdge(alice, 2, TrustNetContexts.GLOBAL);
        vm.stopPrank();
    }

    function test_RateEdge_MaxMinValues() public {
        vm.startPrank(alice);

        // Test extreme trust levels
        trustGraph.rateEdge(bob, type(int8).min / 64, TrustNetContexts.GLOBAL); // -2
        trustGraph.rateEdge(charlie, type(int8).max / 64, TrustNetContexts.GLOBAL); // 1 (due to division)

        vm.stopPrank();
    }

    function test_RateEdge_ZeroContextId() public {
        vm.startPrank(alice);
        vm.expectEmit(true, true, true, true);
        emit EdgeRated(alice, bob, 1, bytes32(0));
        trustGraph.rateEdge(bob, 1, bytes32(0));
        vm.stopPrank();
    }
}
