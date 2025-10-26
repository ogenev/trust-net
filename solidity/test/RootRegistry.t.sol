// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../RootRegistry.sol";

contract RootRegistryTest is Test {
    RootRegistry public registry;

    // Test addresses
    address public owner = address(0x1);
    address public publisher = address(0x2);
    address public newPublisher = address(0x3);
    address public unauthorized = address(0x4);

    // Test roots
    bytes32 public root1 = keccak256("root1");
    bytes32 public root2 = keccak256("root2");
    bytes32 public root3 = keccak256("root3");

    // Events for testing
    event RootPublished(
        uint256 indexed epoch,
        bytes32 indexed root,
        address indexed publisher,
        uint256 timestamp
    );

    event PublisherChanged(address indexed oldPublisher, address indexed newPublisher);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        // Deploy as owner with publisher set
        vm.prank(owner);
        registry = new RootRegistry(publisher);

        // Label addresses for better trace output
        vm.label(owner, "Owner");
        vm.label(publisher, "Publisher");
        vm.label(newPublisher, "NewPublisher");
        vm.label(unauthorized, "Unauthorized");
    }

    // ============ Constructor Tests ============

    function test_Constructor_SetsOwner() public view {
        assertEq(registry.owner(), owner, "Owner should be set correctly");
    }

    function test_Constructor_SetsPublisher() public view {
        assertEq(registry.publisher(), publisher, "Publisher should be set correctly");
    }

    function test_Constructor_InitializesEpochToZero() public view {
        assertEq(registry.currentEpoch(), 0, "Current epoch should start at 0");
    }

    function test_Constructor_InitializesRootToZero() public view {
        assertEq(registry.currentRoot(), bytes32(0), "Current root should start at 0x0");
    }

    function test_Constructor_RejectsZeroPublisher() public {
        vm.expectRevert(RootRegistry.ZeroAddress.selector);
        vm.prank(owner);
        new RootRegistry(address(0));
    }

    function test_Constructor_SetsVersion() public view {
        assertEq(registry.VERSION(), "trustnet-v1", "Version should be trustnet-v1");
    }

    // ============ PublishRoot Tests ============

    function test_PublishRoot_FirstEpoch() public {
        vm.prank(publisher);

        // Expect the event
        vm.expectEmit(true, true, true, true);
        emit RootPublished(1, root1, publisher, block.timestamp);

        registry.publishRoot(root1, 1);

        assertEq(registry.currentRoot(), root1, "Current root should be updated");
        assertEq(registry.currentEpoch(), 1, "Current epoch should be 1");
    }

    function test_PublishRoot_SequentialEpochs() public {
        vm.startPrank(publisher);

        // Publish epoch 1
        registry.publishRoot(root1, 1);
        assertEq(registry.currentEpoch(), 1);
        assertEq(registry.currentRoot(), root1);

        // Publish epoch 2
        registry.publishRoot(root2, 2);
        assertEq(registry.currentEpoch(), 2);
        assertEq(registry.currentRoot(), root2);

        // Publish epoch 3
        registry.publishRoot(root3, 3);
        assertEq(registry.currentEpoch(), 3);
        assertEq(registry.currentRoot(), root3);

        vm.stopPrank();
    }

    function test_PublishRoot_StoresInHistory() public {
        vm.startPrank(publisher);

        registry.publishRoot(root1, 1);
        registry.publishRoot(root2, 2);

        vm.stopPrank();

        assertEq(registry.getRootAt(1), root1, "Root 1 should be in history");
        assertEq(registry.getRootAt(2), root2, "Root 2 should be in history");
    }

    function test_PublishRoot_RecordsTimestamp() public {
        vm.prank(publisher);
        uint256 timestamp = block.timestamp;
        registry.publishRoot(root1, 1);

        assertEq(registry.getEpochTimestamp(1), timestamp, "Timestamp should be recorded");
    }

    function test_PublishRoot_RejectsNonSequentialEpoch() public {
        vm.startPrank(publisher);

        // Skip from epoch 0 to epoch 2 (should fail)
        vm.expectRevert(abi.encodeWithSelector(RootRegistry.InvalidEpoch.selector, 2, 1));
        registry.publishRoot(root1, 2);

        // Publish epoch 1 successfully
        registry.publishRoot(root1, 1);

        // Try to skip to epoch 3 (should fail)
        vm.expectRevert(abi.encodeWithSelector(RootRegistry.InvalidEpoch.selector, 3, 2));
        registry.publishRoot(root2, 3);

        vm.stopPrank();
    }

    function test_PublishRoot_RejectsZeroRoot() public {
        vm.prank(publisher);
        vm.expectRevert(RootRegistry.InvalidRoot.selector);
        registry.publishRoot(bytes32(0), 1);
    }

    function test_PublishRoot_RejectsUnauthorizedCaller() public {
        vm.prank(unauthorized);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.publishRoot(root1, 1);
    }

    function test_PublishRoot_OwnerCannotPublish() public {
        vm.prank(owner);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.publishRoot(root1, 1);
    }

    function test_PublishRoot_EmitsEvent() public {
        vm.prank(publisher);

        vm.expectEmit(true, true, true, true);
        emit RootPublished(1, root1, publisher, block.timestamp);

        registry.publishRoot(root1, 1);
    }

    // ============ GetRootAt Tests ============

    function test_GetRootAt_ReturnsCorrectRoot() public {
        vm.startPrank(publisher);
        registry.publishRoot(root1, 1);
        registry.publishRoot(root2, 2);
        vm.stopPrank();

        assertEq(registry.getRootAt(1), root1, "Should return root1 for epoch 1");
        assertEq(registry.getRootAt(2), root2, "Should return root2 for epoch 2");
    }

    function test_GetRootAt_ReturnsZeroForUnpublishedEpoch() public view {
        assertEq(registry.getRootAt(1), bytes32(0), "Should return 0x0 for unpublished epoch");
        assertEq(registry.getRootAt(999), bytes32(0), "Should return 0x0 for future epoch");
    }

    // ============ VerifyRoot Tests ============

    function test_VerifyRoot_ReturnsTrueForValidRoot() public {
        vm.prank(publisher);
        registry.publishRoot(root1, 1);

        assertTrue(registry.verifyRoot(root1, 1), "Should verify correct root for epoch");
    }

    function test_VerifyRoot_ReturnsFalseForWrongRoot() public {
        vm.prank(publisher);
        registry.publishRoot(root1, 1);

        assertFalse(registry.verifyRoot(root2, 1), "Should not verify wrong root");
    }

    function test_VerifyRoot_ReturnsFalseForUnpublishedEpoch() public view {
        assertFalse(registry.verifyRoot(root1, 1), "Should not verify unpublished epoch");
    }

    function test_VerifyRoot_ReturnsFalseForZeroRoot() public view {
        assertFalse(registry.verifyRoot(bytes32(0), 1), "Should not verify zero root");
    }

    // ============ IsValidEpoch Tests ============

    function test_IsValidEpoch_ReturnsTrueForPublishedEpoch() public {
        vm.prank(publisher);
        registry.publishRoot(root1, 1);

        assertTrue(registry.isValidEpoch(1), "Should return true for published epoch");
    }

    function test_IsValidEpoch_ReturnsFalseForUnpublishedEpoch() public view {
        assertFalse(registry.isValidEpoch(1), "Should return false for unpublished epoch");
        assertFalse(registry.isValidEpoch(0), "Should return false for epoch 0");
    }

    // ============ GetEpochTimestamp Tests ============

    function test_GetEpochTimestamp_ReturnsCorrectTimestamp() public {
        uint256 timestamp = block.timestamp;
        vm.prank(publisher);
        registry.publishRoot(root1, 1);

        assertEq(
            registry.getEpochTimestamp(1),
            timestamp,
            "Should return correct timestamp"
        );
    }

    function test_GetEpochTimestamp_ReturnsZeroForUnpublishedEpoch() public view {
        assertEq(registry.getEpochTimestamp(1), 0, "Should return 0 for unpublished epoch");
    }

    // ============ SetPublisher Tests ============

    function test_SetPublisher_OwnerCanChangePublisher() public {
        vm.prank(owner);

        vm.expectEmit(true, true, false, false);
        emit PublisherChanged(publisher, newPublisher);

        registry.setPublisher(newPublisher);

        assertEq(registry.publisher(), newPublisher, "Publisher should be updated");
    }

    function test_SetPublisher_NewPublisherCanPublish() public {
        // Change publisher
        vm.prank(owner);
        registry.setPublisher(newPublisher);

        // New publisher can publish
        vm.prank(newPublisher);
        registry.publishRoot(root1, 1);

        assertEq(registry.currentRoot(), root1, "New publisher should be able to publish");
    }

    function test_SetPublisher_OldPublisherCannotPublish() public {
        // Change publisher
        vm.prank(owner);
        registry.setPublisher(newPublisher);

        // Old publisher cannot publish anymore
        vm.prank(publisher);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.publishRoot(root1, 1);
    }

    function test_SetPublisher_RejectsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(RootRegistry.ZeroAddress.selector);
        registry.setPublisher(address(0));
    }

    function test_SetPublisher_RejectsUnauthorizedCaller() public {
        vm.prank(unauthorized);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.setPublisher(newPublisher);
    }

    function test_SetPublisher_PublisherCannotChangePublisher() public {
        vm.prank(publisher);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.setPublisher(newPublisher);
    }

    // ============ TransferOwnership Tests ============

    function test_TransferOwnership_OwnerCanTransfer() public {
        address newOwner = address(0x5);

        vm.prank(owner);

        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, newOwner);

        registry.transferOwnership(newOwner);

        assertEq(registry.owner(), newOwner, "Owner should be updated");
    }

    function test_TransferOwnership_NewOwnerHasControl() public {
        address newOwner = address(0x5);

        vm.prank(owner);
        registry.transferOwnership(newOwner);

        // New owner can change publisher
        vm.prank(newOwner);
        registry.setPublisher(newPublisher);

        assertEq(registry.publisher(), newPublisher, "New owner should have control");
    }

    function test_TransferOwnership_OldOwnerLosesControl() public {
        address newOwner = address(0x5);

        vm.prank(owner);
        registry.transferOwnership(newOwner);

        // Old owner cannot change publisher anymore
        vm.prank(owner);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.setPublisher(newPublisher);
    }

    function test_TransferOwnership_RejectsZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(RootRegistry.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }

    function test_TransferOwnership_RejectsUnauthorizedCaller() public {
        vm.prank(unauthorized);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.transferOwnership(address(0x5));
    }

    // ============ Integration Tests ============

    function test_Integration_FullPublishingCycle() public {
        // Publisher publishes multiple epochs
        vm.startPrank(publisher);

        for (uint256 i = 1; i <= 5; i++) {
            bytes32 root = keccak256(abi.encodePacked("root", i));
            registry.publishRoot(root, i);

            assertEq(registry.currentEpoch(), i, "Current epoch should be updated");
            assertEq(registry.currentRoot(), root, "Current root should be updated");
            assertTrue(registry.isValidEpoch(i), "Epoch should be valid");
            assertTrue(registry.verifyRoot(root, i), "Root should verify");
        }

        vm.stopPrank();

        // Verify all historical roots
        for (uint256 i = 1; i <= 5; i++) {
            bytes32 expectedRoot = keccak256(abi.encodePacked("root", i));
            assertEq(registry.getRootAt(i), expectedRoot, "Historical root should be correct");
        }
    }

    function test_Integration_OwnershipAndPublisherChange() public {
        address newOwner = address(0x5);

        // Original owner transfers ownership
        vm.prank(owner);
        registry.transferOwnership(newOwner);

        // New owner changes publisher
        vm.prank(newOwner);
        registry.setPublisher(newPublisher);

        // New publisher publishes a root
        vm.prank(newPublisher);
        registry.publishRoot(root1, 1);

        assertEq(registry.currentRoot(), root1, "New publisher should be able to publish");
        assertEq(registry.owner(), newOwner, "Ownership should be transferred");
        assertEq(registry.publisher(), newPublisher, "Publisher should be changed");
    }

    // ============ Edge Cases ============

    function test_EdgeCase_CannotPublishSameEpochTwice() public {
        vm.startPrank(publisher);

        registry.publishRoot(root1, 1);

        // Try to publish epoch 1 again (should fail because current epoch is now 1)
        vm.expectRevert(abi.encodeWithSelector(RootRegistry.InvalidEpoch.selector, 1, 2));
        registry.publishRoot(root2, 1);

        vm.stopPrank();
    }

    function test_EdgeCase_RootCanBeSameAsPrevious() public {
        vm.startPrank(publisher);

        // Publish same root for different epochs (allowed)
        registry.publishRoot(root1, 1);
        registry.publishRoot(root1, 2); // Same root, different epoch

        assertEq(registry.getRootAt(1), root1, "Root 1 should be root1");
        assertEq(registry.getRootAt(2), root1, "Root 2 should also be root1");

        vm.stopPrank();
    }

    function test_EdgeCase_VerifyRootWithZeroEpoch() public view {
        // Epoch 0 is never published, so verification should fail
        assertFalse(registry.verifyRoot(root1, 0), "Should not verify epoch 0");
    }
}
