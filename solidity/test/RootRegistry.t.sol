// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";
import {RootRegistry} from "../RootRegistry.sol";

contract RootRegistryTest is Test {
    RootRegistry public registry;

    address public owner = address(0x1);
    address public publisher = address(0x2);
    address public newPublisher = address(0x3);
    address public unauthorized = address(0x4);

    bytes32 public root1 = keccak256("root1");
    bytes32 public root2 = keccak256("root2");

    bytes32 public manifestHash1 = keccak256("manifest1");
    bytes32 public manifestHash2 = keccak256("manifest2");

    string public manifestURI1 = "ipfs://manifest1";
    string public manifestURI2 = "ipfs://manifest2";

    event RootPublished(
        uint256 indexed epoch,
        bytes32 indexed root,
        bytes32 manifestHash,
        string manifestURI,
        address indexed publisher,
        uint256 timestamp
    );

    function setUp() public {
        vm.prank(owner);
        registry = new RootRegistry(publisher);
    }

    function test_Constructor_SetsOwnerAndPublisher() public view {
        assertEq(registry.owner(), owner);
        assertEq(registry.publisher(), publisher);
    }

    function test_Constructor_InitializesToZero() public view {
        assertEq(registry.currentEpoch(), 0);
        assertEq(registry.currentRoot(), bytes32(0));
        assertEq(registry.currentManifestHash(), bytes32(0));
        assertEq(registry.currentManifestURI(), "");
    }

    function test_PublishRoot_FirstEpoch_StoresRootAndManifest() public {
        vm.prank(publisher);

        vm.expectEmit(true, true, true, true);
        emit RootPublished(1, root1, manifestHash1, manifestURI1, publisher, block.timestamp);

        registry.publishRoot(root1, 1, manifestHash1, manifestURI1);

        assertEq(registry.currentEpoch(), 1);
        assertEq(registry.currentRoot(), root1);
        assertEq(registry.currentManifestHash(), manifestHash1);
        assertEq(registry.currentManifestURI(), manifestURI1);
        assertEq(registry.getRootAt(1), root1);
        assertEq(registry.getManifestHashAt(1), manifestHash1);
        assertEq(registry.getManifestURIAt(1), manifestURI1);
    }

    function test_PublishRoot_SequentialEpochs() public {
        vm.startPrank(publisher);

        registry.publishRoot(root1, 1, manifestHash1, manifestURI1);
        registry.publishRoot(root2, 2, manifestHash2, manifestURI2);

        assertEq(registry.currentEpoch(), 2);
        assertEq(registry.currentRoot(), root2);
        assertEq(registry.getRootAt(1), root1);
        assertEq(registry.getRootAt(2), root2);

        vm.stopPrank();
    }

    function test_PublishRoot_RejectsNonSequentialEpoch() public {
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(RootRegistry.InvalidEpoch.selector, 2, 1));
        registry.publishRoot(root1, 2, manifestHash1, manifestURI1);
    }

    function test_PublishRoot_RejectsZeroRoot() public {
        vm.prank(publisher);
        vm.expectRevert(RootRegistry.InvalidRoot.selector);
        registry.publishRoot(bytes32(0), 1, manifestHash1, manifestURI1);
    }

    function test_PublishRoot_RejectsZeroManifestHash() public {
        vm.prank(publisher);
        vm.expectRevert(RootRegistry.InvalidRoot.selector);
        registry.publishRoot(root1, 1, bytes32(0), manifestURI1);
    }

    function test_PublishRoot_RejectsUnauthorizedCaller() public {
        vm.prank(unauthorized);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.publishRoot(root1, 1, manifestHash1, manifestURI1);
    }

    function test_VerifyRoot() public {
        vm.prank(publisher);
        registry.publishRoot(root1, 1, manifestHash1, manifestURI1);

        assertTrue(registry.verifyRoot(root1, 1));
        assertFalse(registry.verifyRoot(root2, 1));
        assertFalse(registry.verifyRoot(root1, 2));
    }

    function test_SetPublisher_OwnerOnly() public {
        vm.prank(unauthorized);
        vm.expectRevert(RootRegistry.Unauthorized.selector);
        registry.setPublisher(newPublisher);

        vm.prank(owner);
        registry.setPublisher(newPublisher);
        assertEq(registry.publisher(), newPublisher);
    }

    function test_TransferOwnership_ChangesOwner() public {
        address newOwner = address(0x99);
        vm.prank(owner);
        registry.transferOwnership(newOwner);
        assertEq(registry.owner(), newOwner);
    }
}
