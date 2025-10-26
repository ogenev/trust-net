// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title RootRegistry
 * @notice On-chain anchor for Sparse Merkle Map (SMM) commitments in TrustNet
 * @dev Part of TrustNet reputation layer for ERC-8004 agents
 *
 * RootRegistry stores the active graphRoot and epoch, enabling verifiers to
 * check TrustPathVerifier proofs against the latest trust graph state. The off-chain
 * Indexer builds the SMM from EdgeRated events and publishes roots here.
 *
 * Phase 1 (MVP) features:
 * - Basic root storage and retrieval
 * - Single publisher model
 * - Simple epoch advancement (monotonically increasing)
 *
 * Spec: https://github.com/trustnet/whitepaper Section 6.2
 */
contract RootRegistry {
    /// @notice Version identifier for this contract
    string public constant VERSION = "trustnet-v1";

    /// @notice Current active Sparse Merkle Map root
    bytes32 public currentRoot;

    /// @notice Current epoch number (monotonically increasing)
    uint256 public currentEpoch;

    /// @notice Historical roots mapping for lookups
    mapping(uint256 => bytes32) public rootHistory;

    /// @notice Timestamp when each epoch was published
    mapping(uint256 => uint256) public epochTimestamps;

    /// @notice Contract owner (can change publisher)
    address public owner;

    /// @notice Authorized publisher (typically the indexer)
    address public publisher;

    /**
     * @notice Emitted when a new root is published
     * @param epoch The epoch number for this root
     * @param root The Sparse Merkle Map root hash
     * @param publisher Address that published this root
     * @param timestamp Block timestamp of publication
     */
    event RootPublished(
        uint256 indexed epoch,
        bytes32 indexed root,
        address indexed publisher,
        uint256 timestamp
    );

    /**
     * @notice Emitted when the publisher is changed
     * @param oldPublisher Previous publisher address
     * @param newPublisher New publisher address
     */
    event PublisherChanged(address indexed oldPublisher, address indexed newPublisher);

    /**
     * @notice Emitted when ownership is transferred
     * @param previousOwner Previous owner address
     * @param newOwner New owner address
     */
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @notice Error thrown when caller is not authorized
     */
    error Unauthorized();

    /**
     * @notice Error thrown when epoch is not sequential
     * @param provided The epoch provided
     * @param expected The expected epoch (currentEpoch + 1)
     */
    error InvalidEpoch(uint256 provided, uint256 expected);

    /**
     * @notice Error thrown when root is invalid (zero)
     */
    error InvalidRoot();

    /**
     * @notice Error thrown when address is zero
     */
    error ZeroAddress();

    /**
     * @dev Modifier to restrict function access to owner
     */
    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        _;
    }

    /**
     * @dev Modifier to restrict function access to publisher
     */
    modifier onlyPublisher() {
        if (msg.sender != publisher) {
            revert Unauthorized();
        }
        _;
    }

    /**
     * @notice Deploy a new RootRegistry
     * @param _publisher Initial publisher address (typically the indexer)
     *
     * @dev msg.sender becomes the owner
     * @dev currentEpoch starts at 0, no root set initially
     */
    constructor(address _publisher) {
        if (_publisher == address(0)) {
            revert ZeroAddress();
        }

        owner = msg.sender;
        publisher = _publisher;
        currentEpoch = 0;
        // currentRoot remains 0x0 until first publish
    }

    /**
     * @notice Publish a new Sparse Merkle Map root
     * @param newRoot The new SMM root hash
     * @param epoch The epoch number (must be currentEpoch + 1)
     *
     * @dev Only callable by authorized publisher
     * @dev Epochs must increase monotonically
     * @dev Root cannot be zero
     * @dev Emits RootPublished event
     *
     * Example:
     * - Indexer builds SMM from EdgeRated events
     * - Calls publishRoot(0xabc..., 1) to publish epoch 1
     */
    function publishRoot(bytes32 newRoot, uint256 epoch) external onlyPublisher {
        // Validate root is not zero
        if (newRoot == bytes32(0)) {
            revert InvalidRoot();
        }

        // Validate epoch is sequential (currentEpoch + 1)
        uint256 expectedEpoch = currentEpoch + 1;
        if (epoch != expectedEpoch) {
            revert InvalidEpoch(epoch, expectedEpoch);
        }

        // Update current state
        currentRoot = newRoot;
        currentEpoch = epoch;

        // Store in history
        rootHistory[epoch] = newRoot;
        epochTimestamps[epoch] = block.timestamp;

        // Emit event
        emit RootPublished(epoch, newRoot, msg.sender, block.timestamp);
    }

    /**
     * @notice Get the root hash for a specific epoch
     * @param epoch The epoch to query
     * @return The root hash for that epoch, or 0x0 if not found
     *
     * @dev Returns 0x0 for future epochs or epochs that were never published
     */
    function getRootAt(uint256 epoch) external view returns (bytes32) {
        return rootHistory[epoch];
    }

    /**
     * @notice Check if a root matches a specific epoch
     * @param root The root hash to verify
     * @param epoch The epoch to check against
     * @return True if the root matches the epoch's stored root
     *
     * @dev Used by verifiers to validate proofs
     */
    function verifyRoot(bytes32 root, uint256 epoch) external view returns (bool) {
        return rootHistory[epoch] == root && rootHistory[epoch] != bytes32(0);
    }

    /**
     * @notice Check if an epoch has been published
     * @param epoch The epoch to check
     * @return True if the epoch has a published root
     */
    function isValidEpoch(uint256 epoch) external view returns (bool) {
        return rootHistory[epoch] != bytes32(0);
    }

    /**
     * @notice Get the timestamp when an epoch was published
     * @param epoch The epoch to query
     * @return The block timestamp when the epoch was published, or 0 if not found
     */
    function getEpochTimestamp(uint256 epoch) external view returns (uint256) {
        return epochTimestamps[epoch];
    }

    /**
     * @notice Change the authorized publisher
     * @param newPublisher The new publisher address
     *
     * @dev Only callable by owner
     * @dev Emits PublisherChanged event
     */
    function setPublisher(address newPublisher) external onlyOwner {
        if (newPublisher == address(0)) {
            revert ZeroAddress();
        }

        address oldPublisher = publisher;
        publisher = newPublisher;

        emit PublisherChanged(oldPublisher, newPublisher);
    }

    /**
     * @notice Transfer ownership to a new address
     * @param newOwner The new owner address
     *
     * @dev Only callable by current owner
     * @dev Emits OwnershipTransferred event
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert ZeroAddress();
        }

        address previousOwner = owner;
        owner = newOwner;

        emit OwnershipTransferred(previousOwner, newOwner);
    }
}
