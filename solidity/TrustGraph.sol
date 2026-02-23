// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

/**
 * @title TrustGraph
 * @notice Events-only contract for recording trust edges in TrustNet
 * @dev Part of TrustNet reputation layer for ERC-8004 agents
 *
 * TrustGraph emits EdgeRated events to record curator edges (O→Y) and
 * direct override edges (O→T). These events are ingested by off-chain
 * indexers to build the Sparse Merkle Map and compute trust scores.
 *
 * This contract stores NO state - it only emits events for minimal gas cost.
 * Latest-wins semantics are enforced by indexers using (block, txIndex, logIndex).
 *
 * Spec: docs/TRUSTNET_v1.1.md §7
 */
contract TrustGraph {
    /// @notice Version identifier for this contract
    string public constant VERSION = "trustnet-v1";

    /// @notice Minimum allowed trust level
    int8 public constant MIN_LEVEL = -2;

    /// @notice Maximum allowed trust level
    int8 public constant MAX_LEVEL = 2;

    /**
     * @notice Emitted when a trust edge is rated
     * @param rater Address setting the trust rating (decider or curator)
     * @param target Address receiving the rating (endorser or agent)
     * @param level Trust level in range [-2, +2]
     *        -2: Strong distrust
     *        -1: Mild distrust
     *         0: Neutral
     *        +1: Mild trust
     *        +2: Strong trust
     * @param contextId Capability namespace (e.g., payments, code-exec, writes)
     *
     * @dev Latest event per (rater, target, contextId) prevails
     * @dev Ordering: (blockNumber, transactionIndex, logIndex)
     */
    event EdgeRated(
        address indexed rater,
        address indexed target,
        int8 level,
        bytes32 indexed contextId
    );

    /**
     * @notice Error thrown when trust level is out of valid range
     * @param level The invalid level provided
     */
    error InvalidLevel(int8 level);

    /**
     * @notice Error thrown when target address is zero
     */
    error InvalidTarget();

    /**
     * @notice Record a trust edge rating
     * @param target Address to rate (must not be zero address)
     * @param level Trust level, must be in range [-2, +2]
     * @param contextId Capability namespace to scope the rating
     *
     * @dev msg.sender is the rater
     * @dev Emits EdgeRated event
     * @dev Gas cost: ~21k for first rating in a tx, ~5k for subsequent
     *
     * Examples:
     * - Decider rates curator: rateEdge(curatorAddress, +2, PAYMENTS_CTX)
     * - Decider overrides agent: rateEdge(agentAddress, -2, PAYMENTS_CTX)
     * - Curator rates agent: rateEdge(agentAddress, +1, CODE_EXEC_CTX)
     */
    function rateEdge(
        address target,
        int8 level,
        bytes32 contextId
    ) external {
        // Validate target address
        if (target == address(0)) {
            revert InvalidTarget();
        }

        // Validate level is in range [-2, +2]
        if (level < MIN_LEVEL || level > MAX_LEVEL) {
            revert InvalidLevel(level);
        }

        // Emit event (no storage writes for minimal gas)
        emit EdgeRated(msg.sender, target, level, contextId);
    }

    /**
     * @notice Record multiple trust edge ratings in a single transaction
     * @param targets Array of addresses to rate
     * @param levels Array of trust levels corresponding to targets
     * @param contextIds Array of context IDs corresponding to targets
     *
     * @dev All arrays must have the same length
     * @dev More gas-efficient than multiple individual calls
     * @dev Useful for bulk rating updates by curators
     */
    function rateEdgeBatch(
        address[] calldata targets,
        int8[] calldata levels,
        bytes32[] calldata contextIds
    ) external {
        uint256 length = targets.length;

        // Validate array lengths match
        require(
            length == levels.length && length == contextIds.length,
            "Array length mismatch"
        );

        // Rate each edge
        for (uint256 i = 0; i < length; i++) {
            address target = targets[i];
            int8 level = levels[i];

            // Validate target address
            if (target == address(0)) {
                revert InvalidTarget();
            }

            // Validate level is in range [-2, +2]
            if (level < MIN_LEVEL || level > MAX_LEVEL) {
                revert InvalidLevel(level);
            }

            // Emit event
            emit EdgeRated(msg.sender, target, level, contextIds[i]);
        }
    }
}
