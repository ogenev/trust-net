// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title TrustNetContexts
 * @notice Canonical context identifiers for TrustNet capability namespaces
 * @dev These context IDs are used to scope trust ratings to specific capabilities,
 *      preventing privilege escalation across different capability domains.
 *
 * Spec: https://github.com/trustnet/whitepaper Section 8.4
 */
library TrustNetContexts {
    /**
     * @notice Global context - general trust rating across all capabilities
     * @dev keccak256("trustnet:ctx:global:v1")
     */
    bytes32 public constant GLOBAL =
        0x430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b;

    /**
     * @notice Payments context - trust for executing payment transactions
     * @dev keccak256("trustnet:ctx:payments:v1")
     * @dev Used for gating payment actions (e.g., agent can spend ≤ $50)
     */
    bytes32 public constant PAYMENTS =
        0x195c31d552212fd148934033b94b89c00b603e2b73e757a2b7684b4cc9602147;

    /**
     * @notice Code execution context - trust for running code/CI/CD
     * @dev keccak256("trustnet:ctx:code-exec:v1")
     * @dev Used for gating code execution (e.g., PR runs, deployment scripts)
     */
    bytes32 public constant CODE_EXEC =
        0x5efe84ba1b51e4f09cf7666eca4d0685fcccf1ee1f5c051bfd1b40c537b4565b;

    /**
     * @notice Writes context - trust for data write operations
     * @dev keccak256("trustnet:ctx:writes:v1")
     * @dev Used for gating write access (e.g., CRM updates, database modifications)
     */
    bytes32 public constant WRITES =
        0xa4d767d43a1aa6ce314b2c1df834966b812e18b0b99fcce9faf1591c0a6f2674;

    /**
     * @notice DeFi execution context - trust for DeFi protocol interactions
     * @dev keccak256("trustnet:ctx:defi-exec:v1")
     * @dev Used for gating DeFi operations (e.g., rebalancing, yield farming)
     */
    bytes32 public constant DEFI_EXEC =
        0x3372ad16565f09e46bfdcd8668e8ddb764599c1e6088d92a088c17ecb464ad65;

    /**
     * @notice Compute the context ID for a custom capability namespace
     * @param capability The capability name (e.g., "custom-capability")
     * @param version The version string (e.g., "v1", "v2")
     * @return The keccak256 hash of the formatted context string
     *
     * @dev Format: "trustnet:ctx:{capability}:{version}"
     *
     * Example:
     * computeContextId("api-access", "v1")
     * → keccak256("trustnet:ctx:api-access:v1")
     */
    function computeContextId(
        string memory capability,
        string memory version
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "trustnet:ctx:",
                capability,
                ":",
                version
            )
        );
    }

    /**
     * @notice Check if a context ID is one of the canonical contexts
     * @param contextId The context ID to check
     * @return True if the context ID matches a canonical context
     */
    function isCanonical(bytes32 contextId) internal pure returns (bool) {
        return
            contextId == GLOBAL ||
            contextId == PAYMENTS ||
            contextId == CODE_EXEC ||
            contextId == WRITES ||
            contextId == DEFI_EXEC;
    }

    /**
     * @notice Get a human-readable name for a canonical context
     * @param contextId The context ID to look up
     * @return The name of the context, or "unknown" if not canonical
     */
    function getContextName(bytes32 contextId)
        internal
        pure
        returns (string memory)
    {
        if (contextId == GLOBAL) return "global";
        if (contextId == PAYMENTS) return "payments";
        if (contextId == CODE_EXEC) return "code-exec";
        if (contextId == WRITES) return "writes";
        if (contextId == DEFI_EXEC) return "defi-exec";
        return "unknown";
    }
}
