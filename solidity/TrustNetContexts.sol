// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title TrustNetContexts
 * @notice Canonical context identifiers for TrustNet capability namespaces
 * @dev These context IDs are used to scope trust ratings to specific capabilities,
 *      preventing privilege escalation across different capability domains.
 *
 * Spec: docs/TrustNet_Spec_v0.7.md §7
 */
library TrustNetContexts {
    /**
     * @notice Agent-collab messaging context.
     * @dev keccak256("trustnet:ctx:agent-collab:messaging:v1")
     */
    bytes32 public constant AGENT_COLLAB_MESSAGING =
        0x04b03219e64c6472e5872ec762574f95cad7503f96392e00dae2bbbeaddd8158;

    /**
     * @notice Agent-collab files-read context.
     * @dev keccak256("trustnet:ctx:agent-collab:files:read:v1")
     */
    bytes32 public constant AGENT_COLLAB_FILES_READ =
        0xc1fec36e15bcd80ff1f0c7d817e26b6a558c5f027fb0e2af1fcef6755e6c04aa;

    /**
     * @notice Agent-collab files-write context.
     * @dev keccak256("trustnet:ctx:agent-collab:files:write:v1")
     */
    bytes32 public constant AGENT_COLLAB_FILES_WRITE =
        0x129283efa53ecd8ee862e64bbe6ca301c1f52167c643b55aafa8a668874769cf;

    /**
     * @notice Agent-collab code-exec context.
     * @dev keccak256("trustnet:ctx:agent-collab:code-exec:v1")
     */
    bytes32 public constant AGENT_COLLAB_CODE_EXEC =
        0x88329f80681e8980157f3ce652efd4fd18edf3c55202d5fb4f4da8a23e2d6971;

    /**
     * @notice Agent-collab delegation context.
     * @dev keccak256("trustnet:ctx:agent-collab:delegation:v1")
     */
    bytes32 public constant AGENT_COLLAB_DELEGATION =
        0xc6664c53c5aa763dbc7a4925c548e6600ce8d337698eb2faed7c9d348c3055d2;

    /**
     * @notice Agent-collab data-share context.
     * @dev keccak256("trustnet:ctx:agent-collab:data-share:v1")
     */
    bytes32 public constant AGENT_COLLAB_DATA_SHARE =
        0xc217daac2c1b96669c55300178ca750feaf0eceffc89d9878cd3a5518d3ad33c;

    // Convenience aliases used by existing contracts/tests.
    bytes32 public constant MESSAGING = AGENT_COLLAB_MESSAGING;
    bytes32 public constant FILES_READ = AGENT_COLLAB_FILES_READ;
    bytes32 public constant FILES_WRITE = AGENT_COLLAB_FILES_WRITE;
    bytes32 public constant CODE_EXEC = AGENT_COLLAB_CODE_EXEC;
    bytes32 public constant DELEGATION = AGENT_COLLAB_DELEGATION;
    bytes32 public constant DATA_SHARE = AGENT_COLLAB_DATA_SHARE;
    bytes32 public constant GLOBAL = AGENT_COLLAB_DATA_SHARE;
    bytes32 public constant PAYMENTS = AGENT_COLLAB_DELEGATION;
    bytes32 public constant WRITES = AGENT_COLLAB_FILES_WRITE;

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
            contextId == AGENT_COLLAB_MESSAGING ||
            contextId == AGENT_COLLAB_FILES_READ ||
            contextId == AGENT_COLLAB_FILES_WRITE ||
            contextId == AGENT_COLLAB_CODE_EXEC ||
            contextId == AGENT_COLLAB_DELEGATION ||
            contextId == AGENT_COLLAB_DATA_SHARE;
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
        if (contextId == AGENT_COLLAB_MESSAGING) return "agent-collab:messaging";
        if (contextId == AGENT_COLLAB_FILES_READ) return "agent-collab:files:read";
        if (contextId == AGENT_COLLAB_FILES_WRITE) return "agent-collab:files:write";
        if (contextId == AGENT_COLLAB_CODE_EXEC) return "agent-collab:code-exec";
        if (contextId == AGENT_COLLAB_DELEGATION) return "agent-collab:delegation";
        if (contextId == AGENT_COLLAB_DATA_SHARE) return "agent-collab:data-share";
        return "unknown";
    }
}
