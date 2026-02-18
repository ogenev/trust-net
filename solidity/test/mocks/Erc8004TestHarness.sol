// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @notice Minimal ERC-8004 identity registry harness for local chain smoke tests.
contract MockErc8004IdentityRegistry {
    mapping(uint256 => address) private agentWallets;

    function setAgentWallet(uint256 agentId, address agentWallet) external {
        agentWallets[agentId] = agentWallet;
    }

    function getAgentWallet(uint256 agentId) external view returns (address agentWallet) {
        return agentWallets[agentId];
    }
}

/// @notice Minimal ERC-8004 reputation harness for emitting events used by indexer ingestion.
contract MockErc8004Reputation {
    string internal constant CONTEXT_TAG = "trustnet:ctx:agent-collab:code-exec:v1";
    string internal constant TRUSTNET_TAG = "trustnet:v1";
    string internal constant TRUSTNET_ENDPOINT = "trustnet";

    event NewFeedback(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        int128 value,
        uint8 valueDecimals,
        string indexed indexedTag1,
        string tag1,
        string tag2,
        string endpoint,
        string feedbackURI,
        bytes32 feedbackHash
    );

    event ResponseAppended(
        uint256 indexed agentId,
        address indexed clientAddress,
        uint64 feedbackIndex,
        address indexed responder,
        string responseURI,
        bytes32 responseHash
    );

    function emitTrustnetFeedback(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        int128 value,
        uint8 valueDecimals,
        bytes32 feedbackHash
    ) external {
        emit NewFeedback(
            agentId,
            clientAddress,
            feedbackIndex,
            value,
            valueDecimals,
            CONTEXT_TAG,
            CONTEXT_TAG,
            TRUSTNET_TAG,
            TRUSTNET_ENDPOINT,
            "",
            feedbackHash
        );
    }

    function emitResponseAppendedSimple(
        uint256 agentId,
        address clientAddress,
        uint64 feedbackIndex,
        address responder,
        bytes32 responseHash
    ) external {
        emit ResponseAppended(
            agentId,
            clientAddress,
            feedbackIndex,
            responder,
            "",
            responseHash
        );
    }
}
