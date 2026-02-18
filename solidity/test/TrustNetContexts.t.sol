// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../TrustNetContexts.sol";

contract TrustNetContextsTest is Test {
    function test_CanonicalContextIds() public {
        assertEq(
            TrustNetContexts.AGENT_COLLAB_MESSAGING,
            keccak256(abi.encodePacked("trustnet:ctx:agent-collab:messaging:v1"))
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_FILES_READ,
            keccak256(abi.encodePacked("trustnet:ctx:agent-collab:files:read:v1"))
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_FILES_WRITE,
            keccak256(abi.encodePacked("trustnet:ctx:agent-collab:files:write:v1"))
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_CODE_EXEC,
            keccak256(abi.encodePacked("trustnet:ctx:agent-collab:code-exec:v1"))
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_DELEGATION,
            keccak256(abi.encodePacked("trustnet:ctx:agent-collab:delegation:v1"))
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_DATA_SHARE,
            keccak256(abi.encodePacked("trustnet:ctx:agent-collab:data-share:v1"))
        );
    }

    function test_CanonicalContextValues() public {
        assertEq(
            TrustNetContexts.AGENT_COLLAB_MESSAGING,
            0x04b03219e64c6472e5872ec762574f95cad7503f96392e00dae2bbbeaddd8158
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_FILES_READ,
            0xc1fec36e15bcd80ff1f0c7d817e26b6a558c5f027fb0e2af1fcef6755e6c04aa
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_FILES_WRITE,
            0x129283efa53ecd8ee862e64bbe6ca301c1f52167c643b55aafa8a668874769cf
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_CODE_EXEC,
            0x88329f80681e8980157f3ce652efd4fd18edf3c55202d5fb4f4da8a23e2d6971
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_DELEGATION,
            0xc6664c53c5aa763dbc7a4925c548e6600ce8d337698eb2faed7c9d348c3055d2
        );
        assertEq(
            TrustNetContexts.AGENT_COLLAB_DATA_SHARE,
            0xc217daac2c1b96669c55300178ca750feaf0eceffc89d9878cd3a5518d3ad33c
        );
    }

    function test_CanonicalContextsAreUnique() public {
        bytes32[] memory contexts = new bytes32[](6);
        contexts[0] = TrustNetContexts.AGENT_COLLAB_MESSAGING;
        contexts[1] = TrustNetContexts.AGENT_COLLAB_FILES_READ;
        contexts[2] = TrustNetContexts.AGENT_COLLAB_FILES_WRITE;
        contexts[3] = TrustNetContexts.AGENT_COLLAB_CODE_EXEC;
        contexts[4] = TrustNetContexts.AGENT_COLLAB_DELEGATION;
        contexts[5] = TrustNetContexts.AGENT_COLLAB_DATA_SHARE;

        for (uint256 i = 0; i < contexts.length; i++) {
            for (uint256 j = i + 1; j < contexts.length; j++) {
                assertTrue(contexts[i] != contexts[j], "canonical contexts must be unique");
            }
        }
    }

    function test_AliasSymbolsMapToCanonical() public {
        assertEq(TrustNetContexts.MESSAGING, TrustNetContexts.AGENT_COLLAB_MESSAGING);
        assertEq(TrustNetContexts.FILES_READ, TrustNetContexts.AGENT_COLLAB_FILES_READ);
        assertEq(TrustNetContexts.FILES_WRITE, TrustNetContexts.AGENT_COLLAB_FILES_WRITE);
        assertEq(TrustNetContexts.CODE_EXEC, TrustNetContexts.AGENT_COLLAB_CODE_EXEC);
        assertEq(TrustNetContexts.DELEGATION, TrustNetContexts.AGENT_COLLAB_DELEGATION);
        assertEq(TrustNetContexts.DATA_SHARE, TrustNetContexts.AGENT_COLLAB_DATA_SHARE);

        // Legacy symbol names map to canonical v0.7 IDs (never v0.6 IDs).
        assertEq(TrustNetContexts.GLOBAL, TrustNetContexts.AGENT_COLLAB_DATA_SHARE);
        assertEq(TrustNetContexts.PAYMENTS, TrustNetContexts.AGENT_COLLAB_DELEGATION);
        assertEq(TrustNetContexts.WRITES, TrustNetContexts.AGENT_COLLAB_FILES_WRITE);
    }

    function test_ComputeContextId_MatchesCanonical() public {
        assertEq(
            TrustNetContexts.computeContextId("agent-collab:messaging", "v1"),
            TrustNetContexts.AGENT_COLLAB_MESSAGING
        );
        assertEq(
            TrustNetContexts.computeContextId("agent-collab:files:read", "v1"),
            TrustNetContexts.AGENT_COLLAB_FILES_READ
        );
        assertEq(
            TrustNetContexts.computeContextId("agent-collab:files:write", "v1"),
            TrustNetContexts.AGENT_COLLAB_FILES_WRITE
        );
        assertEq(
            TrustNetContexts.computeContextId("agent-collab:code-exec", "v1"),
            TrustNetContexts.AGENT_COLLAB_CODE_EXEC
        );
        assertEq(
            TrustNetContexts.computeContextId("agent-collab:delegation", "v1"),
            TrustNetContexts.AGENT_COLLAB_DELEGATION
        );
        assertEq(
            TrustNetContexts.computeContextId("agent-collab:data-share", "v1"),
            TrustNetContexts.AGENT_COLLAB_DATA_SHARE
        );
    }

    function testFuzz_ComputeContextId(string memory capability, string memory version) public {
        bytes32 computed = TrustNetContexts.computeContextId(capability, version);
        bytes32 expected =
            keccak256(abi.encodePacked("trustnet:ctx:", capability, ":", version));
        assertEq(computed, expected);
    }

    function test_IsCanonical_TrueForCanonicalContexts() public {
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.AGENT_COLLAB_MESSAGING));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.AGENT_COLLAB_FILES_READ));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.AGENT_COLLAB_FILES_WRITE));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.AGENT_COLLAB_CODE_EXEC));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.AGENT_COLLAB_DELEGATION));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.AGENT_COLLAB_DATA_SHARE));
    }

    function test_IsCanonical_FalseForLegacyV06ContextIds() public {
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:global:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:payments:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:code-exec:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:writes:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:messaging:v1"))
            )
        );
    }

    function test_GetContextName_CanonicalContexts() public {
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.AGENT_COLLAB_MESSAGING),
            "agent-collab:messaging"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.AGENT_COLLAB_FILES_READ),
            "agent-collab:files:read"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.AGENT_COLLAB_FILES_WRITE),
            "agent-collab:files:write"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.AGENT_COLLAB_CODE_EXEC),
            "agent-collab:code-exec"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.AGENT_COLLAB_DELEGATION),
            "agent-collab:delegation"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.AGENT_COLLAB_DATA_SHARE),
            "agent-collab:data-share"
        );
    }

    function test_GetContextName_UnknownContext() public {
        assertEq(TrustNetContexts.getContextName(bytes32(0)), "unknown");
        assertEq(TrustNetContexts.getContextName(keccak256("random")), "unknown");
    }
}
