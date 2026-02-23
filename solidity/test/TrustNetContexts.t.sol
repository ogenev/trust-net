// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";
import {TrustNetContexts} from "../TrustNetContexts.sol";

contract TrustNetContextsTest is Test {
    function test_CanonicalContextIds() public pure {
        assertEq(
            TrustNetContexts.GLOBAL,
            keccak256(abi.encodePacked("trustnet:ctx:global:v1"))
        );
        assertEq(
            TrustNetContexts.PAYMENTS,
            keccak256(abi.encodePacked("trustnet:ctx:payments:v1"))
        );
        assertEq(
            TrustNetContexts.CODE_EXEC,
            keccak256(abi.encodePacked("trustnet:ctx:code-exec:v1"))
        );
        assertEq(
            TrustNetContexts.WRITES,
            keccak256(abi.encodePacked("trustnet:ctx:writes:v1"))
        );
        assertEq(
            TrustNetContexts.DEFI_EXEC,
            keccak256(abi.encodePacked("trustnet:ctx:defi-exec:v1"))
        );
    }

    function test_CanonicalContextValues() public pure {
        assertEq(
            TrustNetContexts.GLOBAL,
            0x430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b
        );
        assertEq(
            TrustNetContexts.PAYMENTS,
            0x195c31d552212fd148934033b94b89c00b603e2b73e757a2b7684b4cc9602147
        );
        assertEq(
            TrustNetContexts.CODE_EXEC,
            0x5efe84ba1b51e4f09cf7666eca4d0685fcccf1ee1f5c051bfd1b40c537b4565b
        );
        assertEq(
            TrustNetContexts.WRITES,
            0xa4d767d43a1aa6ce314b2c1df834966b812e18b0b99fcce9faf1591c0a6f2674
        );
        assertEq(
            TrustNetContexts.DEFI_EXEC,
            0x3372ad16565f09e46bfdcd8668e8ddb764599c1e6088d92a088c17ecb464ad65
        );
    }

    function test_CanonicalContextsAreUnique() public pure {
        bytes32[] memory contexts = new bytes32[](5);
        contexts[0] = TrustNetContexts.GLOBAL;
        contexts[1] = TrustNetContexts.PAYMENTS;
        contexts[2] = TrustNetContexts.CODE_EXEC;
        contexts[3] = TrustNetContexts.WRITES;
        contexts[4] = TrustNetContexts.DEFI_EXEC;

        for (uint256 i = 0; i < contexts.length; i++) {
            for (uint256 j = i + 1; j < contexts.length; j++) {
                assertTrue(contexts[i] != contexts[j], "canonical contexts must be unique");
            }
        }
    }

    function test_ComputeContextId_MatchesCanonical() public pure {
        assertEq(
            TrustNetContexts.computeContextId("global", "v1"),
            TrustNetContexts.GLOBAL
        );
        assertEq(
            TrustNetContexts.computeContextId("payments", "v1"),
            TrustNetContexts.PAYMENTS
        );
        assertEq(
            TrustNetContexts.computeContextId("code-exec", "v1"),
            TrustNetContexts.CODE_EXEC
        );
        assertEq(
            TrustNetContexts.computeContextId("writes", "v1"),
            TrustNetContexts.WRITES
        );
        assertEq(
            TrustNetContexts.computeContextId("defi-exec", "v1"),
            TrustNetContexts.DEFI_EXEC
        );
    }

    function testFuzz_ComputeContextId(string memory capability, string memory version) public pure {
        bytes32 computed = TrustNetContexts.computeContextId(capability, version);
        bytes32 expected =
            keccak256(abi.encodePacked("trustnet:ctx:", capability, ":", version));
        assertEq(computed, expected);
    }

    function test_IsCanonical_TrueForCanonicalContexts() public pure {
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.GLOBAL));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.PAYMENTS));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.CODE_EXEC));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.WRITES));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.DEFI_EXEC));
    }

    function test_IsCanonical_FalseForLegacyAgentCollabContextIds() public pure {
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:agent-collab:messaging:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:agent-collab:files:read:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:agent-collab:files:write:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:agent-collab:code-exec:v1"))
            )
        );
        assertFalse(
            TrustNetContexts.isCanonical(
                keccak256(abi.encodePacked("trustnet:ctx:agent-collab:data-share:v1"))
            )
        );
    }

    function test_GetContextName_CanonicalContexts() public pure {
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.GLOBAL),
            "global"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.PAYMENTS),
            "payments"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.CODE_EXEC),
            "code-exec"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.WRITES),
            "writes"
        );
        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.DEFI_EXEC),
            "defi-exec"
        );
    }

    function test_GetContextName_UnknownContext() public pure {
        assertEq(TrustNetContexts.getContextName(bytes32(0)), "unknown");
        assertEq(TrustNetContexts.getContextName(keccak256("random")), "unknown");
    }
}
