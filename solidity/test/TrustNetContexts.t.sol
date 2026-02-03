// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../TrustNetContexts.sol";

contract TrustNetContextsTest is Test {
    // ============ Canonical Context ID Tests ============

    function test_CanonicalContextIds() public {
        // Verify all canonical context IDs are correctly computed
        assertEq(
            TrustNetContexts.GLOBAL,
            keccak256(abi.encodePacked("trustnet:ctx:global:v1")),
            "GLOBAL context ID mismatch"
        );

        assertEq(
            TrustNetContexts.PAYMENTS,
            keccak256(abi.encodePacked("trustnet:ctx:payments:v1")),
            "PAYMENTS context ID mismatch"
        );

        assertEq(
            TrustNetContexts.CODE_EXEC,
            keccak256(abi.encodePacked("trustnet:ctx:code-exec:v1")),
            "CODE_EXEC context ID mismatch"
        );

        assertEq(
            TrustNetContexts.WRITES,
            keccak256(abi.encodePacked("trustnet:ctx:writes:v1")),
            "WRITES context ID mismatch"
        );

        assertEq(
            TrustNetContexts.MESSAGING,
            keccak256(abi.encodePacked("trustnet:ctx:messaging:v1")),
            "MESSAGING context ID mismatch"
        );
    }

    function test_CanonicalContextValues() public {
        // Verify the actual hex values match documentation
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
            TrustNetContexts.MESSAGING,
            0x9a61a0d65a04cee1ab884471f6d8f2b07d58922715c5a822f2a3caaf7e587841
        );
    }

    function test_CanonicalContextsAreUnique() public {
        // Ensure all canonical contexts have unique IDs
        bytes32[] memory contexts = new bytes32[](5);
        contexts[0] = TrustNetContexts.GLOBAL;
        contexts[1] = TrustNetContexts.PAYMENTS;
        contexts[2] = TrustNetContexts.CODE_EXEC;
        contexts[3] = TrustNetContexts.WRITES;
        contexts[4] = TrustNetContexts.MESSAGING;

        for (uint i = 0; i < contexts.length; i++) {
            for (uint j = i + 1; j < contexts.length; j++) {
                assertTrue(
                    contexts[i] != contexts[j],
                    "Canonical contexts must be unique"
                );
            }
        }
    }

    // ============ computeContextId Tests ============

    function test_ComputeContextId_BasicCapability() public {
        bytes32 computed = TrustNetContexts.computeContextId("test", "v1");
        bytes32 expected = keccak256(abi.encodePacked("trustnet:ctx:test:v1"));
        assertEq(computed, expected, "Context ID computation mismatch");
    }

    function test_ComputeContextId_EmptyCapability() public {
        bytes32 computed = TrustNetContexts.computeContextId("", "v1");
        bytes32 expected = keccak256(abi.encodePacked("trustnet:ctx::v1"));
        assertEq(computed, expected);
    }

    function test_ComputeContextId_EmptyVersion() public {
        bytes32 computed = TrustNetContexts.computeContextId("test", "");
        bytes32 expected = keccak256(abi.encodePacked("trustnet:ctx:test:"));
        assertEq(computed, expected);
    }

    function test_ComputeContextId_BothEmpty() public {
        bytes32 computed = TrustNetContexts.computeContextId("", "");
        bytes32 expected = keccak256(abi.encodePacked("trustnet:ctx::"));
        assertEq(computed, expected);
    }

    function test_ComputeContextId_SpecialCharacters() public {
        bytes32 computed = TrustNetContexts.computeContextId("test-capability_123", "v2.0-beta");
        bytes32 expected = keccak256(abi.encodePacked("trustnet:ctx:test-capability_123:v2.0-beta"));
        assertEq(computed, expected);
    }

    function test_ComputeContextId_MatchesCanonical() public {
        // Verify computeContextId produces same results as hardcoded canonical values
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
            TrustNetContexts.computeContextId("messaging", "v1"),
            TrustNetContexts.MESSAGING
        );
    }

    function testFuzz_ComputeContextId(string memory capability, string memory version) public {
        bytes32 computed = TrustNetContexts.computeContextId(capability, version);
        bytes32 expected = keccak256(
            abi.encodePacked("trustnet:ctx:", capability, ":", version)
        );
        assertEq(computed, expected);
    }

    // ============ isCanonical Tests ============

    function test_IsCanonical_TrueForCanonicalContexts() public {
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.GLOBAL));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.PAYMENTS));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.CODE_EXEC));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.WRITES));
        assertTrue(TrustNetContexts.isCanonical(TrustNetContexts.MESSAGING));
    }

    function test_IsCanonical_FalseForCustomContexts() public {
        assertFalse(TrustNetContexts.isCanonical(bytes32(0)));
        assertFalse(TrustNetContexts.isCanonical(keccak256("random")));
        assertFalse(TrustNetContexts.isCanonical(bytes32(uint256(1))));
        assertFalse(TrustNetContexts.isCanonical(TrustNetContexts.computeContextId("custom", "v1")));
    }

    function test_IsCanonical_FalseForSimilarContexts() public {
        // Test contexts that are similar but not exactly canonical
        assertFalse(TrustNetContexts.isCanonical(
            TrustNetContexts.computeContextId("GLOBAL", "v1") // uppercase
        ));
        assertFalse(TrustNetContexts.isCanonical(
            TrustNetContexts.computeContextId("global", "v2") // wrong version
        ));
        assertFalse(TrustNetContexts.isCanonical(
            TrustNetContexts.computeContextId("payment", "v1") // typo
        ));
    }

    function testFuzz_IsCanonical_OnlyTrueForCanonical(bytes32 contextId) public {
        bool isCanonical = TrustNetContexts.isCanonical(contextId);

        if (isCanonical) {
            // If it's canonical, it must be one of the 5 canonical contexts
            assertTrue(
                contextId == TrustNetContexts.GLOBAL ||
                contextId == TrustNetContexts.PAYMENTS ||
                contextId == TrustNetContexts.CODE_EXEC ||
                contextId == TrustNetContexts.WRITES ||
                contextId == TrustNetContexts.MESSAGING,
                "isCanonical returned true for non-canonical context"
            );
        }
    }

    // ============ getContextName Tests ============

    function test_GetContextName_CanonicalContexts() public {
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
            TrustNetContexts.getContextName(TrustNetContexts.MESSAGING),
            "messaging"
        );
    }

    function test_GetContextName_CustomContexts() public {
        assertEq(
            TrustNetContexts.getContextName(bytes32(0)),
            "unknown"
        );

        assertEq(
            TrustNetContexts.getContextName(keccak256("random")),
            "unknown"
        );

        assertEq(
            TrustNetContexts.getContextName(TrustNetContexts.computeContextId("my-context", "v1")),
            "unknown"
        );
    }

    function testFuzz_GetContextName(bytes32 contextId) public {
        string memory name = TrustNetContexts.getContextName(contextId);

        if (TrustNetContexts.isCanonical(contextId)) {
            // Canonical contexts should have specific names
            assertTrue(
                keccak256(bytes(name)) == keccak256("global") ||
                keccak256(bytes(name)) == keccak256("payments") ||
                keccak256(bytes(name)) == keccak256("code-exec") ||
                keccak256(bytes(name)) == keccak256("writes") ||
                keccak256(bytes(name)) == keccak256("messaging"),
                "Invalid name for canonical context"
            );
        } else {
            // Non-canonical contexts should return "unknown"
            assertEq(name, "unknown", "Non-canonical context should return unknown");
        }
    }

    // ============ Gas Usage Tests ============

    function test_GasUsage_ComputeContextId() public {
        uint256 gas = gasleft();
        TrustNetContexts.computeContextId("test", "v1");
        gas = gas - gasleft();
        console.log("Gas for computeContextId:", gas);
        assertLt(gas, 5000, "computeContextId uses too much gas");
    }

    function test_GasUsage_IsCanonical() public {
        uint256 gas = gasleft();
        TrustNetContexts.isCanonical(TrustNetContexts.GLOBAL);
        gas = gas - gasleft();
        console.log("Gas for isCanonical:", gas);
        assertLt(gas, 3000, "isCanonical uses too much gas");
    }

    function test_GasUsage_GetContextName() public {
        uint256 gas = gasleft();
        TrustNetContexts.getContextName(TrustNetContexts.GLOBAL);
        gas = gas - gasleft();
        console.log("Gas for getContextName:", gas);
        assertLt(gas, 5000, "getContextName uses too much gas");
    }

    // ============ Integration Tests ============

    function test_Integration_UseComputedContextIdInIsCanonical() public {
        // Compute a canonical context ID
        bytes32 computed = TrustNetContexts.computeContextId("global", "v1");

        // It should be recognized as canonical
        assertTrue(TrustNetContexts.isCanonical(computed));

        // And should return correct name
        assertEq(TrustNetContexts.getContextName(computed), "global");
    }

    function test_Integration_UseCustomContextIdAcrossFunctions() public {
        // Create a custom context
        string memory capability = "custom-capability";
        string memory version = "v2";
        bytes32 customContext = TrustNetContexts.computeContextId(capability, version);

        // Should not be canonical
        assertFalse(TrustNetContexts.isCanonical(customContext));

        // Should return "unknown" name
        assertEq(TrustNetContexts.getContextName(customContext), "unknown");

        // Should be deterministic
        assertEq(
            customContext,
            TrustNetContexts.computeContextId(capability, version),
            "computeContextId should be deterministic"
        );
    }

    // ============ Boundary Tests ============

    function test_Boundary_LongStringsInComputeContextId() public {
        string memory longCapability = "this-is-a-very-long-capability-name-that-tests-the-limits-of-string-processing";
        string memory longVersion = "v1.2.3-beta.4-rc.5-snapshot.6789";

        bytes32 computed = TrustNetContexts.computeContextId(longCapability, longVersion);
        bytes32 expected = keccak256(
            abi.encodePacked("trustnet:ctx:", longCapability, ":", longVersion)
        );

        assertEq(computed, expected);
    }

    function test_Boundary_MaxBytes32Values() public {
        bytes32 maxValue = bytes32(type(uint256).max);

        assertFalse(TrustNetContexts.isCanonical(maxValue));
        assertEq(TrustNetContexts.getContextName(maxValue), "unknown");
    }
}
