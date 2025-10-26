// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../../TrustGraph.sol";
import "../../TrustNetContexts.sol";

/**
 * @title TestHelpers
 * @notice Common utilities and helpers for TrustNet tests
 */
contract TestHelpers is Test {
    // ============ Test Data Generators ============

    /**
     * @notice Generate an array of unique addresses
     * @param count Number of addresses to generate
     * @param seed Starting seed for address generation
     */
    function generateAddresses(uint256 count, uint256 seed)
        public
        pure
        returns (address[] memory)
    {
        address[] memory addresses = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            addresses[i] = address(uint160(seed + i));
        }
        return addresses;
    }

    /**
     * @notice Generate trust levels in a pattern
     * @param count Number of levels to generate
     * @param pattern 0: sequential (-2 to 2), 1: all positive, 2: all negative, 3: alternating
     */
    function generateTrustLevels(uint256 count, uint8 pattern)
        public
        pure
        returns (int8[] memory)
    {
        int8[] memory levels = new int8[](count);

        for (uint256 i = 0; i < count; i++) {
            if (pattern == 0) {
                // Sequential pattern: cycles through -2, -1, 0, 1, 2
                levels[i] = int8(int256(i % 5) - 2);
            } else if (pattern == 1) {
                // All positive: cycles through 1, 2
                levels[i] = int8(int256((i % 2) + 1));
            } else if (pattern == 2) {
                // All negative: cycles through -1, -2
                levels[i] = int8(-1 - int256(i % 2));
            } else if (pattern == 3) {
                // Alternating: 2, -2, 2, -2...
                levels[i] = (i % 2 == 0) ? int8(2) : int8(-2);
            } else {
                // Default to 0
                levels[i] = 0;
            }
        }

        return levels;
    }

    /**
     * @notice Generate an array of context IDs
     * @param count Number of contexts to generate
     * @param canonical If true, cycles through canonical contexts; if false, generates custom
     */
    function generateContexts(uint256 count, bool canonical)
        public
        pure
        returns (bytes32[] memory)
    {
        bytes32[] memory contexts = new bytes32[](count);

        if (canonical) {
            bytes32[5] memory canonicalContexts = [
                TrustNetContexts.GLOBAL,
                TrustNetContexts.PAYMENTS,
                TrustNetContexts.CODE_EXEC,
                TrustNetContexts.WRITES,
                TrustNetContexts.DEFI_EXEC
            ];

            for (uint256 i = 0; i < count; i++) {
                contexts[i] = canonicalContexts[i % 5];
            }
        } else {
            for (uint256 i = 0; i < count; i++) {
                contexts[i] = keccak256(abi.encodePacked("custom:context:", i));
            }
        }

        return contexts;
    }

    // ============ Batch Operation Helpers ============

    /**
     * @notice Create valid batch rating data
     * @param size Size of the batch
     */
    function createValidBatchData(uint256 size)
        public
        pure
        returns (
            address[] memory targets,
            int8[] memory levels,
            bytes32[] memory contexts
        )
    {
        targets = generateAddresses(size, 1000);
        levels = generateTrustLevels(size, 0); // Sequential pattern
        contexts = generateContexts(size, true); // Canonical contexts
    }

    /**
     * @notice Create batch data with a zero address at specified index
     */
    function createBatchWithZeroAddress(uint256 size, uint256 zeroIndex)
        public
        pure
        returns (
            address[] memory targets,
            int8[] memory levels,
            bytes32[] memory contexts
        )
    {
        require(zeroIndex < size, "Zero index out of bounds");

        targets = generateAddresses(size, 1000);
        targets[zeroIndex] = address(0);
        levels = generateTrustLevels(size, 0);
        contexts = generateContexts(size, true);
    }

    /**
     * @notice Create batch data with an invalid trust level at specified index
     */
    function createBatchWithInvalidLevel(uint256 size, uint256 invalidIndex, int8 invalidLevel)
        public
        pure
        returns (
            address[] memory targets,
            int8[] memory levels,
            bytes32[] memory contexts
        )
    {
        require(invalidIndex < size, "Invalid index out of bounds");
        require(invalidLevel < -2 || invalidLevel > 2, "Level is actually valid");

        targets = generateAddresses(size, 1000);
        levels = generateTrustLevels(size, 0);
        levels[invalidIndex] = invalidLevel;
        contexts = generateContexts(size, true);
    }

    // ============ Event Assertion Helpers ============

    /**
     * @notice Assert that an EdgeRated event was emitted with specific parameters
     */
    function assertEdgeRatedEvent(
        address rater,
        address target,
        int8 level,
        bytes32 contextId
    ) public {
        vm.expectEmit(true, true, true, true);
        emit TrustGraph.EdgeRated(rater, target, level, contextId);
    }

    /**
     * @notice Assert multiple EdgeRated events in sequence
     */
    function assertBatchEdgeRatedEvents(
        address rater,
        address[] memory targets,
        int8[] memory levels,
        bytes32[] memory contexts
    ) public {
        require(
            targets.length == levels.length && levels.length == contexts.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < targets.length; i++) {
            assertEdgeRatedEvent(rater, targets[i], levels[i], contexts[i]);
        }
    }

    // ============ Gas Measurement Helpers ============

    /**
     * @notice Measure gas usage for a single function call
     * @return gasUsed The amount of gas used
     */
    function measureGas(function() external fn) public returns (uint256 gasUsed) {
        uint256 gasBefore = gasleft();
        fn();
        gasUsed = gasBefore - gasleft();
    }

    /**
     * @notice Compare gas usage between two operations
     * @return firstGas Gas used by first operation
     * @return secondGas Gas used by second operation
     * @return firstMoreEfficient True if first operation used less gas
     */
    function compareGasUsage(
        function() external fn1,
        function() external fn2
    )
        public
        returns (uint256 firstGas, uint256 secondGas, bool firstMoreEfficient)
    {
        firstGas = measureGas(fn1);
        secondGas = measureGas(fn2);
        firstMoreEfficient = firstGas < secondGas;
    }

    // ============ Validation Helpers ============

    /**
     * @notice Check if a trust level is valid (-2 to 2)
     */
    function isValidTrustLevel(int8 level) public pure returns (bool) {
        return level >= -2 && level <= 2;
    }

    /**
     * @notice Check if all elements in an array are unique
     */
    function areAllUnique(bytes32[] memory arr) public pure returns (bool) {
        for (uint256 i = 0; i < arr.length; i++) {
            for (uint256 j = i + 1; j < arr.length; j++) {
                if (arr[i] == arr[j]) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * @notice Check if an address array contains zero address
     */
    function containsZeroAddress(address[] memory addresses) public pure returns (bool) {
        for (uint256 i = 0; i < addresses.length; i++) {
            if (addresses[i] == address(0)) {
                return true;
            }
        }
        return false;
    }

    // ============ Statistical Helpers ============

    /**
     * @notice Calculate average trust level from an array
     */
    function calculateAverageTrust(int8[] memory levels) public pure returns (int256) {
        require(levels.length > 0, "Empty array");

        int256 sum = 0;
        for (uint256 i = 0; i < levels.length; i++) {
            sum += int256(levels[i]);
        }

        return sum / int256(levels.length);
    }

    /**
     * @notice Count occurrences of each trust level
     */
    function countTrustLevels(int8[] memory levels)
        public
        pure
        returns (uint256[5] memory counts)
    {
        // counts[0] = -2, counts[1] = -1, counts[2] = 0, counts[3] = 1, counts[4] = 2
        for (uint256 i = 0; i < levels.length; i++) {
            uint256 index = uint256(int256(levels[i]) + 2);
            counts[index]++;
        }
    }

    // ============ Time Helpers ============

    /**
     * @notice Advance block timestamp by specified seconds
     */
    function advanceTime(uint256 seconds_) public {
        vm.warp(block.timestamp + seconds_);
    }

    /**
     * @notice Advance block number by specified blocks
     */
    function advanceBlocks(uint256 blocks) public {
        vm.roll(block.number + blocks);
    }

    /**
     * @notice Advance both time and blocks proportionally
     */
    function advanceTimeAndBlocks(uint256 seconds_, uint256 blocks) public {
        advanceTime(seconds_);
        advanceBlocks(blocks);
    }

    // ============ Logging Helpers ============

    /**
     * @notice Log trust relationship details
     */
    function logTrustEdge(
        address rater,
        address target,
        int8 level,
        bytes32 contextId,
        string memory label
    ) public {
        console.log("=== Trust Edge: %s ===", label);
        console.log("Rater: %s", rater);
        console.log("Target: %s", target);
        console.log("Level: %d", uint256(int256(level)));
        console.log("Context: %s", TrustNetContexts.getContextName(contextId));
    }

    /**
     * @notice Log batch operation statistics
     */
    function logBatchStats(
        address[] memory targets,
        int8[] memory levels,
        uint256 gasUsed
    ) public {
        console.log("=== Batch Operation Stats ===");
        console.log("Batch size: %d", targets.length);
        console.log("Total gas: %d", gasUsed);
        console.log("Gas per operation: %d", gasUsed / targets.length);

        uint256[5] memory levelCounts = countTrustLevels(levels);
        console.log("Trust levels distribution:");
        for (int8 i = -2; i <= 2; i++) {
            console.log("  Level %d: %d occurrences", uint256(int256(i)), levelCounts[uint256(int256(i + 2))]);
        }
    }
}