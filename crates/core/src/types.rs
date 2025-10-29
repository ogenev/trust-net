//! Core types for TrustNet.

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::constants::{MAX_LEVEL, MIN_LEVEL};
use crate::error::CoreError;

// Re-export Alloy types for convenience
pub use alloy_primitives::Address as EthAddress;
pub use alloy_primitives::B256 as Bytes32;

/// Trust level ranging from -2 to +2.
///
/// This type enforces validation during both construction and deserialization
/// to prevent invalid values from entering the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Level(i8);

impl Level {
    /// Create a new Level, validating the range.
    pub fn new(value: i8) -> Result<Self, CoreError> {
        if !(MIN_LEVEL..=MAX_LEVEL).contains(&value) {
            return Err(CoreError::InvalidLevel(value));
        }
        Ok(Level(value))
    }

    /// Create a Level without validation (use with caution).
    pub const fn new_unchecked(value: i8) -> Self {
        Level(value)
    }

    /// Get the raw value.
    pub const fn value(&self) -> i8 {
        self.0
    }

    /// Convert to SMM value (level + 2) for storage.
    /// Maps [-2, +2] to [0, 4].
    pub const fn to_smm_value(&self) -> u8 {
        (self.0 + 2) as u8
    }

    /// Create from SMM value (0-4).
    pub fn from_smm_value(value: u8) -> Result<Self, CoreError> {
        if value > 4 {
            return Err(CoreError::InvalidSmmValue(value));
        }
        Ok(Level((value as i8) - 2))
    }

    /// Strong negative rating.
    pub const fn strong_negative() -> Self {
        Level(-2)
    }

    /// Negative rating.
    pub const fn negative() -> Self {
        Level(-1)
    }

    /// Neutral rating.
    pub const fn neutral() -> Self {
        Level(0)
    }

    /// Positive rating.
    pub const fn positive() -> Self {
        Level(1)
    }

    /// Strong positive rating.
    pub const fn strong_positive() -> Self {
        Level(2)
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:+}", self.0)
    }
}

// Custom serialization to ensure validation during deserialization
impl Serialize for Level {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as the underlying i8 value
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize as i8, then validate through Level::new
        let value = i8::deserialize(deserializer)?;
        Level::new(value).map_err(|e| serde::de::Error::custom(format!("{}", e)))
    }
}

/// Context identifier (32 bytes).
/// Wrapper around B256 to provide domain-specific type safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContextId(pub B256);

impl ContextId {
    /// Create a new ContextId from a 32-byte array.
    pub const fn new(bytes: B256) -> Self {
        ContextId(bytes)
    }

    /// Get the inner B256.
    pub const fn inner(&self) -> &B256 {
        &self.0
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<B256> for ContextId {
    fn from(b: B256) -> Self {
        ContextId(b)
    }
}

impl From<[u8; 32]> for ContextId {
    fn from(bytes: [u8; 32]) -> Self {
        ContextId(B256::from(bytes))
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Agent identity key (hash of chainId || registry || agentId).
/// Wrapper around B256 to provide domain-specific type safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentKey(pub B256);

impl AgentKey {
    /// Create a new AgentKey from a 32-byte array.
    pub const fn new(bytes: B256) -> Self {
        AgentKey(bytes)
    }

    /// Get the inner B256.
    pub const fn inner(&self) -> &B256 {
        &self.0
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<B256> for AgentKey {
    fn from(b: B256) -> Self {
        AgentKey(b)
    }
}

impl From<[u8; 32]> for AgentKey {
    fn from(bytes: [u8; 32]) -> Self {
        AgentKey(B256::from(bytes))
    }
}

impl fmt::Display for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An edge in the trust graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edge {
    /// The rater (decider) address.
    pub rater: Address,
    /// The target address or agent key.
    pub target: Address,
    /// The context in which this rating applies.
    pub context: ContextId,
    /// The trust level.
    pub level: Level,
}

impl Edge {
    /// Create a new edge.
    pub fn new(rater: Address, target: Address, context: ContextId, level: Level) -> Self {
        Edge {
            rater,
            target,
            context,
            level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    #[test]
    fn test_address_creation() {
        let addr = Address::from(hex!("1234567890abcdef1234567890abcdef12345678"));
        assert_eq!(
            addr.as_slice(),
            &hex!("1234567890abcdef1234567890abcdef12345678")
        );
        assert!(!addr.is_zero());

        let zero = Address::ZERO;
        assert!(zero.is_zero());
    }

    #[test]
    fn test_address_from_str() {
        let addr_str = "0x1234567890abcdef1234567890abcdef12345678";
        let addr: Address = addr_str.parse().unwrap();
        // Alloy uses EIP-55 checksumming, so output may have mixed case
        assert_eq!(addr.to_string().to_lowercase(), addr_str.to_lowercase());

        // Alloy addresses are checksummed, but parsing handles both
        let addr2: Address = "1234567890abcdef1234567890abcdef12345678".parse().unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_level_creation() {
        assert!(Level::new(-3).is_err());
        assert!(Level::new(3).is_err());

        for i in -2..=2 {
            let level = Level::new(i).unwrap();
            assert_eq!(level.value(), i);
        }
    }

    #[test]
    fn test_level_smm_conversion() {
        assert_eq!(Level::strong_negative().to_smm_value(), 0);
        assert_eq!(Level::negative().to_smm_value(), 1);
        assert_eq!(Level::neutral().to_smm_value(), 2);
        assert_eq!(Level::positive().to_smm_value(), 3);
        assert_eq!(Level::strong_positive().to_smm_value(), 4);

        for i in 0..=4 {
            let level = Level::from_smm_value(i).unwrap();
            assert_eq!(level.to_smm_value(), i);
        }

        assert!(Level::from_smm_value(5).is_err());
    }

    #[test]
    fn test_level_display() {
        assert_eq!(Level::strong_negative().to_string(), "-2");
        assert_eq!(Level::negative().to_string(), "-1");
        assert_eq!(Level::neutral().to_string(), "+0");
        assert_eq!(Level::positive().to_string(), "+1");
        assert_eq!(Level::strong_positive().to_string(), "+2");
    }

    #[test]
    fn test_level_serialization() {
        // Test valid levels serialize correctly
        for i in -2..=2 {
            let level = Level::new(i).unwrap();
            let serialized = serde_json::to_string(&level).unwrap();
            assert_eq!(serialized, i.to_string());
        }
    }

    #[test]
    fn test_level_deserialization_valid() {
        // Test valid levels deserialize correctly
        for i in -2..=2 {
            let json = i.to_string();
            let level: Level = serde_json::from_str(&json).unwrap();
            assert_eq!(level.value(), i);
        }
    }

    #[test]
    fn test_level_deserialization_invalid() {
        // Test that invalid levels fail to deserialize
        let invalid_values = [-128, -127, -3, 3, 4, 127];

        for invalid in invalid_values {
            let json = invalid.to_string();
            let result: Result<Level, _> = serde_json::from_str(&json);
            assert!(
                result.is_err(),
                "Expected deserialization to fail for value {}, but it succeeded",
                invalid
            );

            // Verify the error message is meaningful
            let err = result.unwrap_err();
            let err_msg = err.to_string();
            assert!(
                err_msg.contains("Invalid trust level") || err_msg.contains("must be between"),
                "Error message should mention invalid level: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_level_roundtrip() {
        // Test that valid levels can roundtrip through serialization
        for i in -2..=2 {
            let original = Level::new(i).unwrap();
            let serialized = serde_json::to_string(&original).unwrap();
            let deserialized: Level = serde_json::from_str(&serialized).unwrap();
            assert_eq!(original, deserialized);
        }
    }

    #[test]
    fn test_level_in_struct() {
        // Test that Level validation works when embedded in other structs
        #[derive(Serialize, Deserialize)]
        struct TestStruct {
            level: Level,
            name: String,
        }

        // Valid case
        let valid_json = r#"{"level": 2, "name": "test"}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(valid_json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().level.value(), 2);

        // Invalid case
        let invalid_json = r#"{"level": 127, "name": "test"}"#;
        let result: Result<TestStruct, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err(), "Should reject invalid level in struct");
    }

    #[test]
    fn test_level_security_vulnerability_fixed() {
        // This test demonstrates the security vulnerability is fixed.
        // Previously, with derived Deserialize, this would succeed and create
        // Level(127), which would:
        // 1. Overflow to_smm_value() -> (127 + 2) as u8 = 129 (wraps to invalid value)
        // 2. Panic on unreachable branches in quantizer
        // 3. Bypass all invariants

        // Attempt to deserialize an obviously invalid value
        let malicious_json = "127";
        let result: Result<Level, _> = serde_json::from_str(malicious_json);

        // Should FAIL - this is the security fix
        assert!(result.is_err(), "SECURITY: Must reject out-of-range Level");

        // Try edge case just outside valid range
        let edge_case_json = "3";
        let result: Result<Level, _> = serde_json::from_str(edge_case_json);
        assert!(result.is_err(), "SECURITY: Must reject Level=3");

        let edge_case_json = "-3";
        let result: Result<Level, _> = serde_json::from_str(edge_case_json);
        assert!(result.is_err(), "SECURITY: Must reject Level=-3");
    }

    #[test]
    fn test_edge_with_invalid_level_rejected() {
        // Test that Edge deserialization also validates Level
        let invalid_edge_json = r#"{
            "rater": "0x1111111111111111111111111111111111111111",
            "target": "0x2222222222222222222222222222222222222222",
            "context": "0x430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b",
            "level": 100
        }"#;

        let result: Result<Edge, _> = serde_json::from_str(invalid_edge_json);
        assert!(
            result.is_err(),
            "Edge deserialization should reject invalid Level values"
        );
    }

    #[test]
    fn test_context_id() {
        let bytes = hex!("430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b");
        let ctx = ContextId::from(bytes);
        assert_eq!(ctx.as_bytes(), &bytes);
    }

    #[test]
    fn test_context_id_display() {
        let bytes = hex!("430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b");
        let ctx = ContextId::from(bytes);
        let display = format!("{}", ctx);
        assert!(display.starts_with("0x430faa"));
    }

    #[test]
    fn test_agent_key() {
        let bytes = hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let key = AgentKey::from(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_edge_creation() {
        let rater = Address::from(hex!("1111111111111111111111111111111111111111"));
        let target = Address::from(hex!("2222222222222222222222222222222222222222"));
        let context = ContextId::from(hex!(
            "430faa5635b6f437d8b5a2d66333fe4fbcf75602232a76b67e94fd4a3275169b"
        ));
        let level = Level::positive();

        let edge = Edge::new(rater, target, context, level);
        assert_eq!(edge.rater, rater);
        assert_eq!(edge.target, target);
        assert_eq!(edge.context, context);
        assert_eq!(edge.level, level);
    }
}
