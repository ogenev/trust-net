//! Score quantization functions.
//!
//! Converts ERC-8004 scores (0-100) to trust levels (-2 to +2).

use crate::error::{CoreError, Result};
use crate::types::Level;

/// Quantize an ERC-8004 score (0-100) to a trust level (-2 to +2).
///
/// The mapping follows these buckets:
/// - 80-100 → +2 (Strong positive)
/// - 60-79  → +1 (Positive)
/// - 40-59  → 0  (Neutral)
/// - 20-39  → -1 (Negative)
/// - 0-19   → -2 (Strong negative)
///
/// # Arguments
///
/// * `score` - The ERC-8004 score, must be between 0 and 100.
///
/// # Returns
///
/// The quantized trust level.
///
/// # Errors
///
/// Returns `CoreError::InvalidScore` if the score is greater than 100.
///
/// # Example
///
/// ```
/// use trustnet_core::quantizer::quantize;
///
/// let level = quantize(85).unwrap();
/// assert_eq!(level.value(), 2);
///
/// let level = quantize(65).unwrap();
/// assert_eq!(level.value(), 1);
///
/// let level = quantize(45).unwrap();
/// assert_eq!(level.value(), 0);
///
/// let level = quantize(25).unwrap();
/// assert_eq!(level.value(), -1);
///
/// let level = quantize(10).unwrap();
/// assert_eq!(level.value(), -2);
/// ```
pub fn quantize(score: u8) -> Result<Level> {
    // Validate input
    if score > 100 {
        return Err(CoreError::InvalidScore(score));
    }

    // Map to trust level based on buckets
    let level_value = match score {
        80..=100 => 2,       // Strong positive
        60..=79 => 1,        // Positive
        40..=59 => 0,        // Neutral
        20..=39 => -1,       // Negative
        0..=19 => -2,        // Strong negative
        _ => unreachable!(), // Already validated above
    };

    // Create Level (safe because we know the value is in range)
    Ok(Level::new_unchecked(level_value))
}

/// Inverse quantization for testing and validation.
/// Returns the midpoint of the bucket for a given level.
pub fn inverse_quantize(level: Level) -> u8 {
    match level.value() {
        2 => 90,  // Midpoint of 80-100
        1 => 70,  // Midpoint of 60-79
        0 => 50,  // Midpoint of 40-59
        -1 => 30, // Midpoint of 20-39
        -2 => 10, // Midpoint of 0-19
        _ => unreachable!("Invalid level"),
    }
}

/// Get the score range for a given level.
pub fn level_score_range(level: Level) -> (u8, u8) {
    match level.value() {
        2 => (80, 100),
        1 => (60, 79),
        0 => (40, 59),
        -1 => (20, 39),
        -2 => (0, 19),
        _ => unreachable!("Invalid level"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantize_boundaries() {
        // Test exact boundaries
        assert_eq!(quantize(100).unwrap().value(), 2);
        assert_eq!(quantize(80).unwrap().value(), 2);
        assert_eq!(quantize(79).unwrap().value(), 1);
        assert_eq!(quantize(60).unwrap().value(), 1);
        assert_eq!(quantize(59).unwrap().value(), 0);
        assert_eq!(quantize(40).unwrap().value(), 0);
        assert_eq!(quantize(39).unwrap().value(), -1);
        assert_eq!(quantize(20).unwrap().value(), -1);
        assert_eq!(quantize(19).unwrap().value(), -2);
        assert_eq!(quantize(0).unwrap().value(), -2);
    }

    #[test]
    fn test_quantize_midpoints() {
        assert_eq!(quantize(90).unwrap().value(), 2);
        assert_eq!(quantize(70).unwrap().value(), 1);
        assert_eq!(quantize(50).unwrap().value(), 0);
        assert_eq!(quantize(30).unwrap().value(), -1);
        assert_eq!(quantize(10).unwrap().value(), -2);
    }

    #[test]
    fn test_quantize_invalid_score() {
        assert!(quantize(101).is_err());
        assert!(quantize(200).is_err());
        assert!(quantize(255).is_err());
    }

    #[test]
    fn test_inverse_quantize() {
        assert_eq!(inverse_quantize(Level::strong_positive()), 90);
        assert_eq!(inverse_quantize(Level::positive()), 70);
        assert_eq!(inverse_quantize(Level::neutral()), 50);
        assert_eq!(inverse_quantize(Level::negative()), 30);
        assert_eq!(inverse_quantize(Level::strong_negative()), 10);
    }

    #[test]
    fn test_level_score_range() {
        assert_eq!(level_score_range(Level::strong_positive()), (80, 100));
        assert_eq!(level_score_range(Level::positive()), (60, 79));
        assert_eq!(level_score_range(Level::neutral()), (40, 59));
        assert_eq!(level_score_range(Level::negative()), (20, 39));
        assert_eq!(level_score_range(Level::strong_negative()), (0, 19));
    }

    #[test]
    fn test_quantize_all_values() {
        // Test that all values 0-100 can be quantized
        for score in 0..=100 {
            let level = quantize(score).unwrap();
            assert!(level.value() >= -2 && level.value() <= 2);
        }
    }

    #[test]
    fn test_quantize_distribution() {
        // Verify the distribution of levels across all scores
        let mut counts = [0i32; 5]; // Indices 0-4 for levels -2 to +2

        for score in 0..=100 {
            let level = quantize(score).unwrap();
            counts[(level.value() + 2) as usize] += 1;
        }

        assert_eq!(counts[0], 20); // -2: scores 0-19 (20 values)
        assert_eq!(counts[1], 20); // -1: scores 20-39 (20 values)
        assert_eq!(counts[2], 20); // 0: scores 40-59 (20 values)
        assert_eq!(counts[3], 20); // +1: scores 60-79 (20 values)
        assert_eq!(counts[4], 21); // +2: scores 80-100 (21 values)
    }
}
