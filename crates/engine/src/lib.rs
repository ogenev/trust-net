//! TrustNet decision engine (v1.1 spec).
//!
//! Deterministic scoring:
//! - `lDEpos = max(lDE, 0)` (no-sign-flip guard)
//! - `path = lDEpos * lET`
//! - `scoreNumerator = 2*lDT + path`
//! - `score = clamp(scoreNumerator / 2, -2, +2)`
//! - Thresholds map score => ALLOW / ASK / DENY

use trustnet_core::types::{Level, PrincipalId};

/// A TrustNet decision outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allowed without operator approval.
    Allow,
    /// Requires operator approval.
    Ask,
    /// Blocked.
    Deny,
}

impl Decision {
    /// Canonical lowercase string form (matches spec examples).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
        }
    }
}

/// Per-context decision thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// Score required for ALLOW.
    pub allow: i8,
    /// Score required for ASK.
    pub ask: i8,
}

/// Threshold validation errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ThresholdError {
    /// `ask` must be <= `allow` to preserve monotonic mapping.
    #[error("invalid thresholds: ask ({ask}) must be <= allow ({allow})")]
    AskAboveAllow { ask: i8, allow: i8 },
}

impl Thresholds {
    /// Create thresholds with basic validation.
    pub fn new(allow: i8, ask: i8) -> Result<Self, ThresholdError> {
        if ask > allow {
            return Err(ThresholdError::AskAboveAllow { ask, allow });
        }
        Ok(Self { allow, ask })
    }
}

/// Candidate 2-hop path input for `(D -> E -> T)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The endorser principal.
    pub endorser: PrincipalId,
    /// Level for `D -> E`.
    pub level_de: Level,
    /// Level for `E -> T`.
    pub level_et: Level,
}

/// Evidence-aware candidate input for `(D -> E -> T)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateEvidence {
    /// The endorser principal.
    pub endorser: PrincipalId,
    /// Level for `D -> E`.
    pub level_de: Level,
    /// Level for `E -> T`.
    pub level_et: Level,
    /// Whether `E -> T` has evidence committed.
    pub et_has_evidence: bool,
}

/// Evidence gating policy for positive trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidencePolicy {
    /// Require evidence for positive `E -> T`.
    pub require_positive_et_evidence: bool,
    /// Require evidence for positive `D -> T`.
    pub require_positive_dt_evidence: bool,
}

/// Decision result with explainability fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionResult {
    /// Final decision.
    pub decision: Decision,
    /// Final score.
    pub score: i8,
    /// Selected endorser (if a 2-hop path improved score numerator).
    pub endorser: Option<PrincipalId>,
    /// Selected `D -> E` level (neutral if none).
    pub level_de: Level,
    /// Selected `E -> T` level (neutral if none).
    pub level_et: Level,
    /// Direct `D -> T` level (neutral if absent).
    pub level_dt: Level,
}

fn clamp_score_from_numerator(numerator: i16) -> i8 {
    (numerator / 2).clamp(-2, 2) as i8
}

fn score_numerator(level_dt: Level, level_de: Level, level_et: Level) -> i16 {
    let l_dt = i16::from(level_dt.value());
    let l_de_pos = i16::from(level_de.value().max(0));
    let l_et = i16::from(level_et.value());
    (2 * l_dt) + (l_de_pos * l_et)
}

/// Compute the TrustNet v1.1 spec score + decision.
///
/// - Missing edges must be represented as `Level::neutral()`.
pub fn decide(thresholds: Thresholds, level_dt: Level, candidates: &[Candidate]) -> DecisionResult {
    // Baseline path is "no endorser" => level_de=0, level_et=0, path=0.
    let mut best_numerator = score_numerator(level_dt, Level::neutral(), Level::neutral());
    let mut best_candidate: Option<Candidate> = None;

    // Pick best endorser E maximizing scoreNumerator, tie-break by PrincipalId bytes
    // (lexicographic ascending).
    for candidate in candidates {
        let candidate_numerator = score_numerator(level_dt, candidate.level_de, candidate.level_et);
        if candidate_numerator > best_numerator {
            best_numerator = candidate_numerator;
            best_candidate = Some(*candidate);
            continue;
        }
        if candidate_numerator == best_numerator {
            if let Some(current) = best_candidate {
                if candidate.endorser.as_bytes() < current.endorser.as_bytes() {
                    best_candidate = Some(*candidate);
                }
            }
        }
    }

    let score = clamp_score_from_numerator(best_numerator);

    let decision = if score >= thresholds.allow {
        Decision::Allow
    } else if score >= thresholds.ask {
        Decision::Ask
    } else {
        Decision::Deny
    };

    let (endorser, level_de, level_et) = best_candidate
        .map(|c| (Some(c.endorser), c.level_de, c.level_et))
        .unwrap_or((None, Level::neutral(), Level::neutral()));

    DecisionResult {
        decision,
        score,
        endorser,
        level_de,
        level_et,
        level_dt,
    }
}

/// Compute the TrustNet score + decision with evidence gating.
///
/// Evidence gating applies only to **positive** edges:
/// - If `require_positive_et_evidence` is true and `lET > 0` without evidence, treat `lET := 0`.
/// - If `require_positive_dt_evidence` is true and `lDT > 0` without evidence, treat `lDT := 0`.
pub fn decide_with_evidence(
    thresholds: Thresholds,
    evidence_policy: EvidencePolicy,
    level_dt: Level,
    dt_has_evidence: bool,
    candidates: &[CandidateEvidence],
) -> DecisionResult {
    let gated_level_dt =
        if evidence_policy.require_positive_dt_evidence && level_dt.value() > 0 && !dt_has_evidence
        {
            Level::neutral()
        } else {
            level_dt
        };

    let gated_candidates: Vec<Candidate> = candidates
        .iter()
        .map(|candidate| {
            let level_et = if evidence_policy.require_positive_et_evidence
                && candidate.level_et.value() > 0
                && !candidate.et_has_evidence
            {
                Level::neutral()
            } else {
                candidate.level_et
            };

            Candidate {
                endorser: candidate.endorser,
                level_de: candidate.level_de,
                level_et,
            }
        })
        .collect();

    decide(thresholds, gated_level_dt, &gated_candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thresholds() -> Thresholds {
        Thresholds::new(2, 1).unwrap()
    }

    #[test]
    fn direct_negative_is_not_hard_veto_in_v1_1() {
        let candidates = [Candidate {
            endorser: PrincipalId::from([0x01; 32]),
            level_de: Level::strong_positive(),
            level_et: Level::strong_positive(),
        }];

        let result = decide(thresholds(), Level::strong_negative(), &candidates);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.score, 0);
        assert_eq!(result.endorser, Some(PrincipalId::from([0x01; 32])));
    }

    #[test]
    fn no_sign_flip_when_decider_distrusts_endorser() {
        let candidates = [
            Candidate {
                endorser: PrincipalId::from([0x01; 32]),
                level_de: Level::strong_negative(),
                level_et: Level::strong_positive(),
            },
            Candidate {
                endorser: PrincipalId::from([0x02; 32]),
                level_de: Level::strong_positive(),
                level_et: Level::strong_negative(),
            },
        ];

        let result = decide(thresholds(), Level::neutral(), &candidates);
        assert_eq!(result.score, 0);
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.endorser.is_none());
    }

    #[test]
    fn tie_break_is_lexicographic_principal_id() {
        let candidates = [
            Candidate {
                endorser: PrincipalId::from([0x02; 32]),
                level_de: Level::strong_positive(),
                level_et: Level::positive(), // numerator = 2
            },
            Candidate {
                endorser: PrincipalId::from([0x01; 32]),
                level_de: Level::positive(),
                level_et: Level::strong_positive(), // numerator = 2
            },
        ];

        let result = decide(thresholds(), Level::neutral(), &candidates);
        assert_eq!(result.score, 1);
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.endorser, Some(PrincipalId::from([0x01; 32])));
    }

    #[test]
    fn evidence_gating_filters_et_without_evidence() {
        let policy = EvidencePolicy {
            require_positive_et_evidence: true,
            require_positive_dt_evidence: false,
        };

        let candidates = [CandidateEvidence {
            endorser: PrincipalId::from([0x01; 32]),
            level_de: Level::positive(),
            level_et: Level::positive(),
            et_has_evidence: false,
        }];

        let result =
            decide_with_evidence(thresholds(), policy, Level::neutral(), true, &candidates);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.score, 0);
        assert!(result.endorser.is_none());
    }

    #[test]
    fn evidence_gating_filters_dt_without_evidence() {
        let policy = EvidencePolicy {
            require_positive_et_evidence: false,
            require_positive_dt_evidence: true,
        };

        let result = decide_with_evidence(thresholds(), policy, Level::positive(), false, &[]);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.score, 0);

        let result = decide_with_evidence(thresholds(), policy, Level::positive(), true, &[]);
        assert_eq!(result.decision, Decision::Ask);
        assert_eq!(result.score, 1);
    }

    #[test]
    fn score_clamps_to_range() {
        let candidates = [Candidate {
            endorser: PrincipalId::from([0x01; 32]),
            level_de: Level::strong_positive(),
            level_et: Level::strong_positive(),
        }];

        // Numerator = 2*2 + 2*2 = 8 -> score=4 -> clamp to +2
        let result = decide(thresholds(), Level::strong_positive(), &candidates);
        assert_eq!(result.score, 2);
        assert_eq!(result.decision, Decision::Allow);
    }
}
