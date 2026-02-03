//! TrustNet decision engine (Spec v0.4).
//!
//! This crate implements the deterministic trust-to-act rule from the spec:
//! - Hard veto: `lDT == -2` => DENY
//! - Endorser path contributes only for positive edges: `min(lDE, lET)` where `lDE>0 && lET>0`
//! - Direct trust can override upwards: if `lDT > 0`, `score = max(base, lDT)`
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
    /// Selected endorser (if a positive 2-hop path was used).
    pub endorser: Option<PrincipalId>,
    /// Selected `D -> E` level (neutral if none).
    pub level_de: Level,
    /// Selected `E -> T` level (neutral if none).
    pub level_et: Level,
    /// Direct `D -> T` level (neutral if absent).
    pub level_dt: Level,
}

/// Compute the TrustNet v0.4 score + decision.
///
/// - Missing edges must be represented as `Level::neutral()`.
/// - Candidates are filtered to those with `level_de > 0 && level_et > 0`.
pub fn decide(thresholds: Thresholds, level_dt: Level, candidates: &[Candidate]) -> DecisionResult {
    // Hard veto.
    if level_dt.value() == -2 {
        return DecisionResult {
            decision: Decision::Deny,
            score: -2,
            endorser: None,
            level_de: Level::neutral(),
            level_et: Level::neutral(),
            level_dt,
        };
    }

    // Pick best endorser E maximizing min(lDE, lET), tie-break by PrincipalId bytes (lexicographic).
    let mut best: Option<(i8, Candidate)> = None;
    for candidate in candidates {
        if candidate.level_de.value() <= 0 || candidate.level_et.value() <= 0 {
            continue;
        }
        let score = candidate.level_de.value().min(candidate.level_et.value());
        best = match best {
            None => Some((score, *candidate)),
            Some((best_score, best_candidate)) => {
                if score > best_score {
                    Some((score, *candidate))
                } else if score < best_score {
                    Some((best_score, best_candidate))
                } else if candidate.endorser.as_bytes() < best_candidate.endorser.as_bytes() {
                    Some((score, *candidate))
                } else {
                    Some((best_score, best_candidate))
                }
            }
        };
    }

    let base = best.map(|(score, _)| score).unwrap_or(0);

    let score = if level_dt.value() > 0 {
        base.max(level_dt.value())
    } else {
        base
    };

    let decision = if score >= thresholds.allow {
        Decision::Allow
    } else if score >= thresholds.ask {
        Decision::Ask
    } else {
        Decision::Deny
    };

    let (endorser, level_de, level_et) = best
        .map(|(_, c)| (Some(c.endorser), c.level_de, c.level_et))
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
/// - Hard veto (`lDT == -2`) still applies regardless of evidence.
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
    fn veto_always_denies() {
        let candidates = [Candidate {
            endorser: PrincipalId::from([0x01; 32]),
            level_de: Level::strong_positive(),
            level_et: Level::strong_positive(),
        }];

        let result = decide(thresholds(), Level::strong_negative(), &candidates);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.score, -2);
        assert!(result.endorser.is_none());
    }

    #[test]
    fn endorsements_never_propagate_negative() {
        let candidates = [
            Candidate {
                endorser: PrincipalId::from([0x01; 32]),
                level_de: Level::negative(),
                level_et: Level::strong_positive(),
            },
            Candidate {
                endorser: PrincipalId::from([0x02; 32]),
                level_de: Level::strong_positive(),
                level_et: Level::negative(),
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
                level_et: Level::positive(), // min = 1
            },
            Candidate {
                endorser: PrincipalId::from([0x01; 32]),
                level_de: Level::positive(),
                level_et: Level::strong_positive(), // min = 1
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
}
