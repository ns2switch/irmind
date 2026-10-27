use crate::{AppError, FixedAppError};
use irmind_domain::{
    AttackTechnique, CaseTimelineEvent, EvidenceHash, Hypothesis, HypothesisState, Ioc, IocType,
    IocValue, ThreatVerdict, UtcTimestamp,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "entity_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EntityDetails {
    Ioc {
        ioc_type: String,
        first_seen: String,
        last_seen: String,
        verdict: String,
    },
    Hypothesis {
        supporting_evidence: Vec<String>,
        refuting_evidence: Vec<String>,
    },
    Technique {
        technique_id: String,
    },
    Timeline {
        at: String,
        source: String,
        record_index: Option<usize>,
    },
}

impl EntityDetails {
    pub(crate) fn from_args(
        kind: super::FindingKind,
        args: &BTreeMap<String, String>,
    ) -> Result<Option<Self>, AppError> {
        let invalid = || AppError::Fixed(FixedAppError::PolicyInvalidFindingValue);
        let field = |name: &str| args.get(name).cloned().ok_or_else(invalid);
        let allowed = match kind {
            super::FindingKind::Ioc => &["ioc_type", "first_seen", "last_seen", "verdict"][..],
            super::FindingKind::Hypothesis => &["supporting_evidence", "refuting_evidence"][..],
            super::FindingKind::Technique => &["technique_id"][..],
            super::FindingKind::Timeline => &["at", "source", "record_index"][..],
            super::FindingKind::Impact | super::FindingKind::Recommendation => &[][..],
        };
        if args.keys().any(|key| {
            !matches!(key.as_str(), "kind" | "value" | "evidence_hash")
                && !allowed.contains(&key.as_str())
        }) {
            return Err(invalid());
        }
        if kind == super::FindingKind::Hypothesis
            && args.contains_key("refuting_evidence")
            && !args.contains_key("supporting_evidence")
        {
            return Err(invalid());
        }
        let details = match kind {
            super::FindingKind::Ioc if args.contains_key("ioc_type") => Some(Self::Ioc {
                ioc_type: field("ioc_type")?,
                first_seen: field("first_seen")?,
                last_seen: field("last_seen")?,
                verdict: field("verdict")?,
            }),
            super::FindingKind::Hypothesis if args.contains_key("supporting_evidence") => {
                Some(Self::Hypothesis {
                    supporting_evidence: split_hashes(&field("supporting_evidence")?),
                    refuting_evidence: split_hashes(
                        args.get("refuting_evidence").map_or("", String::as_str),
                    ),
                })
            }
            super::FindingKind::Technique if args.contains_key("technique_id") => {
                Some(Self::Technique {
                    technique_id: field("technique_id")?,
                })
            }
            super::FindingKind::Timeline => Some(Self::Timeline {
                at: field("at")?,
                source: field("source")?,
                record_index: args
                    .get("record_index")
                    .map(|value| value.parse().map_err(|_| invalid()))
                    .transpose()?,
            }),
            super::FindingKind::Ioc
            | super::FindingKind::Hypothesis
            | super::FindingKind::Technique => return Err(invalid()),
            super::FindingKind::Impact | super::FindingKind::Recommendation => None,
        };
        Ok(details)
    }

    pub(super) fn valid_for(
        &self,
        finding: &super::Finding,
        known_evidence: &BTreeSet<String>,
    ) -> bool {
        match (finding.kind, self) {
            (
                super::FindingKind::Ioc,
                Self::Ioc {
                    ioc_type,
                    first_seen,
                    last_seen,
                    verdict,
                },
            ) => valid_ioc(finding, ioc_type, first_seen, last_seen, verdict),
            (
                super::FindingKind::Hypothesis,
                Self::Hypothesis {
                    supporting_evidence,
                    refuting_evidence,
                },
            ) => valid_hypothesis(
                finding,
                supporting_evidence,
                refuting_evidence,
                known_evidence,
            ),
            (super::FindingKind::Technique, Self::Technique { technique_id }) => {
                let Ok(hash) = EvidenceHash::parse(&finding.evidence_hash) else {
                    return false;
                };
                finding.value == *technique_id
                    && AttackTechnique {
                        id: technique_id.clone(),
                        evidence: vec![hash],
                        confirmed: finding.confirmed,
                    }
                    .valid()
            }
            (
                super::FindingKind::Timeline,
                Self::Timeline {
                    at,
                    source,
                    record_index,
                },
            ) => {
                let (Ok(at), Ok(hash)) = (
                    UtcTimestamp::parse(at),
                    EvidenceHash::parse(&finding.evidence_hash),
                ) else {
                    return false;
                };
                CaseTimelineEvent {
                    at,
                    source: source.clone(),
                    description: finding.value.clone(),
                    evidence_hash: hash,
                    record_index: *record_index,
                    confirmed: finding.confirmed,
                }
                .valid()
            }
            _ => false,
        }
    }
}

fn valid_ioc(
    finding: &super::Finding,
    ioc_type: &str,
    first_seen: &str,
    last_seen: &str,
    verdict: &str,
) -> bool {
    let (Some(kind), Some(verdict), Ok(first_seen), Ok(last_seen), Ok(hash)) = (
        ioc_type_value(ioc_type),
        verdict_value(verdict),
        UtcTimestamp::parse(first_seen),
        UtcTimestamp::parse(last_seen),
        EvidenceHash::parse(&finding.evidence_hash),
    ) else {
        return false;
    };
    let Ok(value) = IocValue::parse(kind, &finding.value) else {
        return false;
    };
    Ioc {
        kind,
        value,
        first_seen,
        last_seen,
        verdict,
        evidence: vec![hash],
        confirmed: finding.confirmed,
    }
    .valid()
}

fn valid_hypothesis(
    finding: &super::Finding,
    supporting_evidence: &[String],
    refuting_evidence: &[String],
    known_evidence: &BTreeSet<String>,
) -> bool {
    let supporting = if supporting_evidence.is_empty() {
        vec![finding.evidence_hash.clone()]
    } else {
        supporting_evidence.to_vec()
    };
    let (Some(supporting_hashes), Some(refuting_hashes)) =
        (parse_hashes(&supporting), parse_hashes(refuting_evidence))
    else {
        return false;
    };
    supporting.contains(&finding.evidence_hash)
        && supporting
            .iter()
            .chain(refuting_evidence)
            .all(|hash| known_evidence.contains(hash))
        && Hypothesis {
            statement: finding.value.clone(),
            state: if finding.dismissed {
                HypothesisState::Dismissed
            } else if finding.confirmed {
                HypothesisState::Confirmed
            } else {
                HypothesisState::Open
            },
            supporting_evidence: supporting_hashes,
            refuting_evidence: refuting_hashes,
        }
        .valid()
}

fn parse_hashes(values: &[String]) -> Option<Vec<EvidenceHash>> {
    values
        .iter()
        .map(|value| EvidenceHash::parse(value).ok())
        .collect()
}

fn split_hashes(value: &str) -> Vec<String> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split(',').map(str::to_owned).collect()
    }
}

fn ioc_type_value(value: &str) -> Option<IocType> {
    match value {
        "ip" => Some(IocType::Ip),
        "domain" => Some(IocType::Domain),
        "hash" => Some(IocType::Hash),
        "user" => Some(IocType::User),
        "key" => Some(IocType::Key),
        _ => None,
    }
}

fn verdict_value(value: &str) -> Option<ThreatVerdict> {
    match value {
        "unknown" => Some(ThreatVerdict::Unknown),
        "benign" => Some(ThreatVerdict::Benign),
        "suspicious" => Some(ThreatVerdict::Suspicious),
        "malicious" => Some(ThreatVerdict::Malicious),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_model_ioc_requires_typed_fields() {
        let mut args = BTreeMap::from([
            ("kind".into(), "ioc".into()),
            ("value".into(), "203.0.113.8".into()),
            ("evidence_hash".into(), "a".repeat(64)),
        ]);
        assert!(EntityDetails::from_args(super::super::FindingKind::Ioc, &args).is_err());
        args.insert("ioc_type".into(), "ip".into());
        args.insert("first_seen".into(), "2026-10-23T12:00:00Z".into());
        args.insert("last_seen".into(), "2026-10-23T12:00:00Z".into());
        args.insert("verdict".into(), "unknown".into());
        assert!(matches!(
            EntityDetails::from_args(super::super::FindingKind::Ioc, &args),
            Ok(Some(EntityDetails::Ioc { .. }))
        ));
    }
}
