use crate::{EvidenceHash, IocValue, UtcTimestamp};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IocType {
    Ip,
    Domain,
    Hash,
    User,
    Key,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreatVerdict {
    Unknown,
    Benign,
    Suspicious,
    Malicious,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ioc {
    pub kind: IocType,
    pub value: IocValue,
    pub first_seen: UtcTimestamp,
    pub last_seen: UtcTimestamp,
    pub verdict: ThreatVerdict,
    pub evidence: Vec<EvidenceHash>,
    pub confirmed: bool,
}

impl Ioc {
    pub fn valid(&self) -> bool {
        self.value.kind() == self.kind
            && self.first_seen <= self.last_seen
            && valid_evidence(&self.evidence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HypothesisState {
    Open,
    Confirmed,
    Dismissed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hypothesis {
    pub statement: String,
    pub state: HypothesisState,
    pub supporting_evidence: Vec<EvidenceHash>,
    pub refuting_evidence: Vec<EvidenceHash>,
}

impl Hypothesis {
    pub fn valid(&self) -> bool {
        !self.statement.trim().is_empty()
            && self.statement.len() <= 2_000
            && valid_evidence(&self.supporting_evidence)
            && self.refuting_evidence.len() <= 32
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttackTechnique {
    pub id: String,
    pub evidence: Vec<EvidenceHash>,
    pub confirmed: bool,
}

impl AttackTechnique {
    pub fn valid(&self) -> bool {
        let Some(number) = self.id.strip_prefix('T') else {
            return false;
        };
        let parts = number.split('.').collect::<Vec<_>>();
        let valid_id = match parts.as_slice() {
            [main] => main.len() == 4 && main.bytes().all(|byte| byte.is_ascii_digit()),
            [main, sub] => {
                main.len() == 4
                    && sub.len() == 3
                    && main.bytes().all(|byte| byte.is_ascii_digit())
                    && sub.bytes().all(|byte| byte.is_ascii_digit())
            }
            _ => false,
        };
        valid_id && valid_evidence(&self.evidence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseTimelineEvent {
    pub at: UtcTimestamp,
    pub source: String,
    pub description: String,
    pub evidence_hash: EvidenceHash,
    pub record_index: Option<usize>,
    pub confirmed: bool,
}

impl CaseTimelineEvent {
    pub fn valid(&self) -> bool {
        !self.source.trim().is_empty()
            && self.source.len() <= 128
            && !self.description.trim().is_empty()
            && self.description.len() <= 2_000
            && self.record_index.is_none_or(|index| index < 100_000)
    }
}

pub fn valid_hash(value: &str) -> bool {
    EvidenceHash::parse(value).is_ok()
}

fn valid_evidence(hashes: &[EvidenceHash]) -> bool {
    !hashes.is_empty() && hashes.len() <= 32
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn entities_require_timestamps_evidence_and_attack_ids() {
        let hash = EvidenceHash::parse(&"a".repeat(64)).unwrap();
        let mut ioc = Ioc {
            kind: IocType::Ip,
            value: IocValue::parse(IocType::Ip, "203.0.113.8").unwrap(),
            first_seen: UtcTimestamp::parse("2026-10-23T12:00:00Z").unwrap(),
            last_seen: UtcTimestamp::parse("2026-10-23T13:00:00Z").unwrap(),
            verdict: ThreatVerdict::Unknown,
            evidence: vec![hash.clone()],
            confirmed: false,
        };
        assert!(ioc.valid());
        ioc.last_seen = UtcTimestamp::parse("2026-10-22T13:00:00Z").unwrap();
        assert!(!ioc.valid());
        let hypothesis = Hypothesis {
            statement: "Account compromise".into(),
            state: HypothesisState::Open,
            supporting_evidence: vec![hash.clone()],
            refuting_evidence: vec![],
        };
        assert!(hypothesis.valid());
        assert!(
            AttackTechnique {
                id: "T1078.004".into(),
                evidence: vec![hash.clone()],
                confirmed: false
            }
            .valid()
        );
        assert!(
            !AttackTechnique {
                id: "T1078.00x".into(),
                evidence: vec![hash.clone()],
                confirmed: false
            }
            .valid()
        );
        assert!(
            CaseTimelineEvent {
                at: UtcTimestamp::parse("2026-10-23T12:00:00Z").unwrap(),
                source: "CloudTrail".into(),
                description: "AssumeRole".into(),
                evidence_hash: hash,
                record_index: Some(0),
                confirmed: false
            }
            .valid()
        );
    }
}
