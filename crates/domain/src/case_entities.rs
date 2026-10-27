use crate::valid_scope_time;

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
    pub value: String,
    pub first_seen: String,
    pub last_seen: String,
    pub verdict: ThreatVerdict,
    pub evidence: Vec<String>,
    pub confirmed: bool,
}

impl Ioc {
    pub fn valid(&self) -> bool {
        !self.value.trim().is_empty()
            && self.value.len() <= 2_000
            && valid_scope_time(&self.first_seen)
            && valid_scope_time(&self.last_seen)
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
    pub supporting_evidence: Vec<String>,
    pub refuting_evidence: Vec<String>,
}

impl Hypothesis {
    pub fn valid(&self) -> bool {
        !self.statement.trim().is_empty()
            && self.statement.len() <= 2_000
            && valid_evidence(&self.supporting_evidence)
            && self.refuting_evidence.iter().all(|hash| valid_hash(hash))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttackTechnique {
    pub id: String,
    pub evidence: Vec<String>,
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
    pub at: String,
    pub source: String,
    pub description: String,
    pub evidence_hash: String,
    pub record_index: Option<usize>,
    pub confirmed: bool,
}

impl CaseTimelineEvent {
    pub fn valid(&self) -> bool {
        valid_scope_time(&self.at)
            && !self.source.trim().is_empty()
            && self.source.len() <= 128
            && !self.description.trim().is_empty()
            && self.description.len() <= 2_000
            && valid_hash(&self.evidence_hash)
            && self.record_index.is_none_or(|index| index < 100_000)
    }
}

pub fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_evidence(hashes: &[String]) -> bool {
    !hashes.is_empty() && hashes.len() <= 32 && hashes.iter().all(|hash| valid_hash(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities_require_timestamps_evidence_and_attack_ids() {
        let hash = "a".repeat(64);
        let mut ioc = Ioc {
            kind: IocType::Ip,
            value: "203.0.113.8".into(),
            first_seen: "2026-10-23T12:00:00Z".into(),
            last_seen: "2026-10-23T13:00:00Z".into(),
            verdict: ThreatVerdict::Unknown,
            evidence: vec![hash.clone()],
            confirmed: false,
        };
        assert!(ioc.valid());
        ioc.last_seen = "2026-10-22T13:00:00Z".into();
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
                at: "2026-10-23T12:00:00Z".into(),
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
