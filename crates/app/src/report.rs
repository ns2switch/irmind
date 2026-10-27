use crate::*;
mod entity_details;
mod render;
pub use entity_details::EntityDetails;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub kind: FindingKind,
    pub value: String,
    pub evidence_hash: String,
    pub confirmed: bool,
    #[serde(default)]
    pub dismissed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<EntityDetails>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FindingDismissal {
    id: String,
    reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Ioc,
    Hypothesis,
    Technique,
    Timeline,
    Impact,
    Recommendation,
}

impl FindingKind {
    pub fn parse(value: &str) -> Result<Self, AppError> {
        match value {
            "ioc" => Ok(Self::Ioc),
            "hypothesis" => Ok(Self::Hypothesis),
            "technique" => Ok(Self::Technique),
            "timeline" => Ok(Self::Timeline),
            "impact" => Ok(Self::Impact),
            "recommendation" => Ok(Self::Recommendation),
            _ => Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidFindingType,
            )),
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::Ioc => "IOCs",
            Self::Hypothesis => "Hypotheses",
            Self::Technique => "ATT&CK techniques",
            Self::Timeline => "Timeline",
            Self::Impact => "Impact",
            Self::Recommendation => "Recommendations",
        }
    }
}

impl Finding {
    fn valid_for(&self, known_evidence: &std::collections::BTreeSet<String>) -> bool {
        known_evidence.contains(&self.evidence_hash)
            && self
                .details
                .as_ref()
                .is_none_or(|details| details.valid_for(self, known_evidence))
            && (self.kind != FindingKind::Timeline || self.details.is_some())
    }
}

impl Engine<'_> {
    pub fn add_finding(
        &self,
        id: &CaseId,
        kind: FindingKind,
        value: &str,
        evidence_hash: &str,
    ) -> Result<String, AppError> {
        self.require_attended_analyst("add case finding")?;
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        self.propose_finding_unlocked(
            id,
            kind,
            value,
            evidence_hash,
            None,
            crate::AuditOrigin::Analyst,
        )
    }

    pub fn add_entity(
        &self,
        id: &CaseId,
        kind: FindingKind,
        value: &str,
        evidence_hash: &str,
        details: EntityDetails,
    ) -> Result<String, AppError> {
        self.require_attended_analyst("add case entity")?;
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        self.propose_finding_unlocked(
            id,
            kind,
            value,
            evidence_hash,
            Some(details),
            crate::AuditOrigin::Analyst,
        )
    }

    pub(crate) fn propose_finding_unlocked(
        &self,
        id: &CaseId,
        kind: FindingKind,
        value: &str,
        evidence_hash: &str,
        details: Option<EntityDetails>,
        origin: crate::AuditOrigin,
    ) -> Result<String, AppError> {
        if value.trim().is_empty() || value.len() > 2_000 || value.contains('\0') {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidFindingValue,
            ));
        }
        if !self
            .evidence_store
            .evidence_hashes(id)?
            .iter()
            .any(|hash| hash == evidence_hash)
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyFindingEvidenceIsAbsentFromCase,
            ));
        }
        let finding = Finding {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            value: value.to_owned(),
            evidence_hash: evidence_hash.to_owned(),
            confirmed: false,
            dismissed: false,
            details,
        };
        let known_evidence = self
            .evidence_store
            .evidence_hashes(id)?
            .into_iter()
            .collect();
        if !finding.valid_for(&known_evidence) {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidFindingValue,
            ));
        }
        if let Some(EntityDetails::Timeline {
            record_index: Some(index),
            ..
        }) = &finding.details
        {
            self.graph.raw_record(id, evidence_hash, *index)?;
        }
        self.audit(
            id,
            origin,
            AuditEventKind::FindingProposed,
            &serde_json::to_string(&finding).map_err(|e| AppError::Storage(e.to_string()))?,
            Some(evidence_hash),
        )?;
        Ok(finding.id)
    }

    pub fn confirm_finding(&self, id: &CaseId, finding_id: &str) -> Result<(), AppError> {
        self.require_attended_analyst("confirm case finding")?;
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        let findings = self.findings_unlocked(id, &self.audit_log.entries(id)?)?;
        if !findings
            .iter()
            .any(|finding| finding.id == finding_id && !finding.confirmed && !finding.dismissed)
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyUnconfirmedFindingNotFound,
            ));
        }
        self.audit(
            id,
            crate::AuditOrigin::Analyst,
            irmind_domain::AuditEventKind::FindingConfirmed,
            finding_id,
            None,
        )
    }

    pub fn dismiss_finding(
        &self,
        id: &CaseId,
        finding_id: &str,
        reason: &str,
    ) -> Result<(), AppError> {
        self.require_attended_analyst("dismiss case finding")?;
        if reason.trim().is_empty() || reason.len() > 500 {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidDismissalReason,
            ));
        }
        let _case_lock = self.repo.lock_case(id)?;
        if self.repo.get_case(id)?.sealed {
            return Err(AppError::Sealed);
        }
        self.verify_unlocked(id)?;
        let findings = self.findings_unlocked(id, &self.audit_log.entries(id)?)?;
        if !findings
            .iter()
            .any(|finding| finding.id == finding_id && !finding.confirmed && !finding.dismissed)
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyOpenFindingNotFound,
            ));
        }
        let event = FindingDismissal {
            id: finding_id.to_owned(),
            reason: reason.to_owned(),
        };
        self.audit(
            id,
            crate::AuditOrigin::Analyst,
            irmind_domain::AuditEventKind::FindingDismissed,
            &serde_json::to_string(&event).map_err(|error| AppError::Storage(error.to_string()))?,
            None,
        )
    }

    pub fn findings(&self, id: &CaseId) -> Result<Vec<Finding>, AppError> {
        let _case_lock = self.repo.lock_case(id)?;
        self.verify_unlocked(id)?;
        self.findings_unlocked(id, &self.audit_log.entries(id)?)
    }

    pub(crate) fn findings_unlocked(
        &self,
        id: &CaseId,
        entries: &[SignedEntry],
    ) -> Result<Vec<Finding>, AppError> {
        let known_evidence = self
            .evidence_store
            .evidence_hashes(id)?
            .into_iter()
            .collect();
        let mut findings = BTreeMap::<String, Finding>::new();
        for entry in entries {
            match entry.kind {
                AuditEventKind::FindingProposed => {
                    let finding: Finding = serde_json::from_str(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    if !matches!(entry.origin.as_str(), "analyst" | "model")
                        || (entry.origin == "analyst" && entry.actor != Actor::Analyst)
                        || finding.confirmed
                        || finding.dismissed
                        || uuid::Uuid::parse_str(&finding.id).is_err()
                        || finding.value.trim().is_empty()
                        || finding.value.len() > 2_000
                        || finding.value.contains('\0')
                        || entry.evidence.as_deref() != Some(finding.evidence_hash.as_str())
                        || !finding.valid_for(&known_evidence)
                        || findings.insert(finding.id.clone(), finding).is_some()
                    {
                        return Err(AppError::InvalidChain(entry.seq));
                    }
                }
                AuditEventKind::FindingConfirmed => {
                    let finding = findings
                        .get_mut(&entry.payload)
                        .ok_or(AppError::InvalidChain(entry.seq))?;
                    if entry.actor != Actor::Analyst
                        || finding.confirmed
                        || finding.dismissed
                        || entry.evidence.is_some()
                    {
                        return Err(AppError::InvalidChain(entry.seq));
                    }
                    finding.confirmed = true;
                }
                AuditEventKind::FindingDismissed => {
                    let event: FindingDismissal = serde_json::from_str(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    let finding = findings
                        .get_mut(&event.id)
                        .ok_or(AppError::InvalidChain(entry.seq))?;
                    if entry.actor != Actor::Analyst
                        || finding.confirmed
                        || finding.dismissed
                        || entry.evidence.is_some()
                        || event.reason.trim().is_empty()
                        || event.reason.len() > 500
                    {
                        return Err(AppError::InvalidChain(entry.seq));
                    }
                    finding.dismissed = true;
                }
                _ => {}
            }
        }
        Ok(findings.into_values().collect())
    }
}
