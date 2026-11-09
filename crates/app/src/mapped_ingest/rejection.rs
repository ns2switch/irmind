use crate::AppError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFailureReason {
    Format,
    Limit,
    Hash,
    Cancelled,
}
impl SourceFailureReason {
    pub const fn description(self) -> &'static str {
        match self {
            Self::Format => "invalid source format",
            Self::Limit => "source limit exceeded",
            Self::Hash => "source hash mismatch",
            Self::Cancelled => "source processing cancelled",
        }
    }
}
#[derive(Clone, Serialize)]
pub struct RejectedSource {
    source: String,
    reason: SourceFailureReason,
    samples: Vec<String>,
}
#[derive(Deserialize)]
struct Owned {
    operation: String,
    status: String,
    source: RejectionFields,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectionFields {
    source: String,
    reason: SourceFailureReason,
    samples: Vec<String>,
}
impl RejectedSource {
    pub fn try_new(
        source: String,
        reason: SourceFailureReason,
        samples: Vec<String>,
    ) -> Result<Self, AppError> {
        irmind_domain::SourceReferenceV1::file(&source)
            .map_err(|_| AppError::Policy("invalid rejected source reference".into()))?;
        if samples.len() > 3 || samples.iter().any(|s| s.len() > 256) {
            return Err(AppError::Policy(
                "rejected source samples exceed their limit".into(),
            ));
        }
        Ok(Self {
            source,
            reason,
            samples,
        })
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub const fn reason(&self) -> SourceFailureReason {
        self.reason
    }
    pub fn samples(&self) -> &[String] {
        &self.samples
    }
}
impl std::fmt::Debug for RejectedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectedSource")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AuditRejection<'a> {
    operation: &'a str,
    status: &'a str,
    source: &'a RejectedSource,
}
impl RejectedSource {
    pub fn audit_payload(&self) -> Result<String, AppError> {
        serde_json::to_string(&AuditRejection {
            operation: "ingest_source",
            status: "rejected",
            source: self,
        })
        .map_err(|_| AppError::Policy("cannot encode source rejection".into()))
    }
    pub fn from_audit(entry: &crate::SignedEntry) -> Result<Option<Self>, AppError> {
        if entry.kind != crate::AuditEventKind::ToolError {
            return Ok(None);
        }

        let Ok(parsed) = serde_json::from_str::<Owned>(&entry.payload) else {
            return Ok(None);
        };
        if parsed.operation != "ingest_source" || parsed.status != "rejected" {
            return Ok(None);
        }
        Self::try_new(
            parsed.source.source,
            parsed.source.reason,
            parsed.source.samples,
        )
        .map(Some)
    }
}
