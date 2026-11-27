//! The signed binding and whole-plan resources approved for child source queries.
use super::{SubagentDigest, SubagentRecord, SubagentRecordError, codec};
use crate::source_queries::{QUERY_CASE_MAX_BYTES, QUERY_CASE_MAX_ROWS, SourceQueryResources};
use crate::{AuditEventKind, CaseScope};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildQueryShare {
    pub task_id: SubagentDigest,
    pub sources: Vec<String>,
    pub scope: String,
    pub scan_bytes: u64,
    pub retained_rows: u64,
    pub retained_bytes: u64,
}

impl ChildQueryShare {
    pub(super) fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::sorted(&self.sources, 32)?;
        if self.sources.is_empty()
            || self.sources.iter().any(|id| !crate::source_queries::id(id))
            || self.scope.len() > 1000
            || self.retained_rows > QUERY_CASE_MAX_ROWS
            || self.retained_bytes > QUERY_CASE_MAX_BYTES
        {
            return Err(SubagentRecordError);
        }
        let scope = CaseScope::parse(&self.scope).map_err(|_| SubagentRecordError)?;
        let CaseScope::Remote { sources, .. } = &scope else {
            return Err(SubagentRecordError);
        };
        if !self.sources.iter().eq(sources)
            || scope.to_current_string().map_err(|_| SubagentRecordError)? != self.scope
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }

    pub const fn resources(&self) -> SourceQueryResources {
        SourceQueryResources {
            scan_bytes: self.scan_bytes,
            retained_rows: self.retained_rows,
            retained_bytes: self.retained_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildSourceQueryV1 {
    version: u8,
    pub case_id: String,
    pub plan: SubagentDigest,
    pub task_id: SubagentDigest,
    pub query_plan: SubagentDigest,
    pub checkpoint: SubagentDigest,
    pub branch_proposal: SubagentDigest,
    pub source_id: String,
    pub source_set: SubagentDigest,
    pub budget_checkpoint: SubagentDigest,
}

pub(super) fn canonical_j(value: &impl Serialize) -> Result<Vec<u8>, SubagentRecordError> {
    let mut json = serde_json::to_value(value).map_err(|_| SubagentRecordError)?;
    let body = crate::canonical_j::encode(&mut json).map_err(|_| SubagentRecordError)?;
    if body.len() > 256 * 1024 {
        return Err(SubagentRecordError);
    }
    Ok(body)
}

impl SubagentRecord for ChildSourceQueryV1 {
    const KIND: AuditEventKind = AuditEventKind::ChildSourceQueryV1;
    const DOMAIN: &'static [u8] = b"irmind-child-source-query-v1\0";

    fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.case_id)?;
        if self.version != 1 || !crate::source_queries::id(&self.source_id) {
            return Err(SubagentRecordError);
        }
        Ok(())
    }

    fn canonical(&self) -> Result<Vec<u8>, SubagentRecordError> {
        self.validate()?;
        canonical_j(self)
    }
}

/// Version 2 commits the bounded assignment for every child query alongside
/// the existing plan fields. A record alone grants no provider capability.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentPlanV2 {
    #[serde(flatten)]
    plan: super::SubagentPlanV1,
    pub query_resources: Vec<ChildQueryShare>,
}

impl SubagentPlanV2 {
    pub fn new(
        mut plan: super::SubagentPlanV1,
        query_resources: Vec<ChildQueryShare>,
    ) -> Result<Self, SubagentRecordError> {
        plan.format_version = 2;
        let value = Self {
            plan,
            query_resources,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn local_plan(&self) -> &super::SubagentPlanV1 {
        &self.plan
    }

    pub fn requires_query_consent(
        &self,
        remaining: SourceQueryResources,
    ) -> Result<bool, SubagentRecordError> {
        self.validate()?;
        let held = self.query_resources.iter().try_fold(
            SourceQueryResources::default(),
            |sum, share| {
                let share = share.resources();
                Ok::<_, SubagentRecordError>(SourceQueryResources {
                    scan_bytes: sum
                        .scan_bytes
                        .checked_add(share.scan_bytes)
                        .ok_or(SubagentRecordError)?,
                    retained_rows: sum
                        .retained_rows
                        .checked_add(share.retained_rows)
                        .ok_or(SubagentRecordError)?,
                    retained_bytes: sum
                        .retained_bytes
                        .checked_add(share.retained_bytes)
                        .ok_or(SubagentRecordError)?,
                })
            },
        )?;
        let dimensions = [
            (held.scan_bytes, remaining.scan_bytes),
            (held.retained_rows, remaining.retained_rows),
            (held.retained_bytes, remaining.retained_bytes),
        ];
        if dimensions
            .iter()
            .any(|(requested, available)| requested > available)
        {
            return Err(SubagentRecordError);
        }
        Ok(dimensions
            .into_iter()
            .any(|(requested, available)| u128::from(requested) * 4 > u128::from(available)))
    }
}

impl SubagentRecord for SubagentPlanV2 {
    const KIND: AuditEventKind = AuditEventKind::SubagentPlanV2;
    const DOMAIN: &'static [u8] = b"irmind-subagent-plan-v2\0";

    fn validate(&self) -> Result<(), SubagentRecordError> {
        self.plan.validate_version(2)?;
        if self.query_resources.len() > self.plan.tasks.len()
            || self
                .query_resources
                .windows(2)
                .any(|pair| pair[0].task_id >= pair[1].task_id)
        {
            return Err(SubagentRecordError);
        }
        for query in &self.query_resources {
            query.validate()?;
            let task = self
                .plan
                .tasks
                .iter()
                .find(|task| task.task_id == query.task_id)
                .ok_or(SubagentRecordError)?;
            let base = task
                .remote_scope
                .as_deref()
                .and_then(|s| CaseScope::parse(s).ok())
                .ok_or(SubagentRecordError)?;
            if !CaseScope::parse(&query.scope)
                .map_err(|_| SubagentRecordError)?
                .is_within(&base)
            {
                return Err(SubagentRecordError);
            }
        }
        Ok(())
    }

    fn canonical(&self) -> Result<Vec<u8>, SubagentRecordError> {
        self.validate()?;
        canonical_j(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn assert_approved<R: SubagentRecord>(name: &str) -> R {
        let docs: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/development/v08-implementation-vectors/wire.json"
        ))
        .unwrap();
        let vector = &docs["child_queries"][name];
        let bytes = hex::decode(vector["body"]["hex"].as_str().unwrap()).unwrap();
        let record = R::decode(&bytes).unwrap();
        assert_eq!(record.canonical().unwrap(), bytes);
        assert_eq!(record.audit_payload().unwrap(), vector["payload"]);
        assert_eq!(
            crate::hex(record.identity().unwrap().as_bytes()),
            vector["identity_preimage"]["sha256"]
        );
        record
    }

    #[test]
    fn child_source_query_records_match_independent_j_vectors() {
        let plan = assert_approved::<SubagentPlanV2>("plan_without_remote_share");
        assert!(plan.query_resources.is_empty());
        assert!(
            !plan
                .requires_query_consent(SourceQueryResources::default())
                .unwrap()
        );
        let mut binding = assert_approved::<ChildSourceQueryV1>("child_binding_codec_only");
        binding.source_id = "*".into();
        assert!(binding.canonical().is_err());
    }

    #[test]
    fn child_query_share_scope_and_whole_plan_threshold_fail_closed() {
        const SCOPE: &str = "v2;sources=cloudtrail;accounts=123456789012;projects=;hosts=;from=2026-01-01T00:00:00Z;to=2026-01-02T00:00:00Z";
        let mut plan = assert_approved::<SubagentPlanV2>("plan_without_remote_share");
        plan.plan.tasks[0].remote_scope = Some(SCOPE.into());
        plan.query_resources.push(ChildQueryShare {
            task_id: plan.plan.tasks[0].task_id,
            sources: vec!["cloudtrail".into()],
            scope: SCOPE.into(),
            scan_bytes: u64::MAX / 4,
            retained_rows: 25,
            retained_bytes: 50,
        });
        let remaining = SourceQueryResources {
            scan_bytes: u64::MAX,
            retained_rows: 100,
            retained_bytes: 200,
        };
        assert!(!plan.requires_query_consent(remaining).unwrap());
        plan.query_resources[0].scan_bytes += 1;
        assert!(plan.requires_query_consent(remaining).unwrap());
        assert!(
            plan.requires_query_consent(SourceQueryResources::default())
                .is_err()
        );
        plan.query_resources[0].sources[0] = "other-source".into();
        assert!(plan.canonical().is_err());
    }
}
