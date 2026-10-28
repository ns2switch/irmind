use crate::{AppError, AuthorizedCall, Engine, EntityDetails, FindingKind, GraphQueryFilter, Tool};

impl Engine<'_> {
    pub(crate) fn execute_local_tool(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        match call.tool() {
            Tool::EvidenceSearch | Tool::EvidenceRead => self.execute_evidence_tool(call),
            Tool::GraphSummary | Tool::EntityLookup | Tool::Neighbors | Tool::EntityTimeline => {
                self.execute_graph_lookup_tool(call)
            }
            Tool::GraphPath | Tool::TextSearch | Tool::RawRecords => {
                self.execute_graph_search_tool(call)
            }
            Tool::CaseAddFinding => self.execute_finding_tool(call),
            _ => Err(AppError::Fixed(
                crate::FixedAppError::PolicyInvalidLocalTool,
            )),
        }
    }

    fn execute_evidence_tool(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        Ok(match call.tool() {
            Tool::EvidenceSearch => {
                let query = call
                    .arg("query")
                    .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingQuery))?;
                let limit = call.arg("limit").and_then(|v| v.parse().ok()).unwrap_or(10);
                self.evidence_store
                    .search_evidence(call.case_id(), query, limit)?
                    .join("\n")
                    .into_bytes()
            }
            Tool::EvidenceRead => {
                let hash = call
                    .arg("hash")
                    .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingHash))?;
                let bytes = self.evidence_store.get_evidence(call.case_id(), hash)?;
                let limit = call
                    .arg("limit")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(10);
                let max = limit * 500;
                bytes.into_iter().take(max).collect()
            }
            _ => {
                return Err(AppError::Fixed(
                    crate::FixedAppError::PolicyInvalidLocalTool,
                ));
            }
        })
    }

    fn execute_graph_lookup_tool(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        let filter = graph_filter(call)?;
        Ok(match call.tool() {
            Tool::GraphSummary => self.graph.graph_summary(call.case_id())?.into_bytes(),
            Tool::EntityLookup => self
                .graph
                .entity_lookup_filtered(
                    call.case_id(),
                    &filter,
                    call.arg("kind")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingKind))?,
                    call.arg("value")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingValue))?,
                )?
                .into_bytes(),
            Tool::Neighbors => self
                .graph
                .neighbors_filtered(
                    call.case_id(),
                    &filter,
                    call.arg("kind")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingKind))?,
                    call.arg("value")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingValue))?,
                    call.arg("limit")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(10),
                )?
                .into_bytes(),
            Tool::EntityTimeline => self
                .graph
                .entity_timeline_filtered(
                    call.case_id(),
                    &filter,
                    call.arg("kind")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingKind))?,
                    call.arg("value")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingValue))?,
                    call.arg("limit")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(10),
                )?
                .into_bytes(),
            _ => {
                return Err(AppError::Fixed(
                    crate::FixedAppError::PolicyInvalidLocalTool,
                ));
            }
        })
    }

    fn execute_graph_search_tool(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        let filter = graph_filter(call)?;
        Ok(match call.tool() {
            Tool::GraphPath => self
                .graph
                .graph_path_filtered(
                    call.case_id(),
                    &filter,
                    (
                        call.arg("from_kind")
                            .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingFromKind))?,
                        call.arg("from_value").ok_or({
                            AppError::Fixed(crate::FixedAppError::PolicyMissingFromValue)
                        })?,
                    ),
                    (
                        call.arg("to_kind")
                            .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingToKind))?,
                        call.arg("to_value")
                            .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingToValue))?,
                    ),
                )?
                .into_bytes(),
            Tool::TextSearch => self
                .graph
                .text_search_filtered(
                    call.case_id(),
                    &filter,
                    call.arg("query")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingQuery))?,
                    call.arg("limit")
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(10),
                )?
                .into_bytes(),
            Tool::RawRecords => self
                .graph
                .raw_record(
                    call.case_id(),
                    call.arg("hash")
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingHash))?,
                    call.arg("index")
                        .and_then(|value| value.parse().ok())
                        .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingIndex))?,
                )?
                .into_bytes(),
            _ => {
                return Err(AppError::Fixed(
                    crate::FixedAppError::PolicyInvalidLocalTool,
                ));
            }
        })
    }

    fn execute_finding_tool(&self, call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
        Ok(match call.tool() {
            Tool::CaseAddFinding => {
                let kind =
                    FindingKind::parse(call.arg("kind").ok_or({
                        AppError::Fixed(crate::FixedAppError::PolicyMissingFindingKind)
                    })?)?;
                let details = EntityDetails::from_args(kind, call.proposal_args())?;
                self.propose_finding_unlocked(
                    call.case_id(),
                    kind,
                    call.arg("value").ok_or(AppError::Fixed(
                        crate::FixedAppError::PolicyMissingFindingValue,
                    ))?,
                    call.arg("evidence_hash").ok_or({
                        AppError::Fixed(crate::FixedAppError::PolicyMissingFindingEvidence)
                    })?,
                    details,
                    crate::AuditOrigin::Model,
                )?
                .into_bytes()
            }
            _ => {
                return Err(AppError::Fixed(
                    crate::FixedAppError::PolicyInvalidLocalTool,
                ));
            }
        })
    }
}

fn graph_filter(call: &AuthorizedCall) -> Result<GraphQueryFilter, AppError> {
    GraphQueryFilter::parse(
        call.arg("from"),
        call.arg("to"),
        call.arg("account"),
        call.arg("project"),
        call.arg("region"),
    )
    .map_err(|_| AppError::Policy("invalid graph filter".into()))
}
