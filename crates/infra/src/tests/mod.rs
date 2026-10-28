use super::evidence_fs::read_evidence_file;
use super::seal::MAX_EXPORT_BYTES;
use super::*;
use irmind_app::modules::{ModuleConfig, ModuleRegistry};
use irmind_app::{
    CancellationToken, CloudAuditPort, CompletionRequest, CryptoPorts, Engine, EnginePorts,
    FindingKind, InternalIntelPort, LlmPort, ModelResponse, ModelStream, ModelUsage, SiemPort,
    ThreatIntelPort, async_trait,
};
use irmind_domain::{
    Actor, Case, CaseId, Decision, ExecutionMode, PolicyRules, ProposedCall, Tool, evaluate,
};
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use irmind_testkit::{FakeEdr, FixedClock};
use std::collections::BTreeMap;
use std::sync::Arc;

trait LegacyModel: Send + Sync {
    fn complete(&self, context: &str) -> Result<ModelResponse, AppError>;
    fn complete_with_usage(
        &self,
        context: &str,
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        self.complete(context).map(|response| (response, None))
    }
    fn complete_request(
        &self,
        request: &CompletionRequest,
    ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
        self.complete_with_usage(request.context().unwrap_or_default())
    }
}

macro_rules! streaming_test_model {
    ($name:ty) => {
        #[async_trait]
        impl LlmPort for $name {
            async fn complete(
                &self,
                request: CompletionRequest,
                cancel: &CancellationToken,
            ) -> Result<ModelStream, AppError> {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let (response, usage) = LegacyModel::complete_request(self, &request)?;
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                Ok(irmind_app::single_completion_stream(response, usage))
            }
        }
    };
}

mod foundation;
mod test_support;
use foundation::{
    FakeExternalIntel, FindingModel, MissingReadModel, ObedientModel, QuietModel,
    RepeatingReadModel,
};
use test_support::{
    CaptureModel, EdrModel, FakeCloudAudit, FakeInternalIntel, FakeSiem, TestSigner,
};
mod approvals;
mod case_findings_and_agent;
mod concurrency_and_migrations;
mod custody_operations;
mod graph_benchmark;
mod graph_runtime;
mod incremental_custody;
mod injection_and_taint;
mod remote_dispatch_edr_ti;
mod remote_dispatch_siem_cloud;
mod scope_and_graph;
mod scope_pending;
mod seal_export;
mod seal_recovery;
