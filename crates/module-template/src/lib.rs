#![forbid(unsafe_code)]

//! Synthetic SIEM connector template. It is never registered by the binary.

use irmind_app::{
    AppError, CancellationToken, SiemPort, async_trait,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::{AuthorizedCall, Tool};

const SOURCE: &str = "example-siem";

static MANIFEST: ModuleManifest = ModuleManifest {
    id: SOURCE,
    version: "0.1.0",
    ports: &[ModulePort::Siem],
    tools: &[Tool::SiemSearch, Tool::SiemGetAlert],
    config: &[],
};

pub struct ExampleSiem;

impl Module for ExampleSiem {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_siem(self)
    }
}

#[async_trait]
impl SiemPort for ExampleSiem {
    fn source_id(&self) -> &str {
        SOURCE
    }

    fn dialect(&self) -> &'static str {
        "synthetic structured query"
    }

    async fn execute(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if !matches!(call.tool(), Tool::SiemSearch | Tool::SiemGetAlert)
            || call.arg("source") != Some(SOURCE)
        {
            return Err(AppError::Policy("wrong SIEM tool or source".into()));
        }
        Ok(br#"{"result":{"eventName":"AssumeRole"}}"#.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::ExampleSiem;

    #[test]
    fn passes_siem_port_contract() -> Result<(), String> {
        irmind_testkit::run_siem_contract(&ExampleSiem)
    }
}
