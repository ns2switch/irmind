use super::*;
use crate::{
    AppError, CancellationToken, CompletionRequest, EdrPort, LlmPort, ModelEvent, ModelResponse,
    ModelStream, ObjectSource, ObjectSourceOutput, async_trait,
};
use irmind_domain::{AuthorizedCall, Tool};

static LLM: ModuleManifest = ModuleManifest {
    id: "llm-test",
    version: "0.1.0",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[ConfigField {
        name: "TEST_LLM_KEY",
        required: false,
        secret: true,
    }],
};
static EDR: ModuleManifest = ModuleManifest {
    id: "edr-test",
    version: "0.1.0",
    ports: &[ModulePort::Edr],
    tools: &[Tool::EdrDetections],
    config: &[],
};
static MISDECLARED: ModuleManifest = ModuleManifest {
    id: "misdeclared",
    version: "0.1.0",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[],
};
static OBJECT: ModuleManifest = ModuleManifest {
    id: "storage-test",
    version: "0.1.0",
    ports: &[ModulePort::ObjectSource],
    tools: &[Tool::ObjectList, Tool::ObjectRead],
    config: &[],
};

#[test]
fn module_config_rejects_missing_and_unknown_settings() {
    static REQUIRED: ModuleManifest = ModuleManifest {
        id: "config-test",
        version: "0.1.0",
        ports: &[],
        tools: &[],
        config: &[ConfigField {
            name: "SECRET",
            required: true,
            secret: true,
        }],
    };
    let mut config = ModuleConfig::new();
    assert!(config.validate(&REQUIRED).is_err());
    config.insert_secret("SECRET", secrecy::SecretString::from("value".to_owned()));
    assert!(config.validate(&REQUIRED).is_ok());
    config.insert_value("UNKNOWN", "value".into());
    assert!(config.validate(&REQUIRED).is_err());
}

struct TestLlm;
#[async_trait]
impl LlmPort for TestLlm {
    async fn complete(
        &self,
        _request: CompletionRequest,
        _cancel: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        let response = ModelResponse {
            text: "ok".into(),
            calls: Vec::new(),
            raw: "ok".into(),
        };
        Ok(Box::pin(futures_util::stream::once(async move {
            Ok(ModelEvent::Completed {
                response,
                usage: None,
            })
        })))
    }
}
impl Module for TestLlm {
    fn manifest(&self) -> &'static ModuleManifest {
        &LLM
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_llm(LLM.id, self)
    }
}

struct TestEdr;
#[crate::async_trait]
impl EdrPort for TestEdr {
    fn source_id(&self) -> &'static str {
        "edr-test-source"
    }
    fn supports(&self, tool: &Tool) -> bool {
        tool == &Tool::EdrDetections
    }
    async fn execute(
        &self,
        _call: &AuthorizedCall,
        _cancel: &crate::CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        Ok(Vec::new())
    }
}
impl Module for TestEdr {
    fn manifest(&self) -> &'static ModuleManifest {
        &EDR
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_edr(self)
    }
}

struct Misdeclared;
impl Module for Misdeclared {
    fn manifest(&self) -> &'static ModuleManifest {
        &MISDECLARED
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_edr(Box::new(TestEdr))
    }
}

struct TestObject;
#[crate::async_trait]
impl ObjectSource for TestObject {
    fn source_id(&self) -> &'static str {
        "storage-test-source"
    }

    async fn execute(
        &self,
        _call: &AuthorizedCall,
        _cancel: &CancellationToken,
    ) -> Result<ObjectSourceOutput, AppError> {
        Ok(ObjectSourceOutput::Listing {
            objects: Vec::new(),
            total_bytes: 0,
            truncated: false,
        })
    }
}
impl Module for TestObject {
    fn manifest(&self) -> &'static ModuleManifest {
        &OBJECT
    }

    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _config: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_object_source(self)
    }
}

#[test]
fn object_source_registration_is_unique_and_explicit() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(TestObject), &ModuleConfig::new())
        .unwrap();
    assert_eq!(registry.counts()[&ModulePort::ObjectSource], 1);
    assert!(registry.object_source("storage-test-source").is_ok());
    assert!(registry.object_source("another-source").is_err());
    assert!(
        registry
            .register(Box::new(TestObject), &ModuleConfig::new())
            .is_err()
    );
}

#[tokio::test]
async fn llm_and_edr_share_registry_without_replacing_each_other() {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(TestLlm), &ModuleConfig::new())
        .unwrap();
    registry
        .register(Box::new(TestEdr), &ModuleConfig::new())
        .unwrap();
    let cancel = CancellationToken::new();
    let events = registry
        .llm(LLM.id)
        .unwrap()
        .complete(
            CompletionRequest {
                messages: Vec::new(),
                tools: Vec::new(),
                max_output_tokens: 1,
                remaining_case_tokens: 1,
            },
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(
        crate::collect_model_stream(events, &cancel)
            .await
            .unwrap()
            .0
            .text,
        "ok"
    );
    assert_eq!(registry.counts()[&ModulePort::Edr], 1);
    assert!(
        registry
            .register(Box::new(TestLlm), &ModuleConfig::new())
            .is_err()
    );
    assert!(
        registry
            .register(Box::new(TestEdr), &ModuleConfig::new())
            .is_err()
    );
    let fingerprint = registry.fingerprint();
    let mut reversed = ModuleRegistry::new();
    reversed
        .register(Box::new(TestEdr), &ModuleConfig::new())
        .unwrap();
    reversed
        .register(Box::new(TestLlm), &ModuleConfig::new())
        .unwrap();
    assert_eq!(fingerprint, reversed.fingerprint());
    let before = registry.fingerprint();
    assert!(
        registry
            .register(Box::new(Misdeclared), &ModuleConfig::new())
            .is_err()
    );
    assert_eq!(registry.fingerprint(), before);
    assert_eq!(registry.counts()[&ModulePort::Edr], 1);
}
