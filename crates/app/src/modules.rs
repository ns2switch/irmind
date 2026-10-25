//! Compile-time modules are owned by the composition root and exposed through application ports.

use crate::{
    AppError, CloudAuditPort, EdrPort, Engine, EventParser, InternalIntelPort, LlmPort, SiemPort,
    ThreatIntelPort, hex, sha256,
};
use irmind_domain::Tool;
use secrecy::SecretString;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ModulePort {
    Llm,
    Siem,
    Edr,
    CloudAudit,
    InternalIntel,
    ThreatIntel,
    EventParser,
}

#[derive(Clone, Copy, Debug)]
pub struct ConfigField {
    pub name: &'static str,
    pub required: bool,
    pub secret: bool,
}

#[derive(Debug)]
pub struct ModuleManifest {
    pub id: &'static str,
    pub version: &'static str,
    pub ports: &'static [ModulePort],
    pub tools: &'static [Tool],
    pub config: &'static [ConfigField],
}

#[derive(Default)]
pub struct ModuleConfig {
    values: BTreeMap<String, String>,
    secrets: BTreeMap<String, SecretString>,
}

impl ModuleConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_value(&mut self, name: &str, value: String) {
        self.values.insert(name.to_owned(), value);
    }

    pub fn insert_secret(&mut self, name: &str, value: SecretString) {
        self.secrets.insert(name.to_owned(), value);
    }

    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    #[must_use]
    pub fn secret(&self, name: &str) -> Option<&SecretString> {
        self.secrets.get(name)
    }

    pub fn required_value(&self, name: &str) -> Result<&str, AppError> {
        self.value(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::Policy(format!("missing module setting {name}")))
    }

    pub fn required_secret(&self, name: &str) -> Result<&SecretString, AppError> {
        self.secret(name)
            .ok_or_else(|| AppError::Policy(format!("missing module secret {name}")))
    }

    fn validate(&self, manifest: &ModuleManifest) -> Result<(), AppError> {
        for field in manifest.config {
            let present = if field.secret {
                self.secrets.contains_key(field.name)
            } else {
                self.values.contains_key(field.name)
            };
            if field.required && !present {
                return Err(AppError::Policy(format!(
                    "missing module setting {}",
                    field.name
                )));
            }
        }
        for name in self.values.keys().chain(self.secrets.keys()) {
            if !manifest.config.iter().any(|field| field.name == name) {
                return Err(AppError::Policy(format!("unknown module setting {name}")));
            }
        }
        Ok(())
    }
}

pub trait Module: Send + Sync {
    fn manifest(&self) -> &'static ModuleManifest;
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        config: &ModuleConfig,
    ) -> Result<(), AppError>;
}

#[derive(Default)]
pub struct ModuleRegistry {
    manifests: BTreeMap<&'static str, &'static ModuleManifest>,
    llms: BTreeMap<&'static str, Box<dyn LlmPort>>,
    parser: Option<Arc<dyn EventParser>>,
    siems: Vec<Box<dyn SiemPort>>,
    edrs: Vec<Box<dyn EdrPort>>,
    cloud_audits: Vec<Box<dyn CloudAuditPort>>,
    internal_intel: Vec<Box<dyn InternalIntelPort>>,
    threat_intel: Option<Box<dyn ThreatIntelPort>>,
}

impl ModuleRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        module: Box<dyn Module>,
        config: &ModuleConfig,
    ) -> Result<(), AppError> {
        let manifest = module.manifest();
        validate_manifest(manifest)?;
        config.validate(manifest)?;
        if self.manifests.contains_key(manifest.id) {
            return Err(AppError::Policy("duplicate module ID".into()));
        }
        let mut staged = Self::new();
        module.register(&mut staged, config)?;
        let actual = staged.counts();
        for port in [
            ModulePort::Llm,
            ModulePort::Siem,
            ModulePort::Edr,
            ModulePort::CloudAudit,
            ModulePort::InternalIntel,
            ModulePort::ThreatIntel,
            ModulePort::EventParser,
        ] {
            let expected = usize::from(manifest.ports.contains(&port));
            if actual[&port] != expected {
                return Err(AppError::Policy(
                    "module registered undeclared ports".into(),
                ));
            }
        }
        if manifest.ports.contains(&ModulePort::Llm) && !staged.llms.contains_key(manifest.id) {
            return Err(AppError::Policy(
                "LLM registered under a different module ID".into(),
            ));
        }
        if let Some(edr) = staged.edrs.first() {
            for tool in [Tool::EdrHostInfo, Tool::EdrProcessTree, Tool::EdrDetections] {
                if edr.supports(&tool) != manifest.tools.contains(&tool) {
                    return Err(AppError::Policy(
                        "EDR manifest and capabilities differ".into(),
                    ));
                }
            }
        }
        if staged.siems.iter().any(|port| {
            self.siems
                .iter()
                .any(|prior| prior.source_id() == port.source_id())
        }) || staged.edrs.iter().any(|port| {
            self.edrs
                .iter()
                .any(|prior| prior.source_id() == port.source_id())
        }) || staged.cloud_audits.iter().any(|port| {
            self.cloud_audits
                .iter()
                .any(|prior| prior.source_id() == port.source_id())
        }) || staged.internal_intel.iter().any(|port| {
            self.internal_intel
                .iter()
                .any(|prior| prior.source_id() == port.source_id())
        }) || (staged.threat_intel.is_some() && self.threat_intel.is_some())
            || (staged.parser.is_some() && self.parser.is_some())
        {
            return Err(AppError::Policy(
                "module source or port is already registered".into(),
            ));
        }
        self.llms.extend(staged.llms);
        self.siems.extend(staged.siems);
        self.edrs.extend(staged.edrs);
        self.cloud_audits.extend(staged.cloud_audits);
        self.internal_intel.extend(staged.internal_intel);
        if let Some(port) = staged.threat_intel {
            self.threat_intel = Some(port);
        }
        if let Some(port) = staged.parser {
            self.parser = Some(port);
        }
        self.manifests.insert(manifest.id, manifest);
        Ok(())
    }

    #[must_use]
    pub fn manifest(&self, id: &str) -> Option<&'static ModuleManifest> {
        self.manifests.get(id).copied()
    }

    pub fn add_llm(&mut self, id: &'static str, port: Box<dyn LlmPort>) -> Result<(), AppError> {
        if self.llms.contains_key(id) {
            return Err(AppError::Policy("duplicate LLM module".into()));
        }
        self.llms.insert(id, port);
        Ok(())
    }

    pub fn add_parser(&mut self, port: Box<dyn EventParser>) -> Result<(), AppError> {
        if self.parser.is_some() {
            return Err(AppError::Policy("duplicate event parser".into()));
        }
        self.parser = Some(Arc::from(port));
        Ok(())
    }

    pub fn parser(&self) -> Result<Arc<dyn EventParser>, AppError> {
        self.parser
            .clone()
            .ok_or_else(|| AppError::Policy("event parser is not registered".into()))
    }

    pub fn add_siem(&mut self, port: Box<dyn SiemPort>) -> Result<(), AppError> {
        if self
            .siems
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Policy("duplicate SIEM source".into()));
        }
        self.siems.push(port);
        Ok(())
    }

    pub fn add_edr(&mut self, port: Box<dyn EdrPort>) -> Result<(), AppError> {
        if self
            .edrs
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Policy("duplicate EDR source".into()));
        }
        self.edrs.push(port);
        Ok(())
    }

    pub fn add_cloud_audit(&mut self, port: Box<dyn CloudAuditPort>) -> Result<(), AppError> {
        if self
            .cloud_audits
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Policy("duplicate cloud audit source".into()));
        }
        self.cloud_audits.push(port);
        Ok(())
    }

    pub fn add_internal_intel(&mut self, port: Box<dyn InternalIntelPort>) -> Result<(), AppError> {
        if self
            .internal_intel
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Policy(
                "duplicate internal intelligence source".into(),
            ));
        }
        self.internal_intel.push(port);
        Ok(())
    }

    pub fn add_threat_intel(&mut self, port: Box<dyn ThreatIntelPort>) -> Result<(), AppError> {
        if self.threat_intel.is_some() {
            return Err(AppError::Policy(
                "duplicate external intelligence module".into(),
            ));
        }
        self.threat_intel = Some(port);
        Ok(())
    }

    pub fn llm(&self, id: &str) -> Result<&dyn LlmPort, AppError> {
        self.llms
            .get(id)
            .map(Box::as_ref)
            .ok_or_else(|| AppError::Model("LLM module is not registered".into()))
    }

    pub fn bind<'a>(&'a self, mut engine: Engine<'a>) -> Result<Engine<'a>, AppError> {
        for port in &self.siems {
            engine = engine.with_siem(port.as_ref())?;
        }
        for port in &self.edrs {
            engine = engine.with_edr(port.as_ref())?;
        }
        for port in &self.cloud_audits {
            engine = engine.with_cloud_audit(port.as_ref())?;
        }
        for port in &self.internal_intel {
            engine = engine.with_internal_intel(port.as_ref())?;
        }
        if let Some(port) = &self.threat_intel {
            engine = engine.with_threat_intel(port.as_ref());
        }
        engine.with_module_fingerprint(self.fingerprint())
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut data = Vec::new();
        for manifest in self.manifests.values() {
            for field in [manifest.id, manifest.version] {
                data.extend_from_slice(field.as_bytes());
                data.push(0);
            }
            for port in manifest.ports {
                data.extend_from_slice(format!("{port:?}").as_bytes());
                data.push(0);
            }
            for tool in manifest.tools {
                data.extend_from_slice(tool.as_str().as_bytes());
                data.push(0);
            }
            for field in manifest.config {
                data.extend_from_slice(field.name.as_bytes());
                data.extend_from_slice(&[u8::from(field.required), u8::from(field.secret), 0]);
            }
        }
        hex(&sha256(&data))
    }

    fn counts(&self) -> BTreeMap<ModulePort, usize> {
        BTreeMap::from([
            (ModulePort::Llm, self.llms.len()),
            (ModulePort::Siem, self.siems.len()),
            (ModulePort::Edr, self.edrs.len()),
            (ModulePort::CloudAudit, self.cloud_audits.len()),
            (ModulePort::InternalIntel, self.internal_intel.len()),
            (
                ModulePort::ThreatIntel,
                usize::from(self.threat_intel.is_some()),
            ),
            (ModulePort::EventParser, usize::from(self.parser.is_some())),
        ])
    }
}

fn validate_manifest(manifest: &ModuleManifest) -> Result<(), AppError> {
    let valid_id = |value: &str| {
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    if !valid_id(manifest.id)
        || manifest.version.is_empty()
        || manifest.version.len() > 32
        || !manifest
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        || manifest.ports.is_empty()
    {
        return Err(AppError::Policy("invalid module manifest".into()));
    }
    let ports = manifest.ports.iter().copied().collect::<BTreeSet<_>>();
    let tools = manifest
        .tools
        .iter()
        .map(Tool::as_str)
        .collect::<BTreeSet<_>>();
    let fields = manifest
        .config
        .iter()
        .map(|field| field.name)
        .collect::<BTreeSet<_>>();
    if ports.len() != manifest.ports.len()
        || tools.len() != manifest.tools.len()
        || fields.len() != manifest.config.len()
        || manifest.config.iter().any(|field| {
            field.name.is_empty()
                || !field
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(AppError::Policy("invalid module manifest".into()));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        CancellationToken, CompletionRequest, ModelEvent, ModelResponse, ModelStream, async_trait,
    };
    use irmind_domain::AuthorizedCall;

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
}
