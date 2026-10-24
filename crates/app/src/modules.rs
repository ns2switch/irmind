//! Compile-time modules are owned by the composition root and exposed through application ports.

use crate::{
    AppError, CloudAuditPort, EdrPort, Engine, EventParser, InternalIntelPort, LlmPort, SiemPort,
    ThreatIntelPort, hex, sha256,
};
use irmind_domain::Tool;
use std::collections::{BTreeMap, BTreeSet};

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

pub trait Module: Send + Sync {
    fn manifest(&self) -> &'static ModuleManifest;
    fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError>;
}

#[derive(Default)]
pub struct ModuleRegistry {
    manifests: BTreeMap<&'static str, &'static ModuleManifest>,
    llms: BTreeMap<&'static str, Box<dyn LlmPort>>,
    parser: Option<Box<dyn EventParser>>,
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

    pub fn register(&mut self, module: Box<dyn Module>) -> Result<(), AppError> {
        let manifest = module.manifest();
        validate_manifest(manifest)?;
        if self.manifests.contains_key(manifest.id) {
            return Err(AppError::Policy("duplicate module ID".into()));
        }
        let mut staged = Self::new();
        module.register(&mut staged)?;
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
        self.parser = Some(port);
        Ok(())
    }

    pub fn parser(&self) -> Result<&dyn EventParser, AppError> {
        self.parser
            .as_deref()
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
    use crate::{ModelResponse, ModelUsage};
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

    struct TestLlm;
    impl LlmPort for TestLlm {
        fn complete(&self, _context: &str) -> Result<ModelResponse, AppError> {
            Ok(ModelResponse {
                text: "ok".into(),
                calls: Vec::new(),
                raw: "ok".into(),
            })
        }

        fn complete_with_usage(
            &self,
            context: &str,
        ) -> Result<(ModelResponse, Option<ModelUsage>), AppError> {
            self.complete(context).map(|response| (response, None))
        }
    }
    impl Module for TestLlm {
        fn manifest(&self) -> &'static ModuleManifest {
            &LLM
        }
        fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
            registry.add_llm(LLM.id, self)
        }
    }

    struct TestEdr;
    impl EdrPort for TestEdr {
        fn source_id(&self) -> &'static str {
            "edr-test-source"
        }
        fn supports(&self, tool: &Tool) -> bool {
            tool == &Tool::EdrDetections
        }
        fn host_info(&self, _call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
            Ok(Vec::new())
        }
        fn process_tree(&self, _call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
            Ok(Vec::new())
        }
        fn detections(&self, _call: &AuthorizedCall) -> Result<Vec<u8>, AppError> {
            Ok(Vec::new())
        }
    }
    impl Module for TestEdr {
        fn manifest(&self) -> &'static ModuleManifest {
            &EDR
        }
        fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
            registry.add_edr(self)
        }
    }

    struct Misdeclared;
    impl Module for Misdeclared {
        fn manifest(&self) -> &'static ModuleManifest {
            &MISDECLARED
        }
        fn register(self: Box<Self>, registry: &mut ModuleRegistry) -> Result<(), AppError> {
            registry.add_edr(Box::new(TestEdr))
        }
    }

    #[test]
    fn llm_and_edr_share_registry_without_replacing_each_other() {
        let mut registry = ModuleRegistry::new();
        registry.register(Box::new(TestLlm)).unwrap();
        registry.register(Box::new(TestEdr)).unwrap();
        assert_eq!(
            registry.llm(LLM.id).unwrap().complete("x").unwrap().text,
            "ok"
        );
        assert_eq!(registry.counts()[&ModulePort::Edr], 1);
        assert!(registry.register(Box::new(TestLlm)).is_err());
        assert!(registry.register(Box::new(TestEdr)).is_err());
        let fingerprint = registry.fingerprint();
        let mut reversed = ModuleRegistry::new();
        reversed.register(Box::new(TestEdr)).unwrap();
        reversed.register(Box::new(TestLlm)).unwrap();
        assert_eq!(fingerprint, reversed.fingerprint());
        let before = registry.fingerprint();
        assert!(registry.register(Box::new(Misdeclared)).is_err());
        assert_eq!(registry.fingerprint(), before);
        assert_eq!(registry.counts()[&ModulePort::Edr], 1);
    }
}
