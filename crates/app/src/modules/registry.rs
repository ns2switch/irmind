use super::config::{Module, ModuleConfig, ModuleManifest, ModulePort};
use crate::{
    AppError, CloudAuditPort, EdrPort, Engine, EventParser, InternalIntelPort, LlmPort, SiemPort,
    ThreatIntelPort, hex, sha256,
};
use irmind_domain::Tool;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateModuleID,
            ));
        }
        let mut staged = Self::new();
        module.register(&mut staged, config)?;
        self.validate_staged(manifest, &staged)?;
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

    fn validate_staged(&self, manifest: &ModuleManifest, staged: &Self) -> Result<(), AppError> {
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
                return Err(AppError::Fixed(
                    crate::FixedAppError::PolicyModuleRegisteredUndeclaredPorts,
                ));
            }
        }
        if manifest.ports.contains(&ModulePort::Llm) && !staged.llms.contains_key(manifest.id) {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyLLMRegisteredUnderADifferentModuleID,
            ));
        }
        if let Some(edr) = staged.edrs.first() {
            for tool in [Tool::EdrHostInfo, Tool::EdrProcessTree, Tool::EdrDetections] {
                if edr.supports(&tool) != manifest.tools.contains(&tool) {
                    return Err(AppError::Fixed(
                        crate::FixedAppError::PolicyEDRManifestAndCapabilitiesDiffer,
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
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyModuleSourceOrPortIsAlreadyRegistered,
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn manifest(&self, id: &str) -> Option<&'static ModuleManifest> {
        self.manifests.get(id).copied()
    }

    pub fn add_llm(&mut self, id: &'static str, port: Box<dyn LlmPort>) -> Result<(), AppError> {
        if self.llms.contains_key(id) {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateLLMModule,
            ));
        }
        self.llms.insert(id, port);
        Ok(())
    }

    pub fn add_parser(&mut self, port: Box<dyn EventParser>) -> Result<(), AppError> {
        if self.parser.is_some() {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateEventParser,
            ));
        }
        self.parser = Some(Arc::from(port));
        Ok(())
    }

    pub fn parser(&self) -> Result<Arc<dyn EventParser>, AppError> {
        self.parser.clone().ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyEventParserIsNotRegistered,
        ))
    }

    pub fn add_siem(&mut self, port: Box<dyn SiemPort>) -> Result<(), AppError> {
        if self
            .siems
            .iter()
            .any(|existing| existing.source_id() == port.source_id())
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateSIEMSource,
            ));
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
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateEDRSource,
            ));
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
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateCloudAuditSource,
            ));
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
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateInternalIntelligenceSource,
            ));
        }
        self.internal_intel.push(port);
        Ok(())
    }

    pub fn add_threat_intel(&mut self, port: Box<dyn ThreatIntelPort>) -> Result<(), AppError> {
        if self.threat_intel.is_some() {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateExternalIntelligenceModule,
            ));
        }
        self.threat_intel = Some(port);
        Ok(())
    }

    pub fn llm(&self, id: &str) -> Result<&dyn LlmPort, AppError> {
        self.llms.get(id).map(Box::as_ref).ok_or(AppError::Fixed(
            crate::FixedAppError::ModelLLMModuleIsNotRegistered,
        ))
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

    pub(super) fn counts(&self) -> BTreeMap<ModulePort, usize> {
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
        return Err(AppError::Fixed(
            crate::FixedAppError::PolicyInvalidModuleManifest,
        ));
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
        return Err(AppError::Fixed(
            crate::FixedAppError::PolicyInvalidModuleManifest,
        ));
    }
    Ok(())
}
