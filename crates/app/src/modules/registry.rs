use super::config::{Module, ModuleConfig, ModuleManifest, ModulePort};
use super::parsers::{ParserCatalog, ParserChoice};
use crate::{
    AppError, CloudAuditPort, EdrPort, Engine, InternalIntelPort, LlmPort, LogParser, ObjectSource,
    SiemPort, ThreatIntelPort, hex, sha256,
};
use irmind_domain::Tool;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
mod definitions;
mod mapping;
fn mapping_error() -> AppError {
    crate::source_mapping::MappingError::InvalidDefinition.into_app()
}

#[derive(Default)]
pub struct ModuleRegistry {
    manifests: BTreeMap<&'static str, &'static ModuleManifest>,
    llms: BTreeMap<&'static str, Box<dyn LlmPort>>,
    parser: Option<Arc<dyn LogParser>>,
    parsers: BTreeMap<String, Arc<dyn LogParser>>,
    parser_variants: Vec<Arc<dyn LogParser>>,
    unavailable_parsers: BTreeMap<String, String>,
    siems: Vec<Box<dyn SiemPort>>,
    source_scopes: BTreeMap<String, crate::SiemSourceScope>,
    result_decoders: BTreeMap<String, Arc<dyn crate::SourceDecoder>>,
    edrs: Vec<Box<dyn EdrPort>>,
    cloud_audits: Vec<Box<dyn CloudAuditPort>>,
    internal_intel: Vec<Box<dyn InternalIntelPort>>,
    threat_intel: Option<Box<dyn ThreatIntelPort>>,
    object_sources: Vec<Box<dyn ObjectSource>>,
    definition_variants: Vec<crate::ApprovedDefinition>,
    definition_history: Option<Arc<crate::definitions::history::DefinitionHistory>>,
    source_decoders: Vec<Arc<dyn crate::SourceDecoder>>,
    source_mappers: Vec<Arc<dyn crate::SourceMapper>>,
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
        for definition in &staged.definition_variants {
            self.source_decoders
                .push(Arc::clone(definition.compiled().decoder()));
            self.source_mappers
                .push(Arc::clone(definition.compiled().extraction_mapper()));
        }
        self.register_siem_scopes(&staged, manifest, config)?;
        for port in &staged.siems {
            if let Some(decoder) = staged
                .source_decoders
                .iter()
                .find(|d| d.identity().name == manifest.id)
            {
                self.result_decoders
                    .insert(port.source_id().into(), Arc::clone(decoder));
            }
        }
        self.source_decoders.extend(staged.source_decoders);
        self.source_mappers.extend(staged.source_mappers);
        self.llms.extend(staged.llms);
        self.siems.extend(staged.siems);
        self.edrs.extend(staged.edrs);
        self.cloud_audits.extend(staged.cloud_audits);
        self.internal_intel.extend(staged.internal_intel);
        self.object_sources.extend(staged.object_sources);
        if let Some(port) = staged.threat_intel {
            self.threat_intel = Some(port);
        }
        if let Some(port) = staged.parser {
            if self.parser.is_none() {
                self.parser = Some(Arc::clone(&port));
            }
            self.parsers.insert(manifest.id.to_owned(), port);
        }
        for port in staged.parser_variants {
            self.parsers.insert(port.identity().name.to_owned(), port);
        }
        self.manifests.insert(manifest.id, manifest);
        Ok(())
    }

    fn register_siem_scopes(
        &mut self,
        staged: &Self,
        manifest: &ModuleManifest,
        config: &ModuleConfig,
    ) -> Result<(), AppError> {
        for port in &staged.siems {
            let scope = staged
                .source_scopes
                .get(port.source_id())
                .cloned()
                .map_or_else(
                    || crate::SiemSourceScope::event_account(port.source_id(), manifest.id),
                    Ok,
                )?;
            if scope.module() != manifest.id {
                return Err(mapping_error());
            }
            let public = manifest
                .config
                .iter()
                .filter(|field| !field.secret)
                .filter_map(|field| config.value(field.name).map(|value| (field.name, value)))
                .collect::<BTreeMap<_, _>>();
            let canonical = serde_json::to_vec(&public).map_err(|_| mapping_error())?;
            self.source_scopes.insert(
                port.source_id().into(),
                scope.with_configuration_hash(sha256(&canonical)),
            );
        }
        Ok(())
    }

    fn validate_staged(&self, manifest: &ModuleManifest, staged: &Self) -> Result<(), AppError> {
        staged.validate_definition_variants(manifest)?;
        self.validate_mapping_registration(manifest, staged)?;
        let actual = staged.counts();
        for port in [
            ModulePort::Llm,
            ModulePort::Siem,
            ModulePort::Edr,
            ModulePort::CloudAudit,
            ModulePort::InternalIntel,
            ModulePort::ThreatIntel,
            ModulePort::EventParser,
            ModulePort::ObjectSource,
            ModulePort::SourceDecoder,
            ModulePort::SourceMapper,
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
        if staged.parser_variants.iter().any(|parser| {
            parser.parser_name() != manifest.id || self.parsers.contains_key(parser.identity().name)
        }) {
            return Err(AppError::Policy(
                "parser variant belongs to another module or duplicates an active parser".into(),
            ));
        }
        if staged
            .parser
            .as_ref()
            .is_some_and(|parser| parser.parser_name() != manifest.id)
        {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyModuleRegisteredUndeclaredPorts,
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
            || staged.object_sources.iter().any(|port| {
                self.object_sources
                    .iter()
                    .any(|prior| prior.source_id() == port.source_id())
            })
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

    pub fn add_parser(&mut self, port: Box<dyn LogParser>) -> Result<(), AppError> {
        if self.parser.is_some() {
            return Err(AppError::Fixed(
                crate::FixedAppError::PolicyDuplicateEventParser,
            ));
        }
        self.parser = Some(Arc::from(port));
        Ok(())
    }

    pub fn add_parser_variant(&mut self, port: Arc<dyn LogParser>) -> Result<(), AppError> {
        let identity = port.identity();
        let valid_name = !identity.name.is_empty()
            && identity.name.len() <= 64
            && identity
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid_name
            || identity.version.is_empty()
            || identity.version.len() > 128
            || self.parser_variants.len() >= 64
            || self
                .parser_variants
                .iter()
                .any(|previous| previous.identity().name == identity.name)
            || identity.name == port.parser_name()
        {
            return Err(AppError::Policy(
                "invalid or duplicate configured parser identity".into(),
            ));
        }
        self.parser_variants.push(port);
        Ok(())
    }

    /// Retain format recognition while refusing selection after a failed startup probe.
    /// The reason must be bounded, non-secret diagnostic text.
    pub fn mark_parser_unavailable(&mut self, id: &str, reason: String) -> Result<(), AppError> {
        if !self.parsers.contains_key(id) || reason.is_empty() || reason.len() > 512 {
            return Err(AppError::Policy(
                "invalid parser availability metadata".into(),
            ));
        }
        self.unavailable_parsers.insert(id.to_owned(), reason);
        Ok(())
    }

    pub fn parser_by_id(&self, id: &str) -> Result<Arc<dyn LogParser>, AppError> {
        self.parser_catalog().get(id)
    }

    #[must_use]
    pub fn detect_parser(&self, source_name: &str, sample: &[u8]) -> ParserChoice {
        self.parser_catalog().detect(source_name, sample)
    }

    #[must_use]
    pub fn parser_catalog(&self) -> ParserCatalog {
        ParserCatalog {
            parsers: self.parsers.clone(),
            unavailable: self.unavailable_parsers.clone(),
            source_selected: BTreeSet::new(),
            resolver: None,
        }
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

    pub fn add_object_source(&mut self, port: Box<dyn ObjectSource>) -> Result<(), AppError> {
        if self
            .object_sources
            .iter()
            .any(|prior| prior.source_id() == port.source_id())
        {
            return Err(AppError::Policy("duplicate object source".into()));
        }
        self.object_sources.push(port);
        Ok(())
    }

    pub fn object_source(&self, source_id: &str) -> Result<&dyn ObjectSource, AppError> {
        self.object_sources
            .iter()
            .find(|port| port.source_id() == source_id)
            .map(Box::as_ref)
            .ok_or_else(|| AppError::Policy("object source unavailable".into()))
    }

    pub fn llm(&self, id: &str) -> Result<&dyn LlmPort, AppError> {
        self.llms.get(id).map(Box::as_ref).ok_or(AppError::Fixed(
            crate::FixedAppError::ModelLLMModuleIsNotRegistered,
        ))
    }

    /// Bind non-secret effective scope metadata to a registered SIEM source.
    pub fn add_siem_scope(&mut self, scope: crate::SiemSourceScope) -> Result<(), AppError> {
        scope.validate()?;
        if !self
            .siems
            .iter()
            .any(|port| port.source_id() == scope.source())
            || self.source_scopes.contains_key(scope.source())
        {
            return Err(mapping_error());
        }
        self.source_scopes.insert(scope.source().into(), scope);
        Ok(())
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
        for port in &self.object_sources {
            engine = engine.with_object_source(port.as_ref())?;
        }
        engine.result_decoders.clone_from(&self.result_decoders);
        engine.source_scopes.extend(self.source_scopes.clone());
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
            (
                ModulePort::EventParser,
                usize::from(self.parser.is_some() || !self.parser_variants.is_empty()),
            ),
            (ModulePort::ObjectSource, self.object_sources.len()),
            (ModulePort::SourceDecoder, self.source_decoders.len()),
            (ModulePort::SourceMapper, self.source_mappers.len()),
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
