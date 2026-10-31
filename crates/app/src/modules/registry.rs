use super::config::{Module, ModuleConfig, ModuleManifest, ModulePort};
use crate::{
    AppError, CancellationToken, CloudAuditPort, EdrPort, Engine, EventParser, GraphRecord,
    InternalIntelPort, LlmPort, LogParser, ObjectSource, ParserConfidence, SiemPort, SignedEntry,
    StreamingEventParser, Tainted, ThreatIntelPort, hex, sha256,
};
use irmind_domain::{AuditEventKind, SourceManifestV1, SourceManifestV2, Tool};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedParser {
    pub id: &'static str,
    pub confidence: ParserConfidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParserChoice {
    Auto(DetectedParser),
    NeedsAnalyst(Vec<DetectedParser>),
    Unsupported,
}

#[derive(Clone, Default)]
pub struct ParserCatalog {
    parsers: BTreeMap<&'static str, Arc<dyn LogParser>>,
}

impl ParserCatalog {
    #[must_use]
    pub fn detect(&self, source_name: &str, sample: &[u8]) -> ParserChoice {
        let sample = &sample[..sample.len().min(64 * 1024)];
        let candidates = self
            .parsers
            .iter()
            .filter_map(|(id, parser)| {
                parser
                    .detect(source_name, sample)
                    .map(|confidence| DetectedParser { id, confidence })
            })
            .collect::<Vec<_>>();
        choose_parser(candidates)
    }

    pub fn get(&self, id: &str) -> Result<Arc<dyn LogParser>, AppError> {
        self.parsers.get(id).cloned().ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyEventParserIsNotRegistered,
        ))
    }

    #[must_use]
    pub fn available(&self) -> Vec<(&'static str, &'static str)> {
        self.parsers
            .iter()
            .map(|(id, parser)| (*id, parser.version()))
            .collect()
    }

    /// Rebuild a case with exactly the parser and version recorded for each
    /// source. Old V1 manifests used the JSON parser exclusively.
    pub fn rebuild_router(&self, entries: &[SignedEntry]) -> Result<RebuildParser, AppError> {
        let mut sources = BTreeMap::new();
        for entry in entries {
            let (source, id, version) = match entry.kind {
                AuditEventKind::SourceManifestV1 => {
                    let manifest = SourceManifestV1::decode(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    (manifest.source, "parser-json", "json-stream-v2")
                }
                AuditEventKind::SourceManifestV2 => {
                    let manifest = SourceManifestV2::decode(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    let parser = self.get(&manifest.parser_id)?;
                    if parser.streaming_version() != manifest.parser_version {
                        return Err(AppError::Policy(
                            "signed parser version is unavailable".into(),
                        ));
                    }
                    let id = parser.parser_name();
                    let version = parser.streaming_version();
                    (manifest.source.source, id, version)
                }
                _ => continue,
            };
            let parser = self.get(id)?;
            if parser.streaming_version() != version || sources.insert(source, parser).is_some() {
                return Err(AppError::InvalidChain(entry.seq));
            }
        }
        Ok(RebuildParser { sources })
    }
}

pub struct RebuildParser {
    sources: BTreeMap<String, Arc<dyn LogParser>>,
}

impl StreamingEventParser for RebuildParser {
    fn streaming_version(&self) -> &'static str {
        "signed-parser-router-v1"
    }
    fn parser_name(&self) -> &'static str {
        "signed-parser-router"
    }

    fn version_for_source(&self, source: &str) -> Result<&'static str, AppError> {
        self.sources
            .get(source)
            .map(|parser| parser.streaming_version())
            .ok_or(AppError::Policy(
                "source has no signed parser selection".into(),
            ))
    }

    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        evidence_hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        self.sources
            .get(source)
            .ok_or(AppError::Policy(
                "source has no signed parser selection".into(),
            ))?
            .parse_reader(source, reader, evidence_hash, cancel, emit)
    }
}

fn choose_parser(mut candidates: Vec<DetectedParser>) -> ParserChoice {
    candidates.sort_by(|left, right| {
        right
            .confidence
            .cmp(&left.confidence)
            .then_with(|| left.id.cmp(right.id))
    });
    let Some(first) = candidates.first() else {
        return ParserChoice::Unsupported;
    };
    if first.confidence.is_high()
        && candidates
            .get(1)
            .is_none_or(|next| next.confidence < first.confidence)
    {
        ParserChoice::Auto(first.clone())
    } else {
        ParserChoice::NeedsAnalyst(candidates)
    }
}

#[derive(Default)]
pub struct ModuleRegistry {
    manifests: BTreeMap<&'static str, &'static ModuleManifest>,
    llms: BTreeMap<&'static str, Box<dyn LlmPort>>,
    parser: Option<Arc<dyn LogParser>>,
    parsers: BTreeMap<&'static str, Arc<dyn LogParser>>,
    siems: Vec<Box<dyn SiemPort>>,
    edrs: Vec<Box<dyn EdrPort>>,
    cloud_audits: Vec<Box<dyn CloudAuditPort>>,
    internal_intel: Vec<Box<dyn InternalIntelPort>>,
    threat_intel: Option<Box<dyn ThreatIntelPort>>,
    object_sources: Vec<Box<dyn ObjectSource>>,
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
        self.object_sources.extend(staged.object_sources);
        if let Some(port) = staged.threat_intel {
            self.threat_intel = Some(port);
        }
        if let Some(port) = staged.parser {
            if self.parser.is_none() {
                self.parser = Some(Arc::clone(&port));
            }
            self.parsers.insert(manifest.id, port);
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
            ModulePort::ObjectSource,
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

    pub fn parser(&self) -> Result<Arc<dyn EventParser>, AppError> {
        self.parser
            .clone()
            .map(|parser| parser as Arc<dyn EventParser>)
            .ok_or(AppError::Fixed(
                crate::FixedAppError::PolicyEventParserIsNotRegistered,
            ))
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
            (ModulePort::ObjectSource, self.object_sources.len()),
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod parser_choice_tests {
    use super::{DetectedParser, ParserChoice, ParserConfidence, choose_parser};

    fn candidate(id: &'static str, confidence: u8) -> DetectedParser {
        DetectedParser {
            id,
            confidence: ParserConfidence::new(confidence).unwrap(),
        }
    }

    #[test]
    fn high_unique_candidate_is_automatic() {
        assert_eq!(
            choose_parser(vec![candidate("json", 90)]),
            ParserChoice::Auto(candidate("json", 90))
        );
    }

    #[test]
    fn ties_and_low_confidence_need_analyst() {
        assert!(matches!(
            choose_parser(vec![candidate("json", 90), candidate("ecs", 90)]),
            ParserChoice::NeedsAnalyst(_)
        ));
        assert!(matches!(
            choose_parser(vec![candidate("json", 45)]),
            ParserChoice::NeedsAnalyst(_)
        ));
    }

    #[test]
    fn no_match_is_unsupported() {
        assert_eq!(choose_parser(Vec::new()), ParserChoice::Unsupported);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod parser_router_tests {
    use super::*;
    use irmind_domain::{EvidenceHash, ParserSelectionMode};

    struct FakeParser(&'static str, &'static str);

    impl EventParser for FakeParser {
        fn version(&self) -> &'static str {
            self.1
        }
        fn parse_each(
            &self,
            _: &str,
            _: &[u8],
            _: &CancellationToken,
            _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
        ) -> Result<usize, AppError> {
            Ok(0)
        }
    }
    impl StreamingEventParser for FakeParser {
        fn streaming_version(&self) -> &'static str {
            self.1
        }
        fn parser_name(&self) -> &'static str {
            self.0
        }
        fn parse_reader(
            &self,
            _: &str,
            _: &mut dyn Read,
            _: [u8; 32],
            _: &CancellationToken,
            _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
        ) -> Result<usize, AppError> {
            Ok(0)
        }
    }
    impl LogParser for FakeParser {
        fn detect(&self, _: &str, _: &[u8]) -> Option<ParserConfidence> {
            None
        }
    }

    fn entry(kind: AuditEventKind, payload: String) -> SignedEntry {
        SignedEntry {
            seq: 1,
            case_id: "00000000-0000-0000-0000-000000000001".into(),
            at: 0,
            actor: irmind_domain::Actor::Analyst,
            origin: "system".into(),
            kind,
            payload,
            evidence: None,
            prev: [0; 32],
            hash: [0; 32],
            sig: Vec::new(),
            public_key: Vec::new(),
        }
    }

    #[test]
    fn rebuild_routes_each_source_to_its_signed_parser_version() {
        let mut catalog = ParserCatalog::default();
        catalog.parsers.insert(
            "parser-json",
            Arc::new(FakeParser("parser-json", "json-stream-v2")),
        );
        catalog.parsers.insert(
            "parser-syslog",
            Arc::new(FakeParser("parser-syslog", "syslog-v1")),
        );
        let source = SourceManifestV1 {
            source: "system.log".into(),
            size: 1,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: EvidenceHash::parse(&"a".repeat(64)).unwrap(),
            copied: false,
        };
        let selection = SourceManifestV2 {
            source,
            parser_id: "parser-syslog".into(),
            parser_version: "syslog-v1".into(),
            confidence: 95,
            selection: ParserSelectionMode::Automatic,
            timestamp_context: None,
            rejected_records: 0,
            rejected_sample: Vec::new(),
        };
        let router = catalog
            .rebuild_router(&[entry(
                AuditEventKind::SourceManifestV2,
                selection.encode().unwrap(),
            )])
            .unwrap();
        assert_eq!(
            router.version_for_source("system.log").unwrap(),
            "syslog-v1"
        );
        assert!(router.version_for_source("other.log").is_err());
    }
}
