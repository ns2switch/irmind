//! Static registration metadata. Native mappers have no access to configuration.
use crate::SourceMapper;
use irmind_domain::Tool;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ModulePort {
    Llm,
    Siem,
    Edr,
    CloudAudit,
    InternalIntel,
    ThreatIntel,
    EventParser,
    ObjectSource,
    SourceDecoder,
    SourceMapper,
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

pub trait MappingModule: SourceMapper {
    fn module_manifest(&self) -> &'static ModuleManifest;
}
