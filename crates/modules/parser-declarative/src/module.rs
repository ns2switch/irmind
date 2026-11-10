use crate::{AppError, error};
use irmind_app::{
    CancellationToken, EventParser, GraphRecord, LogParser, ParserConfidence, StreamingEventParser,
    modules::{Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::Tainted;
use std::io::Read;

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-declarative",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[],
};

/// Definitions have already been compiled from approved bytes by the composition root.
pub struct DeclarativeModule {
    active: Vec<irmind_app::ApprovedDefinition>,
}

impl DeclarativeModule {
    pub fn new(active: Vec<irmind_app::ApprovedDefinition>) -> Result<Self, AppError> {
        if active.len() > 64
            || active
                .iter()
                .any(|parser| parser.compiled().selector().parser_name() != MANIFEST.id)
        {
            return Err(error("invalid declarative module definitions"));
        }
        Ok(Self { active })
    }
}

impl Module for DeclarativeModule {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), AppError> {
        registry.add_parser(Box::new(Unconfigured))?;
        for parser in self.active {
            registry.add_approved_definition(parser)?;
        }
        Ok(())
    }
}

struct Unconfigured;
impl EventParser for Unconfigured {
    fn version(&self) -> &'static str {
        "declarative-v2"
    }
    fn parse_each(
        &self,
        _: &str,
        _: &[u8],
        _: &CancellationToken,
        _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Err(error(
            "select an approved declarative definition before parsing",
        ))
    }
}
impl StreamingEventParser for Unconfigured {
    fn parser_name(&self) -> &'static str {
        "parser-declarative"
    }
    fn streaming_version(&self) -> &'static str {
        "declarative-v2"
    }
    fn parse_reader(
        &self,
        _: &str,
        _: &mut dyn Read,
        _: [u8; 32],
        _: &CancellationToken,
        _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Err(error(
            "select an approved declarative definition before parsing",
        ))
    }
}
impl LogParser for Unconfigured {
    fn detect(&self, _: &str, _: &[u8]) -> Option<ParserConfidence> {
        None
    }
}

pub struct DeclarativeCompiler;
impl irmind_app::DefinitionCompiler for DeclarativeCompiler {
    fn compile(&self, contents: &str) -> Result<irmind_app::CompiledDefinition, AppError> {
        crate::pipeline::compile(contents)
    }
}
