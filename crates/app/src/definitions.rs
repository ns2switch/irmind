use crate::{AppError, Engine, LogParser, hex, modules::ParserResolver, sha256};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

mod compiled;
pub(crate) mod history;
pub use compiled::{ApprovedDefinition, CompiledDefinition, definition_mapping_descriptor};
mod errors;
pub use errors::DefinitionError;
mod operations;
mod preview;

pub const MAX_DEFINITION_BYTES: usize = 65_536;
const PREFIX: &str = "parser-definition-v1:";

pub trait ParserDefinitionStore: Send + Sync {
    fn read_active(&self, id: &str) -> Result<Option<String>, AppError>;
    fn write_active(&self, id: &str, contents: &str) -> Result<(), AppError>;
    fn archive(&self, hash: &str, contents: &str) -> Result<(), AppError>;
    fn deactivate(&self, id: &str) -> Result<(), AppError>;
    fn names(&self) -> Result<Vec<String>, AppError>;
    fn clean_temporary(&self) -> Result<usize, AppError> {
        Ok(0)
    }
}

pub trait DefinitionCompiler: Send + Sync {
    fn compile(&self, contents: &str) -> Result<CompiledDefinition, AppError>;
}

#[derive(Clone, Debug)]
pub struct DefinitionStatus {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub active: bool,
    pub available: bool,
    pub description: String,
    pub warning: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    id: String,
    version: String,
    sha256: String,
    contents: String,
    active: bool,
    previous: Option<String>,
}

/// Verified installation history. Construction is restricted to application use cases.
#[derive(Clone, Default)]
pub struct ApprovedDefinitions {
    latest: BTreeMap<String, Arc<Snapshot>>,
    versions: BTreeMap<(String, String), Arc<Snapshot>>,
}

impl ApprovedDefinitions {
    pub fn load_active(
        &self,
        store: &dyn ParserDefinitionStore,
        compiler: &dyn DefinitionCompiler,
    ) -> (Vec<ApprovedDefinition>, Vec<DefinitionStatus>) {
        let mut active = Vec::new();
        let mut statuses = Vec::new();
        for snapshot in self.latest.values() {
            let loaded = Self::load_one(snapshot, store, compiler);
            if snapshot.active
                && let Ok(parser) = &loaded
            {
                active.push(ApprovedDefinition::new(parser.clone()));
            }
            statuses.push(DefinitionStatus {
                id: snapshot.id.clone(), version: snapshot.version.clone(), sha256: snapshot.sha256.clone(), active: snapshot.active,
                available: loaded.is_ok(), description: loaded.as_ref().map_or_else(|_| String::new(), |parser| parser.selector().description().to_owned()),
                warning: loaded.err().map(|_| "Definition file is missing, changed or invalid; restore the approved version.".into()),
            });
        }
        match store.names() {
        Ok(names) => {
            for id in names.into_iter().filter(|id| !self.latest.contains_key(id)) {
                statuses.push(DefinitionStatus {
                    id,
                    version: String::new(),
                    sha256: String::new(),
                    active: false,
                    available: false,
                    description: String::new(),
                    warning: Some(
                        "Unsigned definition is disabled; review it before installation.".into(),
                    ),
                });
            }
        }
        Err(_) => statuses.push(DefinitionStatus {
            id: "definition-storage".into(), version: String::new(), sha256: String::new(), active: false, available: false, description: String::new(), warning: Some("Cannot inspect parser definitions; check the private data directory permissions.".into()),
        }),
        }
        (active, statuses)
    }

    fn load_one(
        snapshot: &Snapshot,
        store: &dyn ParserDefinitionStore,
        compiler: &dyn DefinitionCompiler,
    ) -> Result<CompiledDefinition, AppError> {
        let contents = if snapshot.active {
            store.read_active(&snapshot.id)?.ok_or_else(invalid)?
        } else {
            snapshot.contents.clone()
        };
        if contents != snapshot.contents {
            return Err(invalid());
        }
        compile_snapshot(snapshot, compiler)
    }

    #[must_use]
    pub fn resolver(&self, compiler: Arc<dyn DefinitionCompiler>) -> Arc<dyn ParserResolver> {
        Arc::new(ArchiveResolver {
            approved: self.clone(),
            compiler,
        })
    }
}

struct ArchiveResolver {
    approved: ApprovedDefinitions,
    compiler: Arc<dyn DefinitionCompiler>,
}
impl ParserResolver for ArchiveResolver {
    fn resolve(&self, id: &str, version: &str) -> Result<Arc<dyn LogParser>, AppError> {
        let snapshot = self
            .approved
            .versions
            .get(&(id.to_owned(), version.to_owned()))
            .ok_or(AppError::Fixed(crate::FixedAppError::Definition(
                DefinitionError::VersionUnavailable,
            )))?;
        compile_snapshot(snapshot, self.compiler.as_ref())
            .map(|compiled| Arc::clone(compiled.selector()))
    }
}

fn compile_snapshot(
    snapshot: &Snapshot,
    compiler: &dyn DefinitionCompiler,
) -> Result<CompiledDefinition, AppError> {
    validate_snapshot(snapshot)?;
    let parser = compiler.compile(&snapshot.contents)?;
    if parser.selector().identity().name != snapshot.id
        || parser.selector().identity().version != snapshot.version
        || parser.definition_hash() != snapshot.sha256
    {
        return Err(invalid());
    }
    Ok(parser)
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), AppError> {
    if !valid_id(&snapshot.id)
        || snapshot.version.is_empty()
        || snapshot.version.len() > 128
        || !snapshot.version.is_ascii()
        || snapshot.contents.len() > MAX_DEFINITION_BYTES
        || hex(&sha256(snapshot.contents.as_bytes())) != snapshot.sha256
        || !snapshot.version.ends_with(&snapshot.sha256)
        || snapshot
            .previous
            .as_ref()
            .is_some_and(|hash| !valid_hash(hash))
    {
        return Err(invalid());
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn invalid() -> AppError {
    AppError::Fixed(crate::FixedAppError::Definition(
        DefinitionError::InvalidSnapshot,
    ))
}
