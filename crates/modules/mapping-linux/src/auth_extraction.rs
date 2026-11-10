//! Search-only extraction for account-management and cron messages, never classification.
use super::{
    Arc, EvidenceHash, MappingError, MappingManifest, MappingOutput, Module, ModuleConfig,
    ModuleManifest, ModulePort, ModuleRegistry, SourceMapper, SourceRecordV1,
};
use irmind_app::{
    GraphRecord, IndexedGraphRecord, PartitionProfile,
    source_mapping::{
        MappingDiagnostic, MappingIdentityV1, MappingPartition, MappingProvenance,
        SourceDiscriminator, SourceSelector, SourceValue, json::render_source_fields,
    },
};
use std::collections::{BTreeMap, BTreeSet};
const BUILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/native-mapping-manifest.bin"));
pub struct AuthExtractionMapping {
    manifest: MappingManifest,
}
impl AuthExtractionMapping {
    pub fn new() -> Result<Self, MappingError> {
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(BUILD));
        let identity = MappingIdentityV1::try_new(
            "mapping-linux-auth-extraction",
            &format!("extraction-v1-{}", digest.as_str()),
            irmind_domain::COMMON_EVENT_V1,
            digest,
        )
        .map_err(|_| invalid())?;
        let selectors = ["useradd", "usermod", "cron", "crond", "CRON"]
            .into_iter()
            .map(|app| {
                SourceSelector::try_new(
                    "parser-linux",
                    BTreeSet::from(["linux-source-v1".into()]),
                    Some(("linux".into(), "linux-source-v1".into())),
                    BTreeMap::from([(SourceDiscriminator::Dataset, app.into())]),
                    vec![],
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            manifest: MappingManifest::try_new(
                identity,
                selectors,
                MappingProvenance::NativeBuild {
                    manifest: BUILD.to_vec(),
                },
                true,
            )?,
        })
    }
}
impl SourceMapper for AuthExtractionMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.manifest
    }
    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        if !self.manifest.selectors().iter().any(|s| s.matches(source)) {
            return Err(invalid());
        }
        let fields = source.fields().field("syslog").ok_or_else(invalid)?;
        let host = text(fields, "hostname").ok_or_else(invalid)?;
        let app = text(fields, "appname").ok_or_else(invalid)?;
        if source
            .format()
            .discriminators()
            .get(&SourceDiscriminator::Dataset)
            .map(String::as_str)
            != Some(app)
        {
            return Err(invalid());
        }
        let message = text(fields, "msg").ok_or_else(invalid)?;
        let (event, user, command) = extracted(app, message)?;
        let pid = text(fields, "procid");
        let entities = entities(host, app, pid, user, command);
        let projection = SourceValue::object(vec![
            ("attributes".into(), source.fields().clone()),
            ("host".into(), SourceValue::Text(host.into())),
            (
                "user".into(),
                user.map_or(SourceValue::Null, |v| SourceValue::Text(v.into())),
            ),
            (
                "command_line".into(),
                command.map_or(SourceValue::Null, |v| SourceValue::Text(v.into())),
            ),
        ])
        .map_err(|_| invalid())?;
        let record = GraphRecord {
            index: usize::try_from(source.origin().record()).map_err(|_| invalid())?,
            at: source
                .timestamp()
                .map(irmind_app::IndexedTime::to_rfc3339)
                .unwrap_or_default(),
            event: event.into(),
            text: render_source_fields(&projection).map_err(|_| invalid())?,
            entities,
            relations: vec![],
        };
        MappingOutput::try_new(
            source,
            IndexedGraphRecord {
                record,
                time: source.timestamp(),
                source_offset: source.origin().offset(),
            },
            MappingOutput::unclassified_common(source)?,
            MappingPartition::try_new(PartitionProfile::EndpointHost, "", "", host)?,
            vec![MappingDiagnostic::Unclassified],
        )
    }
}
fn extracted<'a>(
    app: &str,
    message: &'a str,
) -> Result<(&'static str, Option<&'a str>, Option<&'a str>), MappingError> {
    Ok(match app {
        "useradd" => (
            "user_add",
            message
                .split_once("name=")
                .and_then(|(_, r)| r.split([',', ' ']).next()),
            None,
        ),
        "usermod" => (
            "user_modify",
            message
                .split_once('\'')
                .and_then(|(_, r)| r.split_once('\''))
                .map(|(user, _)| user),
            None,
        ),
        "cron" | "crond" | "CRON" => (
            "cron_command",
            message
                .strip_prefix('(')
                .and_then(|r| r.split_once(')'))
                .map(|(user, _)| user),
            message
                .split_once("CMD (")
                .and_then(|(_, r)| r.strip_suffix(')')),
        ),
        _ => return Err(invalid()),
    })
}
fn text<'a>(value: &'a SourceValue, key: &str) -> Option<&'a str> {
    value.field(key).and_then(SourceValue::as_text)
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
static MODULE: ModuleManifest = ModuleManifest {
    id: "mapping-linux-auth-extraction",
    version: "0.1.0",
    ports: &[ModulePort::SourceMapper],
    tools: &[],
    config: &[],
};
impl Module for AuthExtractionMapping {
    fn manifest(&self) -> &'static ModuleManifest {
        &MODULE
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        _: &ModuleConfig,
    ) -> Result<(), irmind_app::AppError> {
        registry.add_source_mapper(Arc::new(*self))
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

fn entities(
    host: &str,
    app: &str,
    pid: Option<&str>,
    user: Option<&str>,
    command: Option<&str>,
) -> Vec<(String, String)> {
    let mut entities = [
        ("host", Some(host)),
        ("user", user),
        ("process", Some(app)),
        ("pid", pid),
        ("command_line", command),
    ]
    .into_iter()
    .filter_map(|(kind, value)| {
        value
            .filter(|v| !v.is_empty() && v.len() <= 4096)
            .map(|v| (kind.into(), v.into()))
    })
    .collect::<Vec<_>>();
    entities.sort();
    entities.dedup();
    entities
}
