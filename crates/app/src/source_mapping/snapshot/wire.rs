use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub contract: String,
    pub identity: Identity,
    pub selectors: Vec<Selector>,
    pub provenance: Provenance,
    pub compatibility_projection: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub id: String,
    pub version: String,
    pub target: String,
    pub implementation: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selector {
    pub parser: String,
    pub versions: Vec<String>,
    pub format: Option<(String, String)>,
    pub discriminators: BTreeMap<u8, String>,
    pub conditions: Vec<Condition>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Condition {
    pub path: Vec<Segment>,
    pub predicate: Predicate,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub(super) enum Segment {
    Key(String),
    Index(u16),
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub(super) enum Predicate {
    Missing,
    Null,
    Present,
    Exact(Scalar),
    IntegerInterval { first: String, last: String },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub(super) enum Scalar {
    Boolean(bool),
    Number(String),
    Text(String),
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(super) enum Provenance {
    NativeBuild {
        manifest: String,
    },
    BundledDefinition {
        canonical: String,
        interpreter: String,
    },
    InstalledDefinition {
        canonical: String,
        interpreter: String,
        operation: String,
    },
}
