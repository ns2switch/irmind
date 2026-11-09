//! A finite data grammar, not an expression or scripting language.
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Definition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    pub id: String,
    pub version: String,
    pub target_schema: String,
    pub source_contract: String,
    pub parser: String,
    pub parser_versions: Vec<String>,
    pub format: Option<String>,
    pub format_version: Option<String>,
    pub dataset: Option<String>,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub native_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub when: Vec<Condition>,
    pub action: Option<Vec<String>>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub partition: Partition,
}
impl Definition {
    pub(super) fn interpreter(
        &self,
    ) -> Result<&'static str, irmind_app::source_mapping::MappingError> {
        match self.interpreter.as_deref() {
            None | Some("irmind-mapping-tables-v1")
                if self.when.is_empty()
                    && self
                        .fields
                        .iter()
                        .chain(self.rules.iter().flat_map(|r| &r.fields))
                        .all(|field| field.omit_text.is_empty()) =>
            {
                Ok("irmind-mapping-tables-v1")
            }
            Some("irmind-mapping-tables-v2") => Ok("irmind-mapping-tables-v2"),
            _ => Err(irmind_app::source_mapping::MappingError::InvalidDefinition),
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rule {
    #[serde(default)]
    pub when: Vec<Condition>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub types: Vec<String>,
    #[serde(default = "unknown")]
    pub outcome: String,
    #[serde(default = "event")]
    pub kind: String,
    #[serde(default)]
    pub fields: Vec<Field>,
}
fn unknown() -> String {
    "unknown".into()
}
fn event() -> String {
    "event".into()
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Condition {
    pub path: Vec<String>,
    pub predicate: Predicate,
}
#[derive(Deserialize, Serialize)]
#[serde(
    tag = "op",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Predicate {
    Missing,
    Null,
    Present,
    Text(String),
    Boolean(bool),
    Number(String),
    IntegerInterval { first: i64, last: i64 },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Field {
    pub source: Vec<String>,
    pub target: String,
    #[serde(default)]
    pub conversion: Conversion,
    pub observation: Option<Observation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omit_text: Vec<String>,
}
#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Conversion {
    #[default]
    Copy,
    Decimal,
    Hex,
    Ip,
    Domain,
    Md5,
    Sha1,
    Sha256,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    pub kind: String,
    pub role: String,
    #[serde(default)]
    pub scope: Scope,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    content = "path",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum Scope {
    #[default]
    SourceRecord,
    Global,
    Host(Vec<String>),
    Account(Vec<String>),
}
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Partition {
    pub host: Option<Vec<String>>,
    pub account: Option<Vec<String>>,
    pub region: Option<Vec<String>>,
}

impl Field {
    pub(super) fn operation_budget(&self) -> usize {
        33 + self.omit_text.len()
    }
}
