use super::{
    QueryOperator, QueryResultKind, QueryTime, SourceQueryError, SourceQueryLimits, SourceQueryV1,
    canonical_query_json,
    types::{digest, id, text},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryAccounting {
    ScanPriced,
    AnalyticsNoQueryCharge,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryBinding {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub value: Value,
}
impl QueryBinding {
    pub fn validate(&self) -> Result<(), SourceQueryError> {
        if !id(&self.name) {
            return Err(SourceQueryError::Invalid);
        }
        let valid = match self.kind.as_str() {
            "text" => self.value.as_str().is_some_and(|s| text(s, 256)),
            "u64" => self.value.is_u64(),
            "bool" => self.value.is_boolean(),
            "ip" => self
                .value
                .as_str()
                .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok()),
            "timestamp" => self
                .value
                .as_str()
                .is_some_and(|s| QueryTime::parse(s).is_ok()),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(SourceQueryError::Invalid)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "SourceWire")]
pub struct ResolvedQuerySourceV1 {
    module: String,
    module_version: String,
    id: String,
    owner: String,
    location: String,
    dataset: String,
    table: String,
    partitions: Vec<QueryBinding>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceWire {
    module: String,
    module_version: String,
    id: String,
    owner: String,
    location: String,
    dataset: String,
    table: String,
    partitions: Vec<QueryBinding>,
}
impl TryFrom<SourceWire> for ResolvedQuerySourceV1 {
    type Error = SourceQueryError;
    fn try_from(w: SourceWire) -> Result<Self, Self::Error> {
        if !matches!(
            w.module.as_str(),
            "query-athena" | "query-bigquery" | "query-azure-log-analytics"
        ) || !id(&w.module_version)
            || !id(&w.id)
            || !id(&w.dataset)
            || !native_identifier(&w.owner)
            || !native_identifier(&w.location)
            || !native_identifier(&w.table)
            || w.partitions.len() > 2048
        {
            return Err(SourceQueryError::Invalid);
        }
        for p in &w.partitions {
            p.validate()?;
        }
        let keys = w
            .partitions
            .iter()
            .map(canonical_query_json)
            .collect::<Result<Vec<_>, _>>()?;
        if keys.windows(2).any(|p| p[0] >= p[1]) {
            return Err(SourceQueryError::Invalid);
        }
        Ok(Self {
            module: w.module,
            module_version: w.module_version,
            id: w.id,
            owner: w.owner,
            location: w.location,
            dataset: w.dataset,
            table: w.table,
            partitions: w.partitions,
        })
    }
}
pub fn native_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}
impl ResolvedQuerySourceV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        super::canonical::checked_value(bytes)?;
        serde_json::from_slice(bytes).map_err(|_| SourceQueryError::Invalid)
    }
    pub fn module(&self) -> &str {
        &self.module
    }
    pub fn module_version(&self) -> &str {
        &self.module_version
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn location(&self) -> &str {
        &self.location
    }
    pub fn dataset(&self) -> &str {
        &self.dataset
    }
    pub fn table(&self) -> &str {
        &self.table
    }
    pub fn partitions(&self) -> &[QueryBinding] {
        &self.partitions
    }
    pub fn admits(&self, query: &SourceQueryV1, scope: &irmind_domain::CaseScope) -> bool {
        if self.id != query.source() || self.dataset != query.dataset() {
            return false;
        }
        // Existing scope timestamps use whole seconds; compare exact instants below.
        let irmind_domain::CaseScope::Remote {
            sources,
            accounts,
            projects,
            from,
            to,
            ..
        } = scope
        else {
            return false;
        };
        let allowed = if self.module == "query-bigquery" {
            projects.contains(&self.owner)
        } else {
            accounts.contains(&self.owner)
        };
        sources.contains(&self.id)
            && allowed
            && QueryTime::parse(from)
                .ok()
                .zip(QueryTime::parse(to).ok())
                .is_some_and(|(a, b)| {
                    query.from().as_str() >= a.as_str() && query.to().as_str() <= b.as_str()
                })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryTranslatorIdentity {
    pub id: String,
    pub version: String,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "CompiledWire")]
pub struct CompiledSourceQueryV1 {
    text: String,
    bindings: Vec<QueryBinding>,
    translator: QueryTranslatorIdentity,
    required_fields: Vec<String>,
    order: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledWire {
    text: String,
    bindings: Vec<QueryBinding>,
    translator: QueryTranslatorIdentity,
    required_fields: Vec<String>,
    order: Vec<String>,
}
impl TryFrom<CompiledWire> for CompiledSourceQueryV1 {
    type Error = SourceQueryError;
    fn try_from(w: CompiledWire) -> Result<Self, Self::Error> {
        if w.text.is_empty()
            || w.text.len() > 32768
            || w.text.contains('\0')
            || w.bindings.len() > 1024
            || w.required_fields.len() > 128
            || w.order.is_empty()
            || w.order.len() > 8
            || !id(&w.translator.id)
            || !text(&w.translator.version, 128)
            || !digest(&w.translator.sha256)
        {
            return Err(SourceQueryError::Invalid);
        }
        let mut names = std::collections::BTreeSet::new();
        for b in &w.bindings {
            b.validate()?;
            if !names.insert(&b.name) {
                return Err(SourceQueryError::Invalid);
            }
        }
        if w.required_fields
            .iter()
            .chain(&w.order)
            .any(|f| !native_identifier(f))
            || w.required_fields.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(Self {
            text: w.text,
            bindings: w.bindings,
            translator: w.translator,
            required_fields: w.required_fields,
            order: w.order,
        })
    }
}
impl CompiledSourceQueryV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceQueryError> {
        super::canonical::checked_value(bytes)?;
        serde_json::from_slice(bytes).map_err(|_| SourceQueryError::Invalid)
    }
    pub fn text(&self) -> &str {
        &self.text
    }
    pub fn bindings(&self) -> &[QueryBinding] {
        &self.bindings
    }
    pub fn translator(&self) -> &QueryTranslatorIdentity {
        &self.translator
    }
    pub fn required_fields(&self) -> &[String] {
        &self.required_fields
    }
    pub fn order(&self) -> &[String] {
        &self.order
    }
}
#[derive(Clone, Debug)]
pub struct SourceQueryModuleV1 {
    pub id: String,
    pub version: String,
    pub datasets: Vec<String>,
    pub fields: Vec<String>,
    pub operators: Vec<QueryOperator>,
    pub result_kinds: Vec<QueryResultKind>,
    pub accounting: QueryAccounting,
    pub recoverable_submit: bool,
    pub cancellation: bool,
    pub api_version: String,
}
impl SourceQueryModuleV1 {
    pub fn validate(&self) -> Result<(), SourceQueryError> {
        if !matches!(
            self.id.as_str(),
            "query-athena" | "query-bigquery" | "query-azure-log-analytics"
        ) || !id(&self.version)
            || self.datasets.is_empty()
            || self.datasets.len() > 64
            || self.datasets.iter().any(|value| !id(value))
            || self.fields.len() > 128
            || self.operators.len() > 5
            || self.result_kinds.is_empty()
            || self.result_kinds.len() > 4
            || !text(&self.api_version, 64)
            || self.fields.iter().any(|s| !text(s, 128))
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(())
    }
}
/// Shared pure compiler gate. A backend must translate every accepted predicate exactly.
pub fn check_query_capabilities(
    query: &SourceQueryV1,
    source: &ResolvedQuerySourceV1,
    module: &SourceQueryModuleV1,
    limits: &SourceQueryLimits,
) -> Result<(), SourceQueryError> {
    module.validate()?;
    limits.validate()?;
    if query.source() != source.id()
        || query.dataset() != source.dataset()
        || source.module() != module.id
        || source.module_version() != module.version
    {
        return Err(SourceQueryError::Scope);
    }
    if !query.interval_within(limits.interval_seconds)? || query.limit() > limits.rows {
        return Err(SourceQueryError::Limit);
    }
    if !module
        .datasets
        .iter()
        .any(|dataset| dataset == query.dataset())
        || !module.result_kinds.contains(&query.result())
        || query
            .fields()
            .iter()
            .chain(query.filters().iter().map(|p| &p.field))
            .any(|f| !module.fields.contains(f))
        || query
            .filters()
            .iter()
            .any(|p| !module.operators.contains(&p.op))
    {
        return Err(SourceQueryError::Unsupported);
    }
    Ok(())
}
