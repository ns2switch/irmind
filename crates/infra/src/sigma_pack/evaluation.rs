//! Evaluate admitted Sigma predicates on authenticated common and original fields.
use super::field_table::{
    SigmaBindingType, SigmaConversion, SigmaEventFilter, SigmaLiteral, SigmaNullPolicy,
    SigmaSourceVariant,
};
use irmind_app::{
    AppError, CancellationToken,
    cluster_audit::{self, AuditExactField},
    v10_proofs::{SigmaCoverageV1, SigmaRuleKeyV1, SigmaRunStatusV1},
};
use irmind_domain::{CommonEventV1, CommonField, CommonValue, EvidenceHash};
use irmind_sigma::{RuleValue, SigmaField, SigmaFieldKind, SigmaProgram, SigmaScalar, admit_rule};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

mod parquet_scan;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod benchmark;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod coverage_fixtures;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod exact_fields;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod family_measurements;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod windows;
const MAX_RECORD_BYTES: usize = 64 * 1024;
pub(super) const MAX_MATCHES: usize = 100_000;

pub struct SigmaVariantPrograms<'a> {
    variant: &'a SigmaSourceVariant,
    eligible: Vec<(SigmaRuleKeyV1, SigmaProgram)>,
    skipped: Vec<(SigmaRuleKeyV1, SigmaCoverageV1)>,
    needs_original: bool,
    used_fields: BTreeSet<&'a str>,
    exact_cluster_field: Option<AuditExactField>,
    uses_exact: Vec<bool>,
}

pub struct SigmaEvaluation<'a> {
    programs: &'a SigmaVariantPrograms<'a>,
    remaining_units: u64,
    reserved_units: u64,
    rules_evaluated: Vec<bool>,
    matches: usize,
    match_limit: usize,
    status: SigmaRunStatusV1,
    pub(super) unavailable_by_source: BTreeMap<EvidenceHash, u64>,
    pub(super) indeterminate_by_rule: BTreeMap<SigmaRuleKeyV1, u64>,
}

impl<'a> SigmaVariantPrograms<'a> {
    /// Compile one enrolled source class. The caller authenticates the original
    /// source and mapping identities before presenting its rows.
    pub fn compile(
        variant: &'a SigmaSourceVariant,
        rules: impl IntoIterator<Item = (SigmaRuleKeyV1, &'a [u8])>,
    ) -> Result<Self, AppError> {
        let bindings = variant
            .fields
            .iter()
            .map(|binding| (binding.name.clone(), field_kind(binding.value_type)))
            .collect();
        let exact_cluster_field = variant.exact_cluster_field();
        let exact_binding = exact_cluster_field.and_then(|field| {
            variant.fields.iter().find(|binding| {
                binding.path.as_deref().is_some_and(|path| {
                    path.first().is_some_and(|key| key == "original")
                        && path[1..]
                            .iter()
                            .map(String::as_str)
                            .eq(field.path().iter().copied())
                })
            })
        });
        let mut programs = Self {
            variant,
            eligible: Vec::new(),
            skipped: Vec::new(),
            needs_original: exact_cluster_field.is_some()
                || variant.events.iter().any(|filter| filter.path.is_some()),
            used_fields: BTreeSet::new(),
            exact_cluster_field,
            uses_exact: Vec::new(),
        };
        for (key, raw) in rules {
            if programs.eligible.len() + programs.skipped.len() == 4096
                || irmind_app::sha256(raw) != key.sha256
            {
                return Err(invalid());
            }
            let rule = admit_rule(raw).map_err(|_| invalid())?;
            if !covers(&rule, variant) {
                programs
                    .skipped
                    .push((key, SigmaCoverageV1::UnsupportedLogsource));
                continue;
            }
            match SigmaProgram::compile(&rule, &bindings) {
                Ok(program) => {
                    let mut fields = BTreeSet::new();
                    if let Some(RuleValue::Mapping(detection)) = rule.fields().get("detection") {
                        for node in detection.values() {
                            collect_fields(node, variant, &mut fields);
                        }
                    }
                    programs.uses_exact.push(
                        exact_binding.is_some_and(|binding| fields.contains(binding.name.as_str())),
                    );
                    programs.used_fields.extend(fields);
                    programs.eligible.push((key, program));
                }
                Err(irmind_sigma::CompileError::MissingBinding) => {
                    programs
                        .skipped
                        .push((key, SigmaCoverageV1::UnsupportedField));
                }
                Err(_) => programs
                    .skipped
                    .push((key, SigmaCoverageV1::UnsupportedRule)),
            }
        }
        programs.needs_original |= variant.fields.iter().any(|binding| {
            binding.path.is_some() && programs.used_fields.contains(binding.name.as_str())
        });
        Ok(programs)
    }

    #[cfg(test)]
    pub fn start(&'a self, units: u64) -> SigmaEvaluation<'a> {
        self.start_with_match_limit(units, MAX_MATCHES)
    }

    pub(super) fn start_with_match_limit(
        &'a self,
        units: u64,
        match_limit: usize,
    ) -> SigmaEvaluation<'a> {
        SigmaEvaluation {
            programs: self,
            remaining_units: units,
            reserved_units: units,
            rules_evaluated: vec![false; self.eligible.len()],
            matches: 0,
            match_limit,
            status: SigmaRunStatusV1::Complete,
            unavailable_by_source: BTreeMap::new(),
            indeterminate_by_rule: BTreeMap::new(),
        }
    }

    pub const fn needs_original(&self) -> bool {
        self.needs_original
    }

    pub fn skipped(&self) -> &[(SigmaRuleKeyV1, SigmaCoverageV1)] {
        &self.skipped
    }

    pub fn eligible(&self) -> usize {
        self.eligible.len()
    }
}

impl SigmaEvaluation<'_> {
    /// Return false on a bounded stop. Matches already emitted remain partial.
    pub fn row(
        &mut self,
        common: &CommonEventV1,
        original_json: Option<&str>,
        cancel: &CancellationToken,
        mut matched: impl FnMut(&SigmaRuleKeyV1) -> Result<(), AppError>,
    ) -> Result<bool, AppError> {
        if cancel.is_cancelled() {
            self.status = SigmaRunStatusV1::Cancelled;
            return Ok(false);
        }
        if !self.charge(1) {
            return Ok(false);
        }
        let original = if self.programs.needs_original {
            let text = original_json.ok_or_else(invalid)?;
            let limit = if self.programs.exact_cluster_field.is_some() {
                cluster_audit::MAX_ENVELOPE_BYTES
            } else {
                MAX_RECORD_BYTES
            };
            if text.len() > limit {
                self.status = SigmaRunStatusV1::OversizedInput;
                return Ok(false);
            }
            if !self.charge(text.len() as u64) {
                return Ok(false);
            }
            let original: Value = serde_json::from_str(text).map_err(|_| invalid())?;
            if !original.is_object() {
                return Err(invalid());
            }
            Some(original)
        } else {
            None
        };
        let exact_unavailable = if let Some(field) = self.programs.exact_cluster_field {
            let retained = original.as_ref().ok_or_else(invalid)?;
            let unavailable = validate_cluster_projection(
                retained,
                original_json.ok_or_else(invalid)?.len(),
                common,
                field,
            )?;
            if unavailable {
                let count = self
                    .unavailable_by_source
                    .entry(common.origin().source().clone())
                    .or_default();
                *count = count.checked_add(1).ok_or_else(invalid)?;
            }
            unavailable
        } else {
            false
        };
        self.evaluate(common, original.as_ref(), exact_unavailable, &mut matched)
    }

    fn evaluate(
        &mut self,
        common: &CommonEventV1,
        original: Option<&Value>,
        exact_unavailable: bool,
        matched: &mut impl FnMut(&SigmaRuleKeyV1) -> Result<(), AppError>,
    ) -> Result<bool, AppError> {
        for filter in &self.programs.variant.events {
            if !self.charge(1) {
                return Ok(false);
            }
            if !event_matches(filter, common, original)? {
                return Ok(true);
            }
        }
        let fields = project_fields(
            self.programs.variant,
            &self.programs.used_fields,
            common,
            original,
        )?;
        for (index, (key, program)) in self.programs.eligible.iter().enumerate() {
            if exact_unavailable && self.programs.uses_exact[index] {
                let Some(remaining) = self.remaining_units.checked_sub(1) else {
                    self.status = SigmaRunStatusV1::WorkLimit;
                    return Ok(false);
                };
                self.remaining_units = remaining;
                let count = self.indeterminate_by_rule.entry(key.clone()).or_default();
                *count = count.checked_add(1).ok_or_else(invalid)?;
                continue;
            }
            self.rules_evaluated[index] = true;
            match program.evaluate(
                |name| {
                    Ok(fields
                        .get(name)
                        .map_or(SigmaField::Absent, Projection::view))
                },
                &mut self.remaining_units,
            ) {
                Ok(true) if self.matches < self.match_limit => {
                    matched(key)?;
                    self.matches += 1;
                }
                Ok(false) => {}
                Err(irmind_sigma::EvaluationError::OversizedInput) => {
                    self.status = SigmaRunStatusV1::OversizedInput;
                    return Ok(false);
                }
                Err(irmind_sigma::EvaluationError::FieldTypeMismatch) => return Err(invalid()),
                Ok(true) | Err(irmind_sigma::EvaluationError::WorkLimit) => {
                    self.status = SigmaRunStatusV1::WorkLimit;
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn charge(&mut self, units: u64) -> bool {
        if let Some(remainder) = self.remaining_units.checked_sub(units) {
            self.remaining_units = remainder;
            true
        } else {
            self.status = SigmaRunStatusV1::WorkLimit;
            false
        }
    }

    pub fn rules_evaluated(&self) -> usize {
        self.rules_evaluated.iter().filter(|ran| **ran).count()
    }

    pub const fn used_units(&self) -> u64 {
        self.reserved_units - self.remaining_units
    }

    pub const fn status(&self) -> SigmaRunStatusV1 {
        self.status
    }
}

fn validate_cluster_projection(
    retained: &Value,
    encoded_len: usize,
    common: &CommonEventV1,
    field: AuditExactField,
) -> Result<bool, AppError> {
    let object = retained.as_object().ok_or_else(invalid)?;
    if object.len() != 4
        || object.get("format").and_then(Value::as_str) != Some(cluster_audit::FORMAT)
    {
        return Err(invalid());
    }
    let common_json = object.get("common").ok_or_else(invalid)?;
    // Value comparison is independent of serde_json's map feature.
    let canonical_common = irmind_app::encode_common_event(common)?;
    if encoded_len
        .checked_sub(canonical_common.len())
        .is_none_or(|extra| extra > cluster_audit::MAX_DECORATION_BYTES)
    {
        return Err(invalid());
    }
    let expected: Value = serde_json::from_str(&canonical_common).map_err(|_| invalid())?;
    if common_json != &expected || !object.get("original").is_some_and(Value::is_object) {
        return Err(invalid());
    }
    let unavailable = object
        .get("unavailable")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if unavailable.is_empty() {
        return Ok(false);
    }
    let reason = unavailable
        .get(field.key())
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if unavailable.len() != 1
        || !matches!(
            reason,
            "overflow" | "invalid_ip" | "duplicate" | "unexpected_type"
        )
        || object["original"]
            .as_object()
            .is_none_or(|value| !value.is_empty())
    {
        return Err(invalid());
    }
    Ok(true)
}

pub(super) fn covers(rule: &irmind_sigma::RuleDocument, variant: &SigmaSourceVariant) -> bool {
    let Some(RuleValue::Mapping(logsource)) = rule.fields().get("logsource") else {
        return false;
    };
    [
        ("product", variant.product.as_deref()),
        ("service", variant.service.as_deref()),
        ("category", variant.category.as_deref()),
    ]
    .into_iter()
    .all(|(key, expected)| {
        logsource.get(key).is_none_or(
            |value| matches!(value, RuleValue::Text(actual) if Some(actual.as_str()) == expected),
        )
    })
}

fn collect_fields<'a>(
    node: &RuleValue,
    variant: &'a SigmaSourceVariant,
    used: &mut BTreeSet<&'a str>,
) {
    match node {
        RuleValue::Mapping(fields) => {
            for key in fields.keys() {
                let name = key.split_once('|').map_or(key.as_str(), |(field, _)| field);
                if let Some(binding) = variant.fields.iter().find(|binding| binding.name == name) {
                    used.insert(binding.name.as_str());
                }
            }
        }
        RuleValue::Sequence(items) => {
            for node in items {
                collect_fields(node, variant, used);
            }
        }
        _ => {}
    }
}

fn event_matches(
    filter: &SigmaEventFilter,
    common: &CommonEventV1,
    original: Option<&Value>,
) -> Result<bool, AppError> {
    use irmind_domain::{EventCategory, EventType};
    match filter.column.as_deref() {
        Some("event.category") => {
            return Ok(filter.values().iter().any(|literal| {
                matches!(literal, SigmaLiteral::Text(text) if EventCategory::parse(text)
                .is_ok_and(|category| common.event().categories().contains(category)))
            }));
        }
        Some("event.type") => {
            return Ok(filter.values().iter().any(|literal| {
                matches!(literal, SigmaLiteral::Text(text) if EventType::parse(text)
                .is_ok_and(|event_type| common.event().types().contains(event_type)))
            }));
        }
        _ => {}
    }
    let value = if let Some(column) = &filter.column {
        project_common(common, column)?
    } else {
        original_path(original, filter.path.as_deref())
            .map_or(Ok(Projection::Missing), |value| {
                scalar_json(value, None).map(Projection::Single)
            })?
    };
    let Projection::Single(value) = value else {
        return Ok(false);
    };
    Ok(filter
        .values()
        .iter()
        .any(|expected| match (expected, value) {
            (SigmaLiteral::Integer(left), SigmaScalar::Integer(right)) => *left == right,
            (SigmaLiteral::Boolean(left), SigmaScalar::Boolean(right)) => *left == right,
            (SigmaLiteral::Text(left), SigmaScalar::Text(right)) => left == right,
            _ => false,
        }))
}

fn project_fields<'a>(
    variant: &'a SigmaSourceVariant,
    used: &BTreeSet<&str>,
    common: &'a CommonEventV1,
    original: Option<&'a Value>,
) -> Result<BTreeMap<&'a str, Projection<'a>>, AppError> {
    variant
        .fields
        .iter()
        .filter(|binding| used.contains(binding.name.as_str()))
        .map(|binding| {
            let value = if let Some(column) = &binding.column {
                project_common(common, column)?
            } else if let Some(value) = original_path(original, binding.path.as_deref()) {
                if value.is_null() && matches!(binding.null_policy, SigmaNullPolicy::Absent) {
                    Projection::Missing
                } else {
                    match binding.conversion {
                        Some(SigmaConversion::EvtxEventId) => evtx_number(value, 5, u16::MAX)?,
                        Some(SigmaConversion::EvtxLogonType) => {
                            evtx_number(value, 3, u16::from(u8::MAX))?
                        }
                        Some(SigmaConversion::DefenderFullPath) => {
                            let basename =
                                original_path(original, binding.basename_path.as_deref())
                                    .and_then(Value::as_str);
                            defender_full_path(value.as_str(), basename)
                                .map_or(Projection::Missing, |path| {
                                    Projection::Single(SigmaScalar::Text(path))
                                })
                        }
                        None => project_json(value, binding.value_type)?,
                    }
                }
            } else {
                Projection::Missing
            };
            Ok((binding.name.as_str(), value))
        })
        .collect()
}

fn project_common<'a>(common: &'a CommonEventV1, column: &str) -> Result<Projection<'a>, AppError> {
    let header = common.event();
    let text = match column {
        "event.code" => header.code(),
        "event.action" => header.action(),
        "event.id" => header.id(),
        "event.dataset" => header.dataset(),
        "event.outcome" => Some(header.outcome().as_str()),
        _ => {
            let field = CommonField::parse(column).map_err(|_| invalid())?;
            return match common.context().get(field) {
                None => Ok(Projection::Missing),
                Some(CommonValue::Ip(value)) => Ok(Projection::Single(SigmaScalar::Ip(*value))),
                Some(CommonValue::Unsigned(value)) => Ok(Projection::Single(SigmaScalar::Integer(
                    i64::try_from(*value).map_err(|_| invalid())?,
                ))),
                Some(CommonValue::Boolean(value)) => {
                    Ok(Projection::Single(SigmaScalar::Boolean(*value)))
                }
                Some(CommonValue::Text(value)) => {
                    Ok(Projection::Single(SigmaScalar::Text(value.as_str())))
                }
                Some(CommonValue::TextList(list)) => Ok(Projection::List(
                    list.values()
                        .iter()
                        .map(|text| SigmaScalar::Text(text.as_str()))
                        .collect(),
                )),
                Some(_) => Err(invalid()),
            };
        }
    };
    Ok(text.map_or(Projection::Missing, |text| {
        Projection::Single(SigmaScalar::Text(text))
    }))
}

fn original_path<'a>(mut node: Option<&'a Value>, path: Option<&[String]>) -> Option<&'a Value> {
    for segment in path? {
        node = node?.as_object()?.get(segment);
    }
    node
}

fn evtx_number(value: &Value, digits: usize, max: u16) -> Result<Projection<'_>, AppError> {
    let value = value
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= digits
                && value.bytes().all(|byte| byte.is_ascii_digit())
        })
        .ok_or_else(invalid)?;
    let parsed = value
        .parse::<u16>()
        .ok()
        .filter(|number| *number <= max)
        .ok_or_else(invalid)?;
    Ok(Projection::Single(SigmaScalar::Integer(i64::from(parsed))))
}

fn defender_full_path<'a>(raw: Option<&'a str>, basename: Option<&str>) -> Option<&'a str> {
    let raw = raw?;
    let basename = basename?;
    let separator = ['\\', '/'];
    let path = raw.as_bytes();
    let components = match path {
        [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic() => &raw[3..],
        [b'\\', b'\\', ..] if raw[2..].split(separator).count() >= 3 => &raw[2..],
        _ => return None,
    };
    if components.split(separator).any(|part| {
        part.is_empty()
            || part == "."
            || part == ".."
            || part.contains(['<', '>', ':', '"', '|', '?', '*'])
            || part.chars().any(char::is_control)
    }) {
        return None;
    }
    components
        .rsplit(separator)
        .next()
        .filter(|component| component.eq_ignore_ascii_case(basename))
        .map(|_| raw)
}

fn project_json(value: &Value, field: SigmaBindingType) -> Result<Projection<'_>, AppError> {
    use SigmaBindingType as Kind;
    if value.is_null() {
        return Ok(Projection::Single(SigmaScalar::Null));
    }
    if field == Kind::PairList {
        let array = value
            .as_array()
            .filter(|items| items.len() <= 128)
            .ok_or_else(invalid)?;
        let pairs = array
            .iter()
            .map(|item| {
                let object = item.as_object().ok_or_else(invalid)?;
                let name = object
                    .get("Name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty() && name.len() <= 512)
                    .ok_or_else(invalid)?;
                let value = object
                    .get("Value")
                    .and_then(Value::as_str)
                    .filter(|value| value.len() <= 4096)
                    .ok_or_else(invalid)?;
                Ok::<_, AppError>((name, value))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Projection::Pairs(pairs));
    }
    let element = match field {
        Kind::TextList => Kind::Text,
        Kind::IntegerList => Kind::Integer,
        Kind::IpList => Kind::Ip,
        scalar => return scalar_json(value, Some(scalar)).map(Projection::Single),
    };
    let values = value.as_array().ok_or_else(invalid)?;
    if values.len() > 1024 {
        return Err(invalid());
    }
    values
        .iter()
        .map(|value| scalar_json(value, Some(element)))
        .collect::<Result<Vec<_>, _>>()
        .map(Projection::List)
}

fn scalar_json(
    value: &Value,
    field: Option<SigmaBindingType>,
) -> Result<SigmaScalar<'_>, AppError> {
    use SigmaBindingType as Kind;
    match (value, field) {
        (Value::Null, _) => Ok(SigmaScalar::Null),
        (Value::String(value), None | Some(Kind::Text)) => Ok(SigmaScalar::Text(value)),
        (Value::String(value), Some(Kind::Ip)) => {
            value.parse().map(SigmaScalar::Ip).map_err(|_| invalid())
        }
        (Value::Bool(value), None | Some(Kind::Boolean)) => Ok(SigmaScalar::Boolean(*value)),
        (Value::Number(value), None | Some(Kind::Integer)) => {
            value.as_i64().map(SigmaScalar::Integer).ok_or_else(invalid)
        }
        _ => Err(invalid()),
    }
}

pub(super) fn field_kind(field: SigmaBindingType) -> SigmaFieldKind {
    use SigmaBindingType as Kind;
    match field {
        Kind::Text => SigmaFieldKind::Text,
        Kind::Integer => SigmaFieldKind::Integer,
        Kind::Boolean => SigmaFieldKind::Boolean,
        Kind::Ip => SigmaFieldKind::Ip,
        Kind::TextList => SigmaFieldKind::TextList,
        Kind::IntegerList => SigmaFieldKind::IntegerList,
        Kind::IpList => SigmaFieldKind::IpList,
        Kind::PairList => SigmaFieldKind::PairList,
    }
}

enum Projection<'a> {
    Missing,
    Single(SigmaScalar<'a>),
    List(Vec<SigmaScalar<'a>>),
    Pairs(Vec<(&'a str, &'a str)>),
}

impl Projection<'_> {
    fn view(&self) -> SigmaField<'_> {
        match self {
            Self::Missing => SigmaField::Absent,
            Self::Single(value) => SigmaField::Single(*value),
            Self::List(values) => SigmaField::List(values),
            Self::Pairs(items) => SigmaField::Pairs(items),
        }
    }
}

fn invalid() -> AppError {
    AppError::Policy("Sigma inputs do not match the enrolled source and field contract".into())
}
