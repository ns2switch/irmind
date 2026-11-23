//! Evaluate admitted Sigma predicates on authenticated common and original fields.
use super::field_table::{
    SigmaBindingType, SigmaEventFilter, SigmaFieldBinding, SigmaLiteral, SigmaNullPolicy,
    SigmaSourceVariant,
};
use irmind_app::{
    AppError, CancellationToken,
    v10_proofs::{SigmaCoverageV1, SigmaRuleKeyV1, SigmaRunStatusV1},
};
use irmind_domain::{CommonEventV1, CommonField, CommonValue};
use irmind_mod_sigma::{
    RuleValue, SigmaField, SigmaFieldKind, SigmaProgram, SigmaScalar, admit_rule,
};
use serde_json::Value;
use std::collections::BTreeMap;

mod parquet_scan;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod benchmark;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_MATCHES: usize = 100_000;

pub struct SigmaVariantPrograms<'a> {
    variant: &'a SigmaSourceVariant,
    eligible: Vec<(SigmaRuleKeyV1, SigmaProgram)>,
    skipped: Vec<(SigmaRuleKeyV1, SigmaCoverageV1)>,
    needs_original: bool,
}

pub struct SigmaEvaluation<'a> {
    programs: &'a SigmaVariantPrograms<'a>,
    remaining_units: u64,
    reserved_units: u64,
    rules_evaluated: Vec<bool>,
    matches: usize,
    status: SigmaRunStatusV1,
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
        let mut programs = Self {
            variant,
            eligible: Vec::new(),
            skipped: Vec::new(),
            needs_original: variant.events.iter().any(|filter| filter.path.is_some()),
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
                    programs.needs_original |= rule_uses_original(&rule, variant);
                    programs.eligible.push((key, program));
                }
                Err(irmind_mod_sigma::CompileError::MissingBinding) => {
                    programs
                        .skipped
                        .push((key, SigmaCoverageV1::UnsupportedField));
                }
                Err(_) => programs
                    .skipped
                    .push((key, SigmaCoverageV1::UnsupportedRule)),
            }
        }
        Ok(programs)
    }

    pub fn start(&'a self, units: u64) -> SigmaEvaluation<'a> {
        SigmaEvaluation {
            programs: self,
            remaining_units: units,
            reserved_units: units,
            rules_evaluated: vec![false; self.eligible.len()],
            matches: 0,
            status: SigmaRunStatusV1::Complete,
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
            if text.len() > MAX_RECORD_BYTES {
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
        self.evaluate(common, original.as_ref(), &mut matched)
    }

    fn evaluate(
        &mut self,
        common: &CommonEventV1,
        original: Option<&Value>,
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
        let fields = project_fields(self.programs.variant, common, original)?;
        for (index, (key, program)) in self.programs.eligible.iter().enumerate() {
            self.rules_evaluated[index] = true;
            match program.evaluate(
                |name| {
                    Ok(fields
                        .get(name)
                        .map_or(SigmaField::Absent, Projection::view))
                },
                &mut self.remaining_units,
            ) {
                Ok(true) if self.matches < MAX_MATCHES => {
                    matched(key)?;
                    self.matches += 1;
                }
                Ok(false) => {}
                Err(irmind_mod_sigma::EvaluationError::OversizedInput) => {
                    self.status = SigmaRunStatusV1::OversizedInput;
                    return Ok(false);
                }
                Err(irmind_mod_sigma::EvaluationError::FieldTypeMismatch) => return Err(invalid()),
                Ok(true) | Err(irmind_mod_sigma::EvaluationError::WorkLimit) => {
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

fn covers(rule: &irmind_mod_sigma::RuleDocument, variant: &SigmaSourceVariant) -> bool {
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

fn rule_uses_original(rule: &irmind_mod_sigma::RuleDocument, variant: &SigmaSourceVariant) -> bool {
    fn has_original(node: &RuleValue, fields: &[SigmaFieldBinding]) -> bool {
        match node {
            RuleValue::Mapping(map) => map.keys().any(|name| {
                let base = name.split_once('|').map_or(name.as_str(), |(base, _)| base);
                fields
                    .iter()
                    .any(|field| field.name == base && field.path.is_some())
            }),
            RuleValue::Sequence(items) => items.iter().any(|node| has_original(node, fields)),
            _ => false,
        }
    }
    matches!(rule.fields().get("detection"), Some(RuleValue::Mapping(map))
        if map.values().any(|node| has_original(node, &variant.fields)))
}

fn event_matches(
    filter: &SigmaEventFilter,
    common: &CommonEventV1,
    original: Option<&Value>,
) -> Result<bool, AppError> {
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
    common: &'a CommonEventV1,
    original: Option<&'a Value>,
) -> Result<BTreeMap<&'a str, Projection<'a>>, AppError> {
    variant
        .fields
        .iter()
        .map(|binding| {
            let value = if let Some(column) = &binding.column {
                project_common(common, column)?
            } else if let Some(value) = original_path(original, binding.path.as_deref()) {
                if value.is_null() && matches!(binding.null_policy, SigmaNullPolicy::Absent) {
                    Projection::Missing
                } else {
                    project_json(value, binding.value_type)?
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

fn project_json(value: &Value, field: SigmaBindingType) -> Result<Projection<'_>, AppError> {
    use SigmaBindingType as Kind;
    if value.is_null() {
        return Ok(Projection::Single(SigmaScalar::Null));
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

fn field_kind(field: SigmaBindingType) -> SigmaFieldKind {
    use SigmaBindingType as Kind;
    match field {
        Kind::Text => SigmaFieldKind::Text,
        Kind::Integer => SigmaFieldKind::Integer,
        Kind::Boolean => SigmaFieldKind::Boolean,
        Kind::Ip => SigmaFieldKind::Ip,
        Kind::TextList => SigmaFieldKind::TextList,
        Kind::IntegerList => SigmaFieldKind::IntegerList,
        Kind::IpList => SigmaFieldKind::IpList,
    }
}

enum Projection<'a> {
    Missing,
    Single(SigmaScalar<'a>),
    List(Vec<SigmaScalar<'a>>),
}

impl Projection<'_> {
    fn view(&self) -> SigmaField<'_> {
        match self {
            Self::Missing => SigmaField::Absent,
            Self::Single(value) => SigmaField::Single(*value),
            Self::List(values) => SigmaField::List(values),
        }
    }
}

fn invalid() -> AppError {
    AppError::Policy("Sigma inputs do not match the enrolled source and field contract".into())
}
