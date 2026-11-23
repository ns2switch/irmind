//! Closed source bindings parsed from a hash-authenticated V10 Sigma table.
use irmind_app::{AppError, v10_proofs::SigmaFieldTableV1};
use irmind_domain::{CommonField, CommonFieldType};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedSigmaFieldTable {
    pub variants: Vec<SigmaSourceVariant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigmaSourceVariant {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
    pub parser_id: String,
    pub parser_version: String,
    pub mapping_id: String,
    pub mapping_version: String,
    pub channel: Option<String>,
    pub dataset: Option<String>,
    pub events: Vec<SigmaEventFilter>,
    pub fields: Vec<SigmaFieldBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigmaEventFilter {
    pub column: Option<String>,
    pub path: Option<Vec<String>>,
    pub equals: Option<SigmaLiteral>,
    pub one_of: Option<Vec<SigmaLiteral>>,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(untagged)]
pub enum SigmaLiteral {
    Text(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigmaFieldBinding {
    pub name: String,
    pub column: Option<String>,
    pub path: Option<Vec<String>>,
    pub value_type: SigmaBindingType,
    pub null_policy: SigmaNullPolicy,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SigmaBindingType {
    Text,
    Integer,
    Boolean,
    Ip,
    TextList,
    IntegerList,
    IpList,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigmaNullPolicy {
    Absent,
    Present,
}

impl ReviewedSigmaFieldTable {
    pub fn parse(object: &SigmaFieldTableV1) -> Result<Self, AppError> {
        if object.toml.len() > 512 * 1024 {
            return Err(invalid());
        }
        let table: Self = toml::from_str(&object.toml).map_err(|_| invalid())?;
        if table.variants.is_empty() || table.variants.len() > 1024 {
            return Err(invalid());
        }
        let mut source_classes = BTreeMap::<_, Vec<&SigmaSourceVariant>>::new();
        for variant in &table.variants {
            variant.validate()?;
            let key = (
                &variant.parser_id,
                &variant.parser_version,
                &variant.mapping_id,
                &variant.mapping_version,
                &variant.dataset,
                &variant.channel,
            );
            let peers = source_classes.entry(key).or_default();
            if peers.iter().any(|previous| previous.overlaps(variant)) {
                return Err(invalid());
            }
            peers.push(variant);
        }
        Ok(table)
    }
}

impl SigmaSourceVariant {
    fn overlaps(&self, other: &Self) -> bool {
        let taxonomy = [
            (&self.product, &other.product),
            (&self.service, &other.service),
            (&self.category, &other.category),
        ];
        if taxonomy.iter().any(|(left, right)| {
            matches!((left, right),
            (Some(left), Some(right)) if left != right)
        }) {
            return false;
        }
        // A pair is disjoint only when the same exact field is constrained
        // to disjoint literal sets. Unknown intersections fail closed.
        !self.events.iter().any(|left| {
            other.events.iter().any(|right| {
                left.column == right.column
                    && left.path == right.path
                    && !left
                        .values()
                        .iter()
                        .any(|value| right.values().contains(value))
            })
        })
    }

    fn validate(&self) -> Result<(), AppError> {
        let taxonomy = [&self.product, &self.service, &self.category];
        if taxonomy.iter().all(|value| value.is_none())
            || taxonomy
                .into_iter()
                .flatten()
                .any(|name| !taxonomy_name(name))
            || self.channel.is_some() == self.dataset.is_some()
            || self
                .channel
                .iter()
                .chain(&self.dataset)
                .any(|name| !bounded_text(name, 256))
            || [
                &self.parser_id,
                &self.parser_version,
                &self.mapping_id,
                &self.mapping_version,
            ]
            .iter()
            .any(|part| !bounded_text(part, 128))
            || self.events.is_empty()
            || self.events.len() > 128
            || self.fields.is_empty()
            || self.fields.len() > 128
        {
            return Err(invalid());
        }
        for event in &self.events {
            event.validate()?;
        }
        let mut names = BTreeSet::new();
        for field in &self.fields {
            if !bounded_text(&field.name, 128) || !names.insert(&field.name) {
                return Err(invalid());
            }
            let column_kind = location(field.column.as_deref(), field.path.as_deref())?;
            if column_kind.is_some_and(|expected| expected != field.value_type) {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

impl SigmaEventFilter {
    fn values(&self) -> &[SigmaLiteral] {
        self.equals.as_ref().map_or_else(
            || self.one_of.as_deref().unwrap_or(&[]),
            std::slice::from_ref,
        )
    }

    fn validate(&self) -> Result<(), AppError> {
        let bound_type = location(self.column.as_deref(), self.path.as_deref())?;
        let values = match (&self.equals, &self.one_of) {
            (Some(value), None) => std::slice::from_ref(value),
            (None, Some(values)) if !values.is_empty() && values.len() <= 128 => values.as_slice(),
            _ => return Err(invalid()),
        };
        let mut seen = BTreeSet::new();
        let actual = literal_kind(&values[0]);
        if values.iter().any(|value| {
            literal_kind(value) != actual
                || !seen.insert(value)
                || matches!(value, SigmaLiteral::Text(text) if !bounded_text(text, 512))
        }) || bound_type.is_some_and(|expected| expected != actual)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn literal_kind(literal: &SigmaLiteral) -> SigmaBindingType {
    match literal {
        SigmaLiteral::Text(_) => SigmaBindingType::Text,
        SigmaLiteral::Integer(_) => SigmaBindingType::Integer,
        SigmaLiteral::Boolean(_) => SigmaBindingType::Boolean,
    }
}

// Original paths use exact components. Common aliases are checked against
// their existing typed declarations and do not undergo implicit casts.
fn location(
    column: Option<&str>,
    path: Option<&[String]>,
) -> Result<Option<SigmaBindingType>, AppError> {
    match (column, path) {
        (Some("event.code" | "event.action" | "event.id" | "event.dataset"), None) => {
            Ok(Some(SigmaBindingType::Text))
        }
        (Some(name), None) => match CommonField::parse(name)
            .map_err(|_| invalid())?
            .value_type()
        {
            CommonFieldType::Text | CommonFieldType::LongText => Ok(Some(SigmaBindingType::Text)),
            CommonFieldType::Ip => Ok(Some(SigmaBindingType::Ip)),
            CommonFieldType::Boolean => Ok(Some(SigmaBindingType::Boolean)),
            CommonFieldType::Unsigned
            | CommonFieldType::Port
            | CommonFieldType::Pid
            | CommonFieldType::HttpStatus => Ok(Some(SigmaBindingType::Integer)),
            CommonFieldType::TextList => Ok(Some(SigmaBindingType::TextList)),
            _ => Err(invalid()),
        },
        (None, Some(parts))
            if !parts.is_empty()
                && parts.len() <= 16
                && parts.iter().all(|part| bounded_text(part, 128)) =>
        {
            Ok(None)
        }
        _ => Err(invalid()),
    }
}

fn taxonomy_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn bounded_text(text: &str, limit: usize) -> bool {
    !text.is_empty() && text.len() <= limit && !text.chars().any(char::is_control)
}

fn invalid() -> AppError {
    AppError::Policy("Sigma field table has an unsupported or ambiguous binding".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sigma_field_table_validates_typed_locations_and_exact_source_variants() {
        let fixtures: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../testkit/fixtures/contracts/sigma_report_objects.json"
        ))
        .unwrap();
        let wire =
            hex::decode(fixtures["sigma_field_table"]["bytes_hex"].as_str().unwrap()).unwrap();
        let mut table = SigmaFieldTableV1::decode(&wire).unwrap();
        let bindings = ReviewedSigmaFieldTable::parse(&table).unwrap();
        assert_eq!(bindings.variants[0].fields[0].name, "Image");
        for replacement in [
            table.toml.replace("process.executable", "anything.active"),
            table
                .toml
                .replace("value_type = \"text\"", "value_type = \"integer\""),
            table.toml.replace("equals = \"1\"", "equals = 1"),
            table.toml.replace(
                "column = \"process.executable\"",
                "column = \"process.executable\"\npath = [\"image\"]",
            ),
            table.toml.repeat(2),
        ] {
            let unsafe_table = SigmaFieldTableV1 {
                toml: replacement,
                ..table.clone()
            };
            assert!(ReviewedSigmaFieldTable::parse(&unsafe_table).is_err());
        }
        table.toml.push_str("unknown_property = true\n");
        assert!(ReviewedSigmaFieldTable::parse(&table).is_err());
    }
}
