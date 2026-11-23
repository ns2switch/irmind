mod intersection;
use super::{
    MappingError, SourceDiscriminator, SourceNumber, SourcePath, SourceRecordV1, SourceValue,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SelectorScalar {
    Boolean(bool),
    Number(SourceNumber),
    Text(String),
}
impl SelectorScalar {
    fn matches(&self, value: &SourceValue) -> bool {
        match (self, value) {
            (Self::Boolean(a), SourceValue::Boolean(b)) => a == b,
            (Self::Number(a), SourceValue::Number(b)) => a == b,
            (Self::Text(a), SourceValue::Text(b)) => a == b,
            _ => false,
        }
    }
    fn integer(&self) -> Option<i128> {
        match self {
            Self::Number(value) => value.as_str().parse().ok(),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SelectorPredicate {
    Missing,
    Null,
    Present,
    Exact(SelectorScalar),
    IntegerInterval { first: i128, last: i128 },
}
impl SelectorPredicate {
    pub fn validate(&self) -> Result<(), MappingError> {
        if matches!(self, Self::IntegerInterval { first, last } if first > last)
            || matches!(self, Self::Exact(SelectorScalar::Text(t)) if t.len() > 256)
        {
            return Err(MappingError::InvalidManifest);
        }
        Ok(())
    }
    pub fn matches(&self, value: Option<&SourceValue>) -> bool {
        match (self, value) {
            (Self::Missing, None) | (Self::Null, Some(SourceValue::Null)) => true,
            (Self::Present, Some(value)) => !matches!(value, SourceValue::Null),
            (Self::Exact(expected), Some(value)) => expected.matches(value),
            (Self::IntegerInterval { first, last }, Some(SourceValue::Number(value))) => value
                .as_str()
                .parse::<i128>()
                .is_ok_and(|v| (*first..=*last).contains(&v)),
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SelectorCondition {
    pub path: SourcePath,
    pub predicate: SelectorPredicate,
}

/// All versions are explicit and checked against the frozen decoder catalog.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceSelector {
    parser: String,
    versions: BTreeSet<String>,
    format: Option<(String, String)>,
    discriminators: BTreeMap<SourceDiscriminator, String>,
    conditions: Vec<SelectorCondition>,
}
impl SourceSelector {
    pub fn try_new(
        parser: &str,
        versions: BTreeSet<String>,
        format: Option<(String, String)>,
        discriminators: BTreeMap<SourceDiscriminator, String>,
        mut conditions: Vec<SelectorCondition>,
    ) -> Result<Self, MappingError> {
        if !valid_id(parser)
            || versions.is_empty()
            || versions.len() > 128
            || versions.iter().any(|v| !valid_version(v))
            || discriminators
                .values()
                .any(|v| v.is_empty() || v.len() > 256)
            || format
                .as_ref()
                .is_some_and(|(id, version)| !valid_id(id) || !valid_version(version))
            || conditions.len() > 8
        {
            return Err(MappingError::InvalidManifest);
        }
        conditions.sort();
        for condition in &conditions {
            condition.predicate.validate()?;
        }
        if conditions.windows(2).any(|v| v[0].path == v[1].path) {
            return Err(MappingError::InvalidManifest);
        }
        let result = Self {
            parser: parser.into(),
            versions,
            format,
            discriminators,
            conditions,
        };
        if result.overlap_witness(&result).is_none() {
            return Err(MappingError::InvalidManifest);
        }
        Ok(result)
    }

    pub fn matches(&self, source: &SourceRecordV1) -> bool {
        self.parser == source.origin().parser()
            && self.versions.contains(source.origin().parser_version())
            && self.format.as_ref().is_none_or(|(id, version)| {
                id == source.format().id() && version == source.format().version()
            })
            && self
                .discriminators
                .iter()
                .all(|(k, v)| source.format().discriminators().get(k) == Some(v))
            && self.conditions.iter().all(|condition| {
                condition
                    .predicate
                    .matches(condition.path.resolve(source.fields()))
            })
    }

    /// A deterministic common selector, before any signed operation or write.
    pub fn overlap_witness(&self, other: &Self) -> Option<String> {
        intersection::witness(self, other)
    }
    pub fn parser(&self) -> &str {
        &self.parser
    }
    pub const fn versions(&self) -> &BTreeSet<String> {
        &self.versions
    }
    pub fn conditions(&self) -> &[SelectorCondition] {
        &self.conditions
    }
    pub const fn format(&self) -> Option<&(String, String)> {
        self.format.as_ref()
    }
    pub const fn discriminators(&self) -> &BTreeMap<SourceDiscriminator, String> {
        &self.discriminators
    }
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn valid_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}
