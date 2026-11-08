use super::{SourceRecordError, SourceValue};

/// Literal dotted keys and nested keys are different source paths.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SourcePathSegment {
    Key(String),
    Index(u16),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourcePath(Vec<SourcePathSegment>);

impl SourcePath {
    pub fn try_new(segments: Vec<SourcePathSegment>) -> Result<Self, SourceRecordError> {
        if segments.is_empty()
            || segments.len() > 32
            || segments
                .iter()
                .any(|s| matches!(s, SourcePathSegment::Key(k) if k.is_empty() || k.len() > 256))
        {
            return Err(SourceRecordError::InvalidPath);
        }
        Ok(Self(segments))
    }

    pub fn keys(keys: &[&str]) -> Result<Self, SourceRecordError> {
        Self::try_new(
            keys.iter()
                .map(|k| SourcePathSegment::Key((*k).into()))
                .collect(),
        )
    }

    pub fn segments(&self) -> &[SourcePathSegment] {
        &self.0
    }

    pub fn resolve<'a>(&self, mut value: &'a SourceValue) -> Option<&'a SourceValue> {
        for segment in &self.0 {
            value = match (segment, value) {
                (SourcePathSegment::Key(key), SourceValue::Object(fields)) => fields.get(key)?,
                (SourcePathSegment::Index(index), SourceValue::Array(values)) => {
                    values.get(usize::from(*index))?
                }
                _ => return None,
            };
        }
        Some(value)
    }
}
