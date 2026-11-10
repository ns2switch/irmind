use irmind_app::source_mapping::{MappingError, SourceValue};
pub(super) struct View<'a>(pub(super) &'a SourceValue);
impl<'a> View<'a> {
    /// Dotted and nested names remain distinct; conflicting aliases are unsupported.
    pub(super) fn get(&self, key: &str) -> Result<Option<&'a SourceValue>, MappingError> {
        let nested = key
            .split('.')
            .try_fold(self.0, |value, part| value.field(part));
        let literal = self.0.field(key);
        match (nested, literal) {
            (Some(a), Some(b)) if a != b => Err(MappingError::UnsupportedSourceValue),
            (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
            _ => Ok(None),
        }
    }
    pub(super) fn text(&self, key: &str) -> Result<Option<&'a str>, MappingError> {
        match self.get(key)? {
            None | Some(SourceValue::Null) => Ok(None),
            Some(SourceValue::Text(text)) => Ok(Some(text)),
            _ => Err(MappingError::UnsupportedSourceValue),
        }
    }
}
