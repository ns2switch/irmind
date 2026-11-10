use irmind_app::source_mapping::{MappingError, SourceValue};
pub(super) struct View<'a>(pub(super) &'a SourceValue);
impl<'a> View<'a> {
    pub(super) fn get(&self, path: &str) -> Option<&'a SourceValue> {
        path.split('.')
            .try_fold(self.0, |value, key| value.field(key))
    }
    pub(super) fn text(&self, path: &str) -> Result<Option<&'a str>, MappingError> {
        match self.get(path) {
            None | Some(SourceValue::Null) => Ok(None),
            Some(SourceValue::Text(text)) => Ok(Some(text)),
            _ => Err(MappingError::UnsupportedSourceValue),
        }
    }
    pub(super) fn uint(&self, path: &str) -> Result<Option<u32>, MappingError> {
        match self.get(path) {
            None | Some(SourceValue::Null) => Ok(None),
            Some(SourceValue::Number(value)) => value
                .as_str()
                .parse()
                .map(Some)
                .map_err(|_| MappingError::UnsupportedSourceValue),
            _ => Err(MappingError::UnsupportedSourceValue),
        }
    }
}
