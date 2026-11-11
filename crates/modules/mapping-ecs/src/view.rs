use irmind_app::source_mapping::{MappingError, SourceValue};
pub(super) struct View<'a> {
    root: &'a SourceValue,
    arrays: bool,
}
impl<'a> View<'a> {
    pub(super) fn for_source(
        source: &'a irmind_app::source_mapping::SourceRecordV1,
    ) -> Result<Self, MappingError> {
        if source.origin().parser() != "siem-elastic" {
            return Ok(Self {
                root: source.fields(),
                arrays: false,
            });
        }
        let fields = source.fields();
        if let Some(value) = fields.field("_source") {
            if !matches!(value, SourceValue::Object(_)) {
                return Err(MappingError::UnsupportedSourceValue);
            }
            return Ok(Self {
                root: value,
                arrays: false,
            });
        }
        match fields.field("fields") {
            Some(root @ SourceValue::Object(_)) => Ok(Self { root, arrays: true }),
            _ => Err(MappingError::UnsupportedSourceValue),
        }
    }
    /// Dotted and nested names remain distinct; conflicting aliases are unsupported.
    pub(super) fn get(&self, key: &str) -> Result<Option<&'a SourceValue>, MappingError> {
        let nested = key
            .split('.')
            .try_fold(self.root, |value, part| value.field(part));
        let literal = self.root.field(key);
        match (nested, literal) {
            (Some(a), Some(b)) if a != b => Err(MappingError::UnsupportedSourceValue),
            (Some(value), _) | (_, Some(value)) => Ok(Some(
                if self.arrays && !matches!(key, "event.category" | "event.type" | "dns.answers") {
                    match value {
                        SourceValue::Array(values) if values.len() == 1 => &values[0],
                        _ => value,
                    }
                } else {
                    value
                },
            )),
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
