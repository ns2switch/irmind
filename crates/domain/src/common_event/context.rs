use super::{CommonField, CommonValue, EventSchemaError};
use std::collections::BTreeMap;

/// A closed, typed field set. Arbitrary JSON destinations are not accepted.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct EventContextV1 {
    fields: BTreeMap<CommonField, CommonValue>,
    bytes: usize,
}
impl EventContextV1 {
    pub fn try_insert(
        &mut self,
        field: CommonField,
        value: CommonValue,
    ) -> Result<(), EventSchemaError> {
        if self.fields.contains_key(&field) {
            return Err(EventSchemaError::DuplicateField);
        }
        if field == CommonField::IrmindClusterIdentity {
            let CommonValue::Text(text) = &value else {
                return Err(EventSchemaError::InvalidFieldType);
            };
            crate::ClusterIdentity::parse_qualified(text.as_str())
                .map_err(|_| EventSchemaError::InvalidValue)?;
        }
        if !field.validates(&value) {
            return Err(EventSchemaError::InvalidFieldType);
        }
        let bytes = self
            .bytes
            .checked_add(field.as_str().len() + 8 + value.json_bytes())
            .ok_or(EventSchemaError::LimitExceeded)?;
        if bytes > 48 * 1024 {
            return Err(EventSchemaError::LimitExceeded);
        }
        self.fields.insert(field, value);
        self.bytes = bytes;
        Ok(())
    }
    pub fn get(&self, field: CommonField) -> Option<&CommonValue> {
        self.fields.get(&field)
    }
    pub fn fields(&self) -> impl Iterator<Item = (CommonField, &CommonValue)> {
        self.fields.iter().map(|(field, value)| (*field, value))
    }
    pub(super) const fn json_bytes(&self) -> usize {
        self.bytes + 2
    }
}
impl std::fmt::Debug for EventContextV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EventContextV1(<redacted>)")
    }
}
