use super::{
    SOURCE_MAX_BYTES, SOURCE_MAX_DEPTH, SOURCE_MAX_NODES, SourceNumber, SourceRecordError,
};
use std::collections::BTreeMap;

/// Construction alone grants no trust. `SourceRecordV1` checks the complete tree.
#[derive(Clone, Eq, PartialEq)]
pub enum SourceValue {
    Null,
    Boolean(bool),
    Number(SourceNumber),
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl std::fmt::Debug for SourceValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceValue(<source data>)")
    }
}

impl SourceValue {
    pub fn object(fields: Vec<(String, Self)>) -> Result<Self, SourceRecordError> {
        if fields.len() > SOURCE_MAX_NODES {
            return Err(SourceRecordError::Limit);
        }
        let mut object = BTreeMap::new();
        for (key, value) in fields {
            if object.insert(key, value).is_some() {
                return Err(SourceRecordError::DuplicateField);
            }
        }
        Ok(Self::Object(object))
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    pub fn field(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.get(name),
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<usize, SourceRecordError> {
        let mut budget = Budget { nodes: 0, bytes: 0 };
        walk(self, 0, &mut budget)?;
        Ok(budget.bytes)
    }
}

struct Budget {
    nodes: usize,
    bytes: usize,
}
impl Budget {
    fn charge(&mut self, bytes: usize) -> Result<(), SourceRecordError> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > SOURCE_MAX_BYTES || self.nodes > SOURCE_MAX_NODES {
            return Err(SourceRecordError::Limit);
        }
        Ok(())
    }
}

fn walk(value: &SourceValue, depth: usize, budget: &mut Budget) -> Result<(), SourceRecordError> {
    if depth > SOURCE_MAX_DEPTH {
        return Err(SourceRecordError::Limit);
    }
    budget.nodes += 1;
    budget.charge(1)?;
    match value {
        SourceValue::Null => Ok(()),
        SourceValue::Boolean(_) => budget.charge(1),
        SourceValue::Number(n) => budget.charge(8 + n.as_str().len()),
        SourceValue::Text(s) => budget.charge(8 + s.len()),
        SourceValue::Bytes(b) => budget.charge(8 + b.len()),
        SourceValue::Array(values) => {
            budget.charge(8)?;
            for value in values {
                walk(value, depth + 1, budget)?;
            }
            Ok(())
        }
        SourceValue::Object(fields) => {
            budget.charge(8)?;
            for (key, value) in fields {
                if key.is_empty() || key.len() > 256 {
                    return Err(SourceRecordError::InvalidPath);
                }
                budget.charge(8 + key.len())?;
                walk(value, depth + 1, budget)?;
            }
            Ok(())
        }
    }
}
