use crate::{AuditEventKind, hex, sha256};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid or unsupported bounded subagent record")]
pub struct SubagentRecordError;

/// A methodology/control commitment, never an evidence identity or capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SubagentDigest([u8; 32]);
impl SubagentDigest {
    pub fn parse(text: &str) -> Result<Self, SubagentRecordError> {
        let bytes: [u8; 32] = hex::decode(text)
            .map_err(|_| SubagentRecordError)?
            .try_into()
            .map_err(|_| SubagentRecordError)?;
        if hex(&bytes) != text {
            return Err(SubagentRecordError);
        }
        Ok(Self(bytes))
    }
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl Serialize for SubagentDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex(&self.0))
    }
}
impl<'de> Deserialize<'de> for SubagentDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Serialization does not authorize a plan: authenticated context is checked separately.
pub trait SubagentRecord: Serialize + DeserializeOwned {
    const KIND: AuditEventKind;
    const DOMAIN: &'static [u8];
    fn validate(&self) -> Result<(), SubagentRecordError>;
    fn canonical(&self) -> Result<Vec<u8>, SubagentRecordError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| SubagentRecordError)?;
        if bytes.len() > 256 * 1024 {
            return Err(SubagentRecordError);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, SubagentRecordError> {
        if bytes.len() > 256 * 1024 {
            return Err(SubagentRecordError);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| SubagentRecordError)?;
        if value.canonical()? != bytes {
            return Err(SubagentRecordError);
        }
        Ok(value)
    }
    fn identity(&self) -> Result<SubagentDigest, SubagentRecordError> {
        let mut bytes = Self::DOMAIN.to_vec();
        bytes.extend_from_slice(&self.canonical()?);
        Ok(SubagentDigest(sha256(&bytes)))
    }
    fn audit_payload(&self) -> Result<String, SubagentRecordError> {
        Ok(format!(
            "{}:{}",
            Self::KIND.as_str(),
            hex(&self.canonical()?)
        ))
    }
}

pub(super) fn uuid(value: &str) -> Result<(), SubagentRecordError> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| SubagentRecordError)?;
    if id.to_string() != value {
        return Err(SubagentRecordError);
    }
    Ok(())
}
pub(super) fn sorted<T: Ord>(values: &[T], max: usize) -> Result<(), SubagentRecordError> {
    if values.len() > max || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SubagentRecordError);
    }
    Ok(())
}
