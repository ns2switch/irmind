mod payload;
use super::{SubagentDigest, SubagentRecordError, codec};
use crate::{Signer, Verifier, hex, sha256};
pub use payload::*;
use serde::{Deserialize, Serialize, ser::SerializeStruct};

#[derive(Clone, Debug)]
pub struct SubagentBranchBody {
    pub case_id: String,
    pub turn_id: String,
    pub task_id: SubagentDigest,
    pub nonce: String,
    pub seq: u64,
    pub at: u64,
    pub payload: SubagentBranchPayload,
    pub prev: SubagentDigest,
    pub public_key: SubagentDigest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBody {
    format_version: u8,
    case_id: String,
    turn_id: String,
    task_id: SubagentDigest,
    nonce: String,
    seq: u64,
    at: u64,
    kind: u8,
    payload: serde_json::Value,
    prev: SubagentDigest,
    public_key: SubagentDigest,
}
impl SubagentBranchBody {
    pub fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.case_id)?;
        codec::uuid(&self.turn_id)?;
        codec::uuid(&self.nonce)?;
        if self.seq == 0 || self.seq > 4096 || (self.seq == 1) != (self.prev.as_bytes() == &[0; 32])
        {
            return Err(SubagentRecordError);
        }
        if let SubagentBranchPayload::SkillLoad(raw) = &self.payload
            && crate::SkillLoadV1::decode(raw)
                .map_err(|_| SubagentRecordError)?
                .turn()
                != self.nonce
        {
            return Err(SubagentRecordError);
        }
        self.payload.validate()
    }
    pub fn identity(&self) -> Result<SubagentDigest, SubagentRecordError> {
        self.validate()?;
        let mut bytes = b"irmind-subagent-branch-entry-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| SubagentRecordError)?);
        Ok(SubagentDigest::from_bytes(sha256(&bytes)))
    }
}
impl Serialize for SubagentBranchBody {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut out = s.serialize_struct("SubagentBranchBody", 11)?;
        out.serialize_field("format_version", &1u8)?;
        out.serialize_field("case_id", &self.case_id)?;
        out.serialize_field("turn_id", &self.turn_id)?;
        out.serialize_field("task_id", &self.task_id)?;
        out.serialize_field("nonce", &self.nonce)?;
        out.serialize_field("seq", &self.seq)?;
        out.serialize_field("at", &self.at)?;
        out.serialize_field("kind", &self.payload.code())?;
        out.serialize_field("payload", &self.payload)?;
        out.serialize_field("prev", &self.prev)?;
        out.serialize_field("public_key", &self.public_key)?;
        out.end()
    }
}
impl<'de> Deserialize<'de> for SubagentBranchBody {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawBody::deserialize(d)?;
        if raw.format_version != 1 {
            return Err(serde::de::Error::custom(SubagentRecordError));
        }
        let value = Self {
            case_id: raw.case_id,
            turn_id: raw.turn_id,
            task_id: raw.task_id,
            nonce: raw.nonce,
            seq: raw.seq,
            at: raw.at,
            payload: SubagentBranchPayload::decode(raw.kind, raw.payload)
                .map_err(serde::de::Error::custom)?,
            prev: raw.prev,
            public_key: raw.public_key,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentBranchEntry {
    pub body: SubagentBranchBody,
    pub hash: SubagentDigest,
    signature: String,
}
impl SubagentBranchEntry {
    pub fn sign(
        body: SubagentBranchBody,
        signer: &dyn Signer,
    ) -> Result<Self, SubagentRecordError> {
        if !matches!(signer.actor(), crate::Actor::Agent(_))
            || signer.public_key() != body.public_key.as_bytes()
        {
            return Err(SubagentRecordError);
        }
        let hash = body.identity()?;
        let sig = signer
            .sign(hash.as_bytes())
            .map_err(|_| SubagentRecordError)?;
        if sig.len() != 64 {
            return Err(SubagentRecordError);
        }
        Ok(Self {
            body,
            hash,
            signature: hex(&sig),
        })
    }
    pub fn canonical(&self) -> Result<Vec<u8>, SubagentRecordError> {
        if self.hash != self.body.identity()?
            || self.signature.len() != 128
            || !self
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SubagentRecordError);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| SubagentRecordError)?;
        if bytes.len() > 1024 * 1024 {
            return Err(SubagentRecordError);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, SubagentRecordError> {
        if bytes.len() > 1024 * 1024 {
            return Err(SubagentRecordError);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| SubagentRecordError)?;
        if value.canonical()? != bytes {
            return Err(SubagentRecordError);
        }
        Ok(value)
    }
    pub fn verify(
        &self,
        expected_agent_key: &[u8],
        verifier: &dyn Verifier,
    ) -> Result<(), SubagentRecordError> {
        self.canonical()?;
        if self.body.public_key.as_bytes() != expected_agent_key {
            return Err(SubagentRecordError);
        }
        let sig = hex::decode(&self.signature).map_err(|_| SubagentRecordError)?;
        verifier
            .verify(expected_agent_key, self.hash.as_bytes(), &sig)
            .map_err(|_| SubagentRecordError)
    }
}
