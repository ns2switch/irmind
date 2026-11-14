use super::{SubagentDigest, SubagentRecord, SubagentRecordError, codec};
use crate::AuditEventKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BundledSubagentType {
    code: u8,
    id: String,
    version: String,
    tools: Vec<String>,
    skills: Vec<String>,
}
impl BundledSubagentType {
    pub const fn code(&self) -> u8 {
        self.code
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn tools(&self) -> &[String] {
        &self.tools
    }
    pub fn skills(&self) -> &[String] {
        &self.skills
    }
    pub fn permits_tool(&self, tool: &irmind_domain::Tool) -> bool {
        self.tools
            .binary_search_by(|id| id.as_str().cmp(tool.as_str()))
            .is_ok()
    }
}

pub fn bundled_subagent_types() -> Result<Vec<BundledSubagentType>, SubagentRecordError> {
    let raw = include_bytes!("bundled-v1.json");
    let values: Vec<BundledSubagentType> =
        serde_json::from_slice(raw).map_err(|_| SubagentRecordError)?;
    if values.len() != 6 || serde_json::to_vec(&values).map_err(|_| SubagentRecordError)? != raw {
        return Err(SubagentRecordError);
    }
    for (index, (value, id)) in values
        .iter()
        .zip([
            "triage",
            "cloud",
            "endpoint",
            "network",
            "kubernetes",
            "threat-intelligence",
        ])
        .enumerate()
    {
        if value.code as usize != index + 1 || value.id != id || value.version != "1" {
            return Err(SubagentRecordError);
        }
        codec::sorted(&value.tools, 32)?;
        codec::sorted(&value.skills, 32)?;
        for tool in &value.tools {
            if irmind_domain::Tool::parse(tool).is_err() {
                return Err(SubagentRecordError);
            }
        }
        for skill in &value.skills {
            irmind_domain::SkillName::parse(skill).map_err(|_| SubagentRecordError)?;
        }
    }
    Ok(values)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubagentTypeSnapshotV1 {
    format_version: u8,
    case_id: String,
    inventory_sha256: SubagentDigest,
    r#type: BundledSubagentType,
}
impl SubagentTypeSnapshotV1 {
    pub fn new(case: &crate::CaseId, id: &str) -> Result<Self, SubagentRecordError> {
        let types = bundled_subagent_types()?;
        let r#type = types
            .iter()
            .find(|t| t.id == id)
            .cloned()
            .ok_or(SubagentRecordError)?;
        let mut inventory = b"irmind-subagent-type-inventory-v1\0".to_vec();
        inventory.extend(serde_json::to_vec(&types).map_err(|_| SubagentRecordError)?);
        let value = Self {
            format_version: 1,
            case_id: case.as_str().into(),
            inventory_sha256: SubagentDigest::from_bytes(crate::sha256(&inventory)),
            r#type,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn case_id(&self) -> &str {
        &self.case_id
    }
    pub fn definition(&self) -> &BundledSubagentType {
        &self.r#type
    }
}
impl SubagentRecord for SubagentTypeSnapshotV1 {
    const KIND: AuditEventKind = AuditEventKind::SubagentTypeSnapshotV1;
    const DOMAIN: &'static [u8] = b"irmind-subagent-type-v1\0";
    fn validate(&self) -> Result<(), SubagentRecordError> {
        codec::uuid(&self.case_id)?;
        let types = bundled_subagent_types()?;
        let mut inventory = b"irmind-subagent-type-inventory-v1\0".to_vec();
        inventory.extend(serde_json::to_vec(&types).map_err(|_| SubagentRecordError)?);
        if self.format_version != 1
            || !types.contains(&self.r#type)
            || self.inventory_sha256.as_bytes() != &crate::sha256(&inventory)
        {
            return Err(SubagentRecordError);
        }
        Ok(())
    }
}
