use super::{decode, encode, hash, invalid};
use crate::{AppError, AuditEventKind, CompiledSkill, SkillCompiler, SkillOrigin, hex, sha256};
use irmind_domain::{COMMON_EVENT_V1, SkillName, SkillPackage, SkillResource, SkillVersion};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkillSnapshotId([u8; 32]);
impl SkillSnapshotId {
    pub fn parse(value: &str) -> Result<Self, AppError> {
        Ok(Self(hash(value)?))
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    path: String,
    contents: String,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillSnapshotV1 {
    format_version: u32,
    name: String,
    skill_version: String,
    target_schema: String,
    interpreter: String,
    package_sha256: String,
    origin: SkillOrigin,
    release_inventory_sha256: Option<String>,
    admission_operation_sha256: Option<String>,
    files: Vec<File>,
}
impl SkillSnapshotV1 {
    pub fn new(skill: &CompiledSkill, origin: SkillOrigin, authorization: [u8; 32]) -> Self {
        let bundled = origin == SkillOrigin::Bundled;
        Self {
            format_version: 1,
            name: skill.metadata().name().as_str().into(),
            skill_version: skill.metadata().version().as_str().into(),
            target_schema: COMMON_EVENT_V1.into(),
            interpreter: "irmind-skill-interpreter-v1".into(),
            package_sha256: hex(skill.package().hash().as_bytes()),
            origin,
            release_inventory_sha256: bundled.then(|| hex(&authorization)),
            admission_operation_sha256: (!bundled).then(|| hex(&authorization)),
            files: skill
                .package()
                .resources()
                .values()
                .map(|r| File {
                    path: r.path().as_str().into(),
                    contents: r.untrusted_text().into(),
                })
                .collect(),
        }
    }
    pub fn encode(&self) -> Result<String, AppError> {
        self.validate()?;
        encode(AuditEventKind::SkillSnapshotV1, self)
    }
    pub fn decode(value: &str) -> Result<Self, AppError> {
        let decoded: Self = decode(AuditEventKind::SkillSnapshotV1, value)?;
        decoded.validate()?;
        Ok(decoded)
    }
    pub fn identity(&self) -> Result<SkillSnapshotId, AppError> {
        self.validate()?;
        let mut bytes = b"irmind-skill-snapshot-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| invalid())?);
        Ok(SkillSnapshotId(sha256(&bytes)))
    }
    pub fn package(&self) -> Result<SkillPackage, AppError> {
        let resources = self
            .files
            .iter()
            .map(|f| SkillResource::new(&f.path, f.contents.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let package = SkillPackage::new(resources)?;
        if hex(package.hash().as_bytes()) != self.package_sha256 {
            return Err(invalid());
        }
        Ok(package)
    }
    pub fn compile(&self, compiler: &dyn SkillCompiler) -> Result<CompiledSkill, AppError> {
        self.validate()?;
        let skill = compiler.compile(self.package()?)?;
        if skill.metadata().name().as_str() != self.name
            || skill.metadata().version().as_str() != self.skill_version
        {
            return Err(invalid());
        }
        Ok(skill)
    }
    fn validate(&self) -> Result<(), AppError> {
        if self.format_version != 1
            || self.target_schema != COMMON_EVENT_V1
            || self.interpreter != "irmind-skill-interpreter-v1"
            || self.files.len() > 17
            || self.files.windows(2).any(|p| p[0].path >= p[1].path)
        {
            return Err(invalid());
        }
        SkillName::parse(&self.name)?;
        SkillVersion::parse(&self.skill_version)?;
        match (
            self.origin,
            &self.release_inventory_sha256,
            &self.admission_operation_sha256,
        ) {
            (SkillOrigin::Bundled, Some(value), None)
            | (SkillOrigin::Analyst | SkillOrigin::Organization, None, Some(value)) => {
                hash(value)?;
            }
            _ => return Err(invalid()),
        }
        self.package()?;
        Ok(())
    }
    pub fn name(&self) -> Result<SkillName, AppError> {
        SkillName::parse(&self.name).map_err(Into::into)
    }
    pub const fn origin(&self) -> SkillOrigin {
        self.origin
    }
    pub fn version(&self) -> &str {
        &self.skill_version
    }
    pub fn admission(&self) -> Option<&str> {
        self.admission_operation_sha256.as_deref()
    }
    pub fn inventory(&self) -> Option<&str> {
        self.release_inventory_sha256.as_deref()
    }
}
impl std::fmt::Debug for SkillSnapshotV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillSnapshotV1")
            .field("name", &self.name)
            .field("sha256", &self.package_sha256)
            .finish_non_exhaustive()
    }
}
