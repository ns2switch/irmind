use super::*;
use irmind_domain::{SkillMetadata, SkillMetadataInput, SkillPackage, SkillResource};

struct Compiler;
impl SkillCompiler for Compiler {
    fn compile(&self, package: SkillPackage) -> Result<CompiledSkill, AppError> {
        let metadata = SkillMetadata::new(SkillMetadataInput {
            format: "irmind-skill-v1".into(),
            name: "triage".into(),
            description: "Review synthetic records.".into(),
            version: "1".into(),
            author: "Community".into(),
            license: "MIT".into(),
            target_schema: "irmind-common-event-v1".into(),
            tools: vec!["text_search".into()],
            sources: vec!["parser-json".into()],
            categories: vec![],
            invocable: true,
        })?;
        Ok(CompiledSkill::new(metadata, package, 0)?)
    }
}
fn snapshot() -> Snapshot {
    let package =
        SkillPackage::new([
            SkillResource::new("SKILL.md", b"# Method\nSynthetic review.\n").unwrap(),
        ])
        .unwrap();
    Snapshot::new(&Compiler.compile(package).unwrap(), SkillOrigin::Analyst)
}

#[test]
fn installation_json_has_fixed_field_order_explicit_null_and_exact_package_commitment() {
    let bytes = serde_json::to_vec(&snapshot()).unwrap();
    let expected = concat!(
        "{\"format_version\":1,\"name\":\"triage\",\"skill_version\":\"1\",",
        "\"package_sha256\":\"f2c2ab563442f71e9f522e8311931f3a18def62561a01c987b23448929cf4a03\",\"origin\":\"analyst\",\"active\":true,",
        "\"previous_operation\":null,\"files\":[{\"path\":\"SKILL.md\",\"contents\":\"# Method\\nSynthetic review.\\n\"}]}"
    );
    assert_eq!(bytes, expected.as_bytes());
}

fn operation(snapshot: &Snapshot) -> SignedOperation {
    SignedOperation {
        case_id: "global".into(),
        seq: 0,
        at: 1,
        actor: irmind_domain::Actor::Analyst,
        operation: format!("{PREFIX}{}", hex(&serde_json::to_vec(snapshot).unwrap())),
        prev: [0; 32],
        hash: [1; 32],
        sig: vec![],
        public_key: vec![],
    }
}

#[test]
fn replay_rejects_relabelled_metadata_commitments_and_wrong_previous_links() {
    let mut changed = snapshot();
    changed.skill_version = "other".into();
    assert!(
        ApprovedSkills::default()
            .apply(&operation(&changed), &Compiler)
            .is_err()
    );
    let mut changed = snapshot();
    changed.package_sha256 = "0".repeat(64);
    assert!(
        ApprovedSkills::default()
            .apply(&operation(&changed), &Compiler)
            .is_err()
    );
    let mut history = ApprovedSkills::default();
    history.apply(&operation(&snapshot()), &Compiler).unwrap();
    assert!(history.apply(&operation(&snapshot()), &Compiler).is_err());
    let mut changed = snapshot();
    changed.previous_operation = Some(hex(&[1; 32]));
    history.apply(&operation(&changed), &Compiler).unwrap();
}

#[test]
fn replay_rejects_noncanonical_bytes_unknown_fields_and_uppercase_hex() {
    let original = operation(&snapshot());
    let payload = original.operation.strip_prefix(PREFIX).unwrap();
    let raw = String::from_utf8(hex::decode(payload).unwrap()).unwrap();
    for bytes in [format!(" {raw}"), raw.replacen('{', "{\"extra\":0,", 1)] {
        let mut changed = original.clone();
        changed.operation = format!("{PREFIX}{}", hex(bytes.as_bytes()));
        assert!(
            ApprovedSkills::default()
                .apply(&changed, &Compiler)
                .is_err()
        );
    }
    let mut changed = original.clone();
    changed.operation = format!("{PREFIX}{}", payload.to_uppercase());
    assert!(
        ApprovedSkills::default()
            .apply(&changed, &Compiler)
            .is_err()
    );
}
