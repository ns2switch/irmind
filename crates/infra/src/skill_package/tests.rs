use super::*;
use irmind_domain::SkillResource;

fn document() -> String {
    "+++\nformat = \"irmind-skill-v1\"\nname = \"windows-triage\"\ndescription = \"Review synthetic evidence.\"\nversion = \"0.1.0\"\nauthor = \"PRIVATE_AUTHOR\"\nlicense = \"MIT OR Apache-2.0\"\ntarget_schema = \"irmind-common-event-v1\"\ntools = [\"text_search\"]\nsources = [\"parser-evtx\"]\ncategories = [\"authentication\"]\ninvocable = true\n+++\n# Method\nPRIVATE_METHOD\n".into()
}

fn decode(document: &str) -> Result<CompiledSkill, SkillError> {
    let package = SkillPackage::new([SkillResource::new("SKILL.md", document.as_bytes())?])?;
    decode_skill_package(package)
}

#[test]
fn toml_metadata_and_exact_body_location_are_decoded_without_authorizing_content() {
    for document in [document(), document().replace('\n', "\r\n")] {
        let decoded = decode(&document).unwrap();
        assert_eq!(decoded.metadata().name().as_str(), "windows-triage");
        assert!(document[decoded.body_offset()..].starts_with("# Method"));
        assert_eq!(decoded.package().bytes(), document.len());
        assert!(!format!("{decoded:?}").contains("PRIVATE_METHOD"));
        assert!(!format!("{decoded:?}").contains("PRIVATE_AUTHOR"));
    }
}

#[test]
fn unknown_and_duplicate_frontmatter_fields_fail_without_echoing_values() {
    let unknown = document().replace(
        "invocable = true",
        "invocable = true\ncredential = \"PRIVATE_CREDENTIAL\"",
    );
    let duplicate = document().replace("invocable = true", "invocable = true\nname = \"other\"");
    for document in [unknown, duplicate] {
        let error = decode(&document).unwrap_err();
        assert_eq!(error, SkillError::InvalidFrontmatter);
        assert!(!error.to_string().contains("PRIVATE_CREDENTIAL"));
    }
}

#[test]
fn wildcard_unknown_tools_and_unknown_semantic_labels_are_rejected() {
    assert_eq!(
        decode(&document().replace("text_search", "*tool")).unwrap_err(),
        SkillError::InvalidMetadata
    );
    assert_eq!(
        decode(&document().replace("text_search", "unknown_tool")).unwrap_err(),
        SkillError::UnknownTool
    );
    assert_eq!(
        decode(&document().replace("authentication", "securityish")).unwrap_err(),
        SkillError::InvalidMetadata
    );
    assert_eq!(
        decode(&document().replace("irmind-common-event-v1", "ecs-latest")).unwrap_err(),
        SkillError::UnsupportedSchema
    );
}

#[test]
fn missing_or_oversized_frontmatter_and_empty_methodology_are_rejected() {
    assert_eq!(
        decode("# No frontmatter\n").unwrap_err(),
        SkillError::InvalidFrontmatter
    );
    assert_eq!(
        decode(&document().replace("+++\n# Method\nPRIVATE_METHOD\n", "+++")).unwrap_err(),
        SkillError::MissingMethodology
    );
    let large = document().replacen(
        "+++\n",
        &format!("+++\n# {}\n", "x".repeat(MAX_SKILL_HEADER_BYTES)),
        1,
    );
    assert_eq!(decode(&large).unwrap_err(), SkillError::LimitExceeded);
}

#[test]
fn executable_code_fences_are_not_accepted_as_query_or_reference_data() {
    for fence in [
        "```sh\necho PRIVATE\n```",
        "~~~python\nprint(1)\n~~~",
        "```rust\nfn main() {}\n```",
    ] {
        let text = document() + fence;
        assert_eq!(decode(&text).unwrap_err(), SkillError::UnsupportedResource);
    }
    assert!(decode(&(document() + "```json\n{}\n```\n")).is_ok());
    assert_eq!(
        decode(&(document() + "```json\n{}")).unwrap_err(),
        SkillError::UnsupportedResource
    );
}

#[test]
fn query_and_reference_resources_are_hashed_and_checked_without_interpretation() {
    let method = SkillResource::new("SKILL.md", document().as_bytes()).unwrap();
    let resource = SkillResource::new(
        "queries/failures.json",
        b"{\"tool\":\"text_search\",\"arguments\":{\"query\":\"failure\"}}",
    )
    .unwrap();
    let decoded =
        decode_skill_package(SkillPackage::new([method.clone(), resource]).unwrap()).unwrap();
    assert_eq!(decoded.package().resources().len(), 2);
    let invalid = SkillResource::new("queries/failures.json", b"{not json}").unwrap();
    assert_eq!(
        decode_skill_package(SkillPackage::new([method.clone(), invalid]).unwrap()).unwrap_err(),
        SkillError::UnsupportedResource
    );
    let reference = SkillResource::new("references/status.toml", b"[unterminated").unwrap();
    assert_eq!(
        decode_skill_package(SkillPackage::new([method, reference]).unwrap()).unwrap_err(),
        SkillError::UnsupportedResource
    );
}
