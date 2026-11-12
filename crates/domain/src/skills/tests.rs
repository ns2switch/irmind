use super::*;

fn input() -> SkillMetadataInput {
    SkillMetadataInput {
        format: SKILL_FORMAT_V1.into(),
        name: "windows-triage".into(),
        description: "Inspect synthetic Windows evidence.".into(),
        version: "0.1.0".into(),
        author: "Untrusted author PRIVATE_MARKER".into(),
        license: "MIT OR Apache-2.0".into(),
        target_schema: crate::COMMON_EVENT_V1.into(),
        tools: vec!["text_search".into()],
        sources: vec!["parser-evtx".into()],
        categories: vec!["authentication".into()],
        invocable: true,
    }
}

#[test]
fn metadata_is_typed_but_not_trusted_or_a_permission_grant() {
    let metadata = SkillMetadata::new(input()).unwrap();
    assert_eq!(metadata.name().as_str(), "windows-triage");
    assert_eq!(metadata.version().as_str(), "0.1.0");
    assert_eq!(
        metadata.description(),
        "Inspect synthetic Windows evidence."
    );
    assert_eq!(metadata.license(), "MIT OR Apache-2.0");
    assert_eq!(metadata.target_schema(), crate::COMMON_EVENT_V1);
    assert!(metadata.tools().contains("text_search"));
    assert!(metadata.sources().contains("parser-evtx"));
    assert!(
        metadata
            .categories()
            .contains(&crate::EventCategory::Authentication)
    );
    assert!(metadata.invocable());
    assert!(metadata.author().contains("PRIVATE_MARKER"));
    assert!(!format!("{metadata:?}").contains("PRIVATE_MARKER"));
}

#[test]
fn names_and_versions_cannot_be_paths_or_command_arguments() {
    for name in [
        "",
        "Windows",
        "-first",
        "last-",
        "two--parts",
        "a_b",
        "a/b",
        "a\nhelp",
    ] {
        assert!(SkillName::parse(name).is_err(), "{name:?}");
    }
    assert!(SkillName::parse(&"a".repeat(49)).is_err());
    for version in ["", "../../v1", "v1;exit", "v1\n", "v1/one", "v1 "] {
        assert!(SkillVersion::parse(version).is_err());
    }
}

#[test]
fn unknown_schema_format_license_and_categories_fail_closed() {
    let mut value = input();
    value.target_schema = "ecs-latest".into();
    assert_eq!(
        SkillMetadata::new(value),
        Err(SkillError::UnsupportedSchema)
    );
    let mut value = input();
    value.format = "irmind-skill-v2".into();
    assert_eq!(
        SkillMetadata::new(value),
        Err(SkillError::UnsupportedFormat)
    );
    let mut value = input();
    value.license = "unknown license".into();
    assert_eq!(
        SkillMetadata::new(value),
        Err(SkillError::UnsupportedLicense)
    );
    let mut value = input();
    value.categories = vec!["made-up-category".into()];
    assert_eq!(SkillMetadata::new(value), Err(SkillError::InvalidMetadata));
}

#[test]
fn descriptions_declarations_and_lists_are_bounded_and_unambiguous() {
    for description in [
        "line\nbreak".into(),
        "x".repeat(257),
        "\u{202e}hidden".into(),
    ] {
        let mut value = input();
        value.description = description;
        assert!(SkillMetadata::new(value).is_err());
    }
    let mut value = input();
    value.tools = vec!["*".into()];
    assert!(SkillMetadata::new(value).is_err());
    let mut value = input();
    value.tools = vec!["text_search".into(); 33];
    assert_eq!(SkillMetadata::new(value), Err(SkillError::LimitExceeded));
    let mut value = input();
    value.sources.push("parser-evtx".into());
    assert_eq!(SkillMetadata::new(value), Err(SkillError::InvalidMetadata));
    let mut value = input();
    value.categories.push("authentication".into());
    assert_eq!(SkillMetadata::new(value), Err(SkillError::InvalidMetadata));
    let mut value = input();
    value.sources.clear();
    value.categories.clear();
    assert_eq!(SkillMetadata::new(value), Err(SkillError::InvalidMetadata));
}

#[test]
fn resource_paths_reject_platform_traversal_scripts_and_aliases() {
    for path in [
        "../SKILL.md",
        "/SKILL.md",
        "C:\\SKILL.md",
        "\\\\host\\file",
        "references/a/../x.md",
        "references/%2e%2e.md",
        "references/con.md",
        "queries/LPT1.json",
        "rules/COM2.yaml",
        "queries/a.json:stream",
        "queries/a..json",
        "references/é.md",
    ] {
        assert!(SkillResourcePath::parse(path).is_err(), "{path}");
    }
    for path in [
        "run.sh",
        "references/run.sh",
        "queries/call.py",
        "rules/plugin.dll",
        "references/payload.zip",
    ] {
        assert!(SkillResourcePath::parse(path).is_err(), "{path}");
    }
    assert!(SkillResourcePath::parse("references/CONNECTION.md").is_ok());
}

fn golden_package(reverse: bool) -> SkillPackage {
    let method = SkillResource::new("SKILL.md", b"# Method\nUse signed evidence.\n").unwrap();
    let terms =
        SkillResource::new("references/terms.csv", b"term,meaning\nactor,initiator\n").unwrap();
    SkillPackage::new(if reverse {
        vec![terms, method]
    } else {
        vec![method, terms]
    })
    .unwrap()
}

#[test]
fn inventory_has_new_golden_bytes_and_does_not_depend_on_input_order() {
    let package = golden_package(false);
    let hex = |bytes: &[u8]| {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            write!(&mut out, "{byte:02x}").unwrap();
            out
        })
    };
    assert_eq!(
        hex(&package.canonical_inventory()),
        "69726d696e642d736b696c6c2d7061636b6167652d76310000000000000000020000000000000008534b494c4c2e6d64000000000000001e0fc6a086a4ac34491edab1b0c9de4b445d07645a0a0cf3bd381f91724fb0fbda00000000000000147265666572656e6365732f7465726d732e637376000000000000001d71adfa5e79a7a346d9d19ff5665f92d68a56a525e9e183e93bc169cd7915d823"
    );
    assert_eq!(
        hex(package.hash().as_bytes()),
        "b4ef1718a0644046d26804100484160a647742a857abfe534b4261ccb67d588b"
    );
    assert_eq!(package, golden_package(true));
}

#[test]
fn changing_resource_content_or_path_changes_package_commitment() {
    let original = golden_package(false);
    for (path, text) in [
        ("references/terms.csv", "different"),
        ("references/other.csv", "term,meaning\nactor,initiator\n"),
    ] {
        let changed = SkillPackage::new([
            SkillResource::new("SKILL.md", b"# Method\nUse signed evidence.\n").unwrap(),
            SkillResource::new(path, text.as_bytes()).unwrap(),
        ])
        .unwrap();
        assert_ne!(changed.hash(), original.hash());
    }
}

#[test]
fn case_fold_collisions_and_missing_methodology_are_rejected() {
    let one = SkillResource::new("references/Readme.md", b"one").unwrap();
    let two = SkillResource::new("references/readme.md", b"two").unwrap();
    assert_eq!(
        SkillPackage::new([one, two]),
        Err(SkillError::DuplicatePath)
    );
    assert_eq!(SkillPackage::new([]), Err(SkillError::MissingMethodology));
}

#[test]
fn package_and_file_caps_are_enforced_while_reading_the_iterator() {
    assert!(SkillResource::new("SKILL.md", &vec![b'x'; MAX_SKILL_BYTES + 1]).is_err());
    let resources = std::iter::once(SkillResource::new("SKILL.md", b"method").unwrap())
        .chain((0..17).map(|i| SkillResource::new(&format!("references/{i}.md"), b"x").unwrap()));
    assert_eq!(SkillPackage::new(resources), Err(SkillError::LimitExceeded));
    let resources = std::iter::once(SkillResource::new("SKILL.md", b"method").unwrap()).chain(
        (0..4).map(|i| {
            SkillResource::new(
                &format!("references/{i}.md"),
                &vec![b'x'; MAX_SKILL_RESOURCE_BYTES],
            )
            .unwrap()
        }),
    );
    assert_eq!(SkillPackage::new(resources), Err(SkillError::LimitExceeded));
}

#[test]
fn invalid_text_is_rejected_and_debug_and_errors_do_not_disclose_content() {
    for bytes in [b"\xff".as_slice(), b"\x1b[2J", b"nul\0", b"bare\rreturn"] {
        assert!(SkillResource::new("SKILL.md", bytes).is_err());
    }
    let resource = SkillResource::new("SKILL.md", b"PRIVATE_CONTENT\r\n").unwrap();
    assert_eq!(resource.untrusted_text(), "PRIVATE_CONTENT\r\n");
    assert!(!format!("{resource:?}").contains("PRIVATE_CONTENT"));
    assert!(!format!("{:?}", SkillPackage::new([resource]).unwrap()).contains("PRIVATE_CONTENT"));
    assert!(
        !SkillError::InvalidText
            .to_string()
            .contains("PRIVATE_CONTENT")
    );
}
