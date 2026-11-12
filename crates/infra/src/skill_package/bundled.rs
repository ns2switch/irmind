//! Compiled-in methodology candidates. Presence never implies activation.
use super::{CompiledSkill, SkillError, SkillPackage, decode_skill_package};
use irmind_domain::SkillResource;

pub fn bundled_skill_candidates() -> Result<Vec<CompiledSkill>, SkillError> {
    let methods = [
        (
            include_bytes!("../../../../skills/aws-credential-compromise/SKILL.md").as_slice(),
            "references/operations.csv",
            include_bytes!(
                "../../../../skills/aws-credential-compromise/references/operations.csv"
            )
            .as_slice(),
        ),
        (
            include_bytes!("../../../../skills/linux-triage/SKILL.md").as_slice(),
            "references/coverage.csv",
            include_bytes!("../../../../skills/linux-triage/references/coverage.csv").as_slice(),
        ),
        (
            include_bytes!("../../../../skills/windows-triage/SKILL.md").as_slice(),
            "references/event-ids.csv",
            include_bytes!("../../../../skills/windows-triage/references/event-ids.csv").as_slice(),
        ),
    ];
    methods
        .into_iter()
        .map(|(method, reference, contents)| {
            let package = SkillPackage::new([
                SkillResource::new("SKILL.md", method)?,
                SkillResource::new(reference, contents)?,
            ])?;
            decode_skill_package(package)
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::TomlSkillCompiler;
    use irmind_app::ContentGuard as _;

    #[test]
    fn initial_methods_use_the_shared_compiler_guard_and_immutable_package_contract() {
        let methods = bundled_skill_candidates().unwrap();
        assert_eq!(methods.len(), 3);
        let names: Vec<_> = methods
            .iter()
            .map(|m| m.metadata().name().as_str())
            .collect();
        assert_eq!(
            names,
            [
                "aws-credential-compromise",
                "linux-triage",
                "windows-triage"
            ]
        );
        let expected: std::collections::BTreeMap<String, String> =
            serde_json::from_str(include_str!("../../../../skills/package-identities.json"))
                .unwrap();
        let guard = irmind_security::MandatoryGuard::new().unwrap();
        for method in methods {
            assert_eq!(method.package().resources().len(), 2);
            assert_eq!(method.metadata().version().as_str(), "0.1.0");
            assert_eq!(
                expected.get(method.metadata().name().as_str()),
                Some(&irmind_app::hex(method.package().hash().as_bytes()))
            );
            irmind_testkit::run_skill_compiler_contract(&TomlSkillCompiler, method.package())
                .unwrap();
            assert!(
                !method
                    .metadata()
                    .tools()
                    .iter()
                    .any(|tool| tool.starts_with("siem_")
                        || tool.starts_with("ti_")
                        || tool.starts_with("cloud_"))
            );
            for resource in method.package().resources().values() {
                assert!(
                    guard
                        .screen(resource.untrusted_text())
                        .unwrap()
                        .detections
                        .is_empty()
                );
            }
        }
    }
}
