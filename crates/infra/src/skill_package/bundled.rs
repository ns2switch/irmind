//! Compiled-in methodology candidates. Presence never implies activation.
use super::{CompiledSkill, SkillError, SkillPackage, decode_skill_package};
use irmind_domain::SkillResource;

mod inventory;

pub fn bundled_skill_candidates() -> Result<Vec<CompiledSkill>, SkillError> {
    inventory::METHODS
        .iter()
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
    fn unchanged_initial_packages_keep_their_published_identities() {
        let packages = bundled_skill_candidates().unwrap();
        for (name, hash) in [
            (
                "linux-triage",
                "be4a83e88922a5b0fec026cd96d7b3d8eaf6e9f81487e5a60fca411d4d9f42e5",
            ),
            (
                "windows-triage",
                "50ca091e3379c589017459d1d210dec8d571b0c16f9e8e1e45312bc587bce57d",
            ),
        ] {
            let package = packages
                .iter()
                .find(|s| s.metadata().name().as_str() == name)
                .unwrap();
            assert_eq!(irmind_app::hex(package.package().hash().as_bytes()), hash);
        }
    }

    #[test]
    fn bundled_methods_use_the_shared_compiler_guard_and_immutable_package_contract() {
        let methods = bundled_skill_candidates().unwrap();
        assert_eq!(methods.len(), 23);
        let names: Vec<_> = methods
            .iter()
            .map(|m| m.metadata().name().as_str())
            .collect();
        assert_eq!(
            names,
            [
                "aws-credential-compromise",
                "aws-s3-data-exfiltration",
                "azure-entra-identity-compromise",
                "endpoint-edr-triage",
                "gcp-service-account-abuse",
                "github-supply-chain",
                "google-workspace-compromise",
                "k8s-cluster-compromise",
                "k8s-workload-compromise",
                "linux-persistence",
                "linux-triage",
                "linux-webshell",
                "m365-bec",
                "macos-compromise",
                "malware-execution-triage",
                "network-c2-beaconing",
                "okta-identity-compromise",
                "phishing-email-triage",
                "web-server-compromise",
                "windows-lateral-movement",
                "windows-persistence",
                "windows-ransomware",
                "windows-triage",
            ]
        );
        let expected: std::collections::BTreeMap<String, String> =
            serde_json::from_str(include_str!("../../../../skills/package-identities.json"))
                .unwrap();
        let guard = irmind_security::MandatoryGuard::new().unwrap();
        for method in methods {
            assert_eq!(method.package().resources().len(), 2);
            let version = match method.metadata().name().as_str() {
                "gcp-service-account-abuse"
                | "network-c2-beaconing"
                | "azure-entra-identity-compromise" => "0.1.2",
                "aws-credential-compromise" | "aws-s3-data-exfiltration" => "0.1.1",
                _ => "0.1.0",
            };
            assert_eq!(method.metadata().version().as_str(), version);
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
                let screened = guard.screen(resource.untrusted_text()).unwrap();
                assert!(
                    screened.detections.is_empty(),
                    "{} {}: {:?}",
                    method.metadata().name().as_str(),
                    resource.path().as_str(),
                    screened.detections
                );
            }
        }
    }
}
