#![forbid(unsafe_code)]

use cargo_metadata::MetadataCommand;
use std::collections::BTreeSet;

fn layer(name: &str) -> Result<u8, String> {
    match name {
        "irmind-domain" => Ok(0),
        "irmind-app" => Ok(1),
        "irmind" => Ok(3),
        name if name.starts_with("irmind-") => Ok(2),
        _ => Err(format!("unclassified workspace crate: {name}")),
    }
}

fn check_edge(from: &str, to: &str) -> Result<(), String> {
    if layer(from)? < layer(to)? {
        return Err(format!("reverse dependency: {from} -> {to}"));
    }
    Ok(())
}

#[test]
fn workspace_dependencies_point_inward() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = MetadataCommand::new().no_deps().exec()?;
    let members = metadata
        .workspace_packages()
        .into_iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    for package in metadata.workspace_packages() {
        layer(package.name.as_str())?;
        for dependency in &package.dependencies {
            if members.contains(dependency.name.as_str()) {
                check_edge(package.name.as_str(), dependency.name.as_str())?;
            }
        }
    }
    Ok(())
}

#[test]
fn deliberate_reverse_edge_is_rejected() {
    assert!(check_edge("irmind-domain", "irmind-app").is_err());
    assert!(check_edge("irmind-app", "irmind-domain").is_ok());
}
