use super::definition::{Conversion, Definition, Scope};
use irmind_app::source_mapping::MappingError;

pub(super) fn validate_definition(definition: &Definition) -> Result<(), MappingError> {
    for field in definition
        .fields
        .iter()
        .chain(definition.rules.iter().flat_map(|r| &r.fields))
    {
        for observation in field.observation.iter().chain(&field.observations) {
            let Scope::ProviderProcess {
                provider,
                tenant,
                host,
            } = &observation.scope
            else {
                continue;
            };
            let source = field.source.iter().map(String::as_str).collect::<Vec<_>>();
            let allowed = match field.target.as_str() {
                "process.entity_id" => {
                    matches!(source.as_slice(), ["TargetProcessId" | "ContextProcessId"])
                        && observation.role == "subject"
                }
                "process.parent.entity_id" => {
                    source == ["ParentProcessId"] && observation.role == "parent"
                }
                _ => false,
            };
            if definition.parser != "parser-fdr"
                || definition.parser_versions != ["fdr-source-v1"]
                || definition.format.as_deref() != Some("falcon-fdr")
                || definition.format_version.as_deref() != Some("fdr-source-v1")
                || definition
                    .partition
                    .host
                    .as_ref()
                    .is_none_or(|p| p.as_slice() != ["aid"])
                || provider != "crowdstrike-fdr"
                || tenant != &["cid"]
                || host != &["aid"]
                || !allowed
                || observation.kind != "process"
                || field.source_index.is_some()
                || !matches!(field.conversion, Conversion::U64Id)
            {
                return Err(MappingError::InvalidDefinition);
            }
        }
    }
    Ok(())
}
