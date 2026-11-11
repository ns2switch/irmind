use super::{
    CompiledRule, TableMapping,
    definition::{Condition, Definition, Predicate},
    fields, invalid,
};
use irmind_app::source_mapping::{
    ApprovedMappingDefinition, MappingError, MappingIdentityV1, MappingManifest, MappingProvenance,
    SelectorCondition, SelectorPredicate, SelectorScalar, SourceDiscriminator, SourceNumber,
    SourcePath, SourceSelector,
};
use irmind_domain::{
    CategorySet, EventCategory, EventHeaderV1, EventKind, EventOutcome, EventType, EventTypeSet,
    EvidenceHash, SOURCE_RECORD_V1,
};
use std::collections::{BTreeMap, BTreeSet};
const LIMIT: usize = 64 * 1024;

impl TableMapping {
    /// The caller supplies a digest pinned in the trusted binary/release manifest.
    pub fn bundled(contents: &str, expected: &EvidenceHash) -> Result<Self, MappingError> {
        let definition = parse_toml(contents)?;
        let canonical = serde_json::to_vec(&definition).map_err(invalid)?;
        if canonical.len() > LIMIT
            || EvidenceHash::from_bytes(irmind_app::sha256(&canonical)) != *expected
        {
            return Err(MappingError::InvalidDefinition);
        }
        let provenance = MappingProvenance::BundledDefinition {
            canonical,
            interpreter: definition.interpreter()?.into(),
        };
        Self::compile(definition, provenance)
    }
    /// Canonical data can be reviewed and signed without activating a mapper.
    pub fn review(contents: &str) -> Result<MappingManifest, MappingError> {
        let definition = parse_toml(contents)?;
        let canonical = serde_json::to_vec(&definition).map_err(invalid)?;
        let digest = EvidenceHash::from_bytes(irmind_app::sha256(&canonical));
        Self::bundled(contents, &digest).map(|mapper| mapper.manifest)
    }
    /// Only an opaque, verified global operation can authorize an installed definition.
    pub fn installed(approved: &ApprovedMappingDefinition) -> Result<Self, MappingError> {
        if !approved.active() {
            return Err(MappingError::InvalidDefinition);
        }
        let manifest = approved.installed_manifest()?;
        let MappingProvenance::InstalledDefinition { canonical, .. } = manifest.provenance() else {
            return Err(MappingError::InvalidDefinition);
        };
        let definition: Definition = serde_json::from_slice(canonical).map_err(invalid)?;
        if serde_json::to_vec(&definition).map_err(invalid)? != *canonical {
            return Err(MappingError::InvalidDefinition);
        }
        let compiled = Self::compile(definition, manifest.provenance().clone())?;
        if compiled.manifest != manifest {
            return Err(MappingError::InvalidDefinition);
        }
        Ok(compiled)
    }
    fn compile(
        definition: Definition,
        provenance: MappingProvenance,
    ) -> Result<Self, MappingError> {
        validate_interpreter(&definition, &provenance)?;
        if definition.source_contract != SOURCE_RECORD_V1
            || definition.rules.len() > 256
            || definition.fields.len() > 64
        {
            return Err(MappingError::InvalidDefinition);
        }
        if definition.when.len() > 8 {
            return Err(MappingError::InvalidDefinition);
        }
        let primary_selector = selector(
            &definition,
            definition
                .when
                .iter()
                .map(condition)
                .collect::<Result<_, _>>()?,
        )?;
        let mut rules: Vec<CompiledRule> = Vec::new();
        let primary_budget: usize = definition.when.iter().map(|c| c.path.len() + 1).sum();
        let mut budget = definition
            .fields
            .iter()
            .map(super::definition::Field::operation_budget)
            .sum::<usize>()
            + primary_budget;
        for rule in &definition.rules {
            let compiled = compile_rule(&definition, rule)?;
            budget += 1
                + primary_budget
                + rule.when.iter().map(|c| c.path.len() + 1).sum::<usize>()
                + rule
                    .fields
                    .iter()
                    .map(super::definition::Field::operation_budget)
                    .sum::<usize>();
            if rules
                .iter()
                .any(|old| old.selector.overlap_witness(&compiled.selector).is_some())
            {
                return Err(MappingError::InvalidDefinition);
            }
            rules.push(compiled);
        }
        if budget > 8192 {
            return Err(MappingError::InvalidDefinition);
        }
        let canonical = match &provenance {
            MappingProvenance::BundledDefinition { canonical, .. }
            | MappingProvenance::InstalledDefinition { canonical, .. } => canonical,
            MappingProvenance::NativeBuild { .. } => return Err(MappingError::InvalidDefinition),
        };
        let identity = MappingIdentityV1::try_new(
            &definition.id,
            &definition.version,
            &definition.target_schema,
            EvidenceHash::from_bytes(irmind_app::sha256(canonical)),
        )
        .map_err(invalid)?;
        Ok(Self {
            manifest: MappingManifest::try_new(
                identity,
                vec![primary_selector],
                provenance,
                false,
            )?,
            rules,
            fields: fields::compile_fields(definition.fields)?,
            partition: fields::CompiledPartition::compile(&definition.partition)?,
            action: definition.action.as_deref().map(fields::path).transpose()?,
        })
    }
}
fn validate_interpreter(
    d: &Definition,
    provenance: &MappingProvenance,
) -> Result<(), MappingError> {
    let expected = d.interpreter()?;
    let actual = match provenance {
        MappingProvenance::BundledDefinition { interpreter, .. }
        | MappingProvenance::InstalledDefinition { interpreter, .. } => interpreter,
        MappingProvenance::NativeBuild { .. } => return Err(MappingError::InvalidDefinition),
    };
    if actual != expected {
        return Err(MappingError::InvalidDefinition);
    }
    Ok(())
}
fn compile_rule(
    definition: &Definition,
    rule: &super::definition::Rule,
) -> Result<CompiledRule, MappingError> {
    if rule.when.len() > 8
        || rule.categories.len() > 20
        || rule.types.len() > 18
        || definition.fields.len() + rule.fields.len() > 64
    {
        return Err(MappingError::InvalidDefinition);
    }
    // Validate the complete selected field set, including duplicate destinations.
    let combined = definition
        .fields
        .iter()
        .chain(&rule.fields)
        .cloned()
        .collect();
    fields::compile_fields(combined)?;
    let selector = selector(
        definition,
        definition
            .when
            .iter()
            .chain(&rule.when)
            .map(condition)
            .collect::<Result<_, _>>()?,
    )?;
    let header = EventHeaderV1::new(
        CategorySet::new(
            rule.categories
                .iter()
                .map(|s| EventCategory::parse(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(invalid)?,
        ),
        EventTypeSet::new(
            rule.types
                .iter()
                .map(|s| EventType::parse(s))
                .collect::<Result<Vec<_>, _>>()
                .map_err(invalid)?,
        ),
        EventOutcome::parse(&rule.outcome).map_err(invalid)?,
        EventKind::parse(&rule.kind).map_err(invalid)?,
    );
    Ok(CompiledRule {
        selector,
        header,
        fields: fields::compile_fields(rule.fields.clone())?,
    })
}
fn parse_toml(contents: &str) -> Result<Definition, MappingError> {
    if contents.len() > LIMIT {
        return Err(MappingError::InvalidDefinition);
    }
    toml::from_str(contents).map_err(invalid)
}
fn selector(
    d: &Definition,
    conditions: Vec<SelectorCondition>,
) -> Result<SourceSelector, MappingError> {
    if d.parser_versions.len() > 128 {
        return Err(MappingError::InvalidDefinition);
    }
    let format = match (&d.format, &d.format_version) {
        (None, None) => None,
        (Some(id), Some(version)) => Some((id.clone(), version.clone())),
        _ => return Err(MappingError::InvalidDefinition),
    };
    let discriminators = [
        (SourceDiscriminator::Dataset, &d.dataset),
        (SourceDiscriminator::Provider, &d.provider),
        (SourceDiscriminator::Channel, &d.channel),
        (SourceDiscriminator::RecordType, &d.native_type),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.as_ref().map(|v| (key, v.clone())))
    .collect::<BTreeMap<_, _>>();
    SourceSelector::try_new(
        &d.parser,
        d.parser_versions.iter().cloned().collect::<BTreeSet<_>>(),
        format,
        discriminators,
        conditions,
    )
}
fn condition(c: &Condition) -> Result<SelectorCondition, MappingError> {
    let predicate = match &c.predicate {
        Predicate::Missing => SelectorPredicate::Missing,
        Predicate::Null => SelectorPredicate::Null,
        Predicate::Present => SelectorPredicate::Present,
        Predicate::Text(v) => SelectorPredicate::Exact(SelectorScalar::Text(v.clone())),
        Predicate::Boolean(v) => SelectorPredicate::Exact(SelectorScalar::Boolean(*v)),
        Predicate::Number(v) => SelectorPredicate::Exact(SelectorScalar::Number(
            SourceNumber::try_new(v).map_err(invalid)?,
        )),
        Predicate::IntegerInterval { first, last } => SelectorPredicate::IntegerInterval {
            first: i128::from(*first),
            last: i128::from(*last),
        },
    };
    Ok(SelectorCondition {
        path: SourcePath::keys(&c.path.iter().map(String::as_str).collect::<Vec<_>>())
            .map_err(invalid)?,
        predicate,
    })
}
