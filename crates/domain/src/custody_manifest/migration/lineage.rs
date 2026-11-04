use super::{DigestStream, ParquetMigrationV1, invalid};
use crate::{DomainError, EvidenceHash, ParquetArtifact};
use std::collections::{BTreeMap, BTreeSet};

/// Pure signed-history interpretation. Pending replacements never enter the
/// active set before the complete migration commitment is accepted.
pub struct ArtifactLineage {
    all: Vec<ParquetArtifact>,
    retired: BTreeSet<String>,
    paths: BTreeSet<String>,
    active_generations: BTreeMap<EvidenceHash, ParquetArtifact>,
    pending: Vec<ParquetArtifact>,
    parsers: BTreeMap<EvidenceHash, (String, String)>,
    manifests: BTreeSet<EvidenceHash>,
    digest: DigestStream,
}

impl ArtifactLineage {
    pub fn new(digest: DigestStream) -> Self {
        Self {
            all: Vec::new(),
            retired: BTreeSet::new(),
            paths: BTreeSet::new(),
            active_generations: BTreeMap::new(),
            pending: Vec::new(),
            parsers: BTreeMap::new(),
            manifests: BTreeSet::new(),
            digest,
        }
    }

    pub fn source(
        &mut self,
        hash: EvidenceHash,
        id: &str,
        version: &str,
        manifest: bool,
    ) -> Result<(), DomainError> {
        if id.is_empty() || version.is_empty() {
            return Err(invalid());
        }
        self.parsers
            .entry(hash.clone())
            .or_insert_with(|| (id.into(), version.into()));
        if manifest {
            self.manifests.insert(hash);
        }
        Ok(())
    }

    pub fn artifact(&mut self, artifact: ParquetArtifact) -> Result<(), DomainError> {
        artifact.validate()?;
        if matches!(&artifact,ParquetArtifact::V2(v) if !matches!(v.builder_version.as_str(),"parquet-builder-v2"|"parquet-builder-v3"))
        {
            return Err(invalid());
        }
        if self.paths.contains(artifact.path())
            || artifact
                .source_hashes()
                .iter()
                .any(|h| !self.parsers.contains_key(h))
        {
            return Err(invalid());
        }
        if matches!(&artifact, ParquetArtifact::V2(v) if !v.superseded_hashes.is_empty()) {
            self.paths.insert(artifact.path().into());
            self.pending.push(artifact);
            return Ok(());
        }
        if !self.pending.is_empty() {
            return Err(invalid());
        }
        if artifact.source_hashes().iter().any(|h| {
            self.active_generations
                .get(h)
                .is_some_and(|old| !old.same_generation(&artifact))
        }) {
            return Err(invalid());
        }
        if let ParquetArtifact::V2(v) = &artifact
            && v.source_hashes.iter().any(|h| {
                !self.manifests.contains(h)
                    || self.parsers.get(h) != Some(&(v.parser_id.clone(), v.parser_version.clone()))
            })
        {
            return Err(invalid());
        }
        self.paths.insert(artifact.path().into());
        for hash in artifact.source_hashes() {
            self.active_generations
                .entry(hash.clone())
                .or_insert_with(|| artifact.clone());
        }
        self.all.push(artifact);
        Ok(())
    }

    pub fn migrate(&mut self, record: &ParquetMigrationV1) -> Result<(), DomainError> {
        let sources = super::sources(&self.pending);
        let previous = self
            .all
            .iter()
            .filter(|a| {
                !self.retired.contains(a.path())
                    && a.source_hashes().iter().any(|h| sources.contains(h))
            })
            .cloned()
            .collect::<Vec<_>>();
        if previous.is_empty()
            || previous
                .iter()
                .any(|a| a.source_hashes().iter().any(|h| !sources.contains(h)))
        {
            return Err(invalid());
        }
        let generation = ParquetMigrationV1::generation(&previous, self.digest)?;
        let directory = format!("migration-{}", generation.as_str());
        if self
            .pending
            .iter()
            .any(|a| !a.path().split('/').any(|part| part == directory))
            || families(&previous)? != families(&self.pending)?
        {
            return Err(invalid());
        }
        for a in &self.pending {
            validate_references(a, &previous)?;
        }
        let expected =
            ParquetMigrationV1::between(&previous, &self.pending, &self.parsers, self.digest)?;
        if &expected != record {
            return Err(invalid());
        }
        let mut new_parsers = BTreeMap::new();
        for a in &self.pending {
            let ParquetArtifact::V2(v) = a else {
                return Err(invalid());
            };
            for source in &v.source_hashes {
                let choice = (v.parser_id.clone(), v.parser_version.clone());
                if new_parsers
                    .insert(source.clone(), choice.clone())
                    .is_some_and(|old| old != choice)
                {
                    return Err(invalid());
                }
            }
        }
        self.retired
            .extend(previous.iter().map(|a| a.path().into()));
        self.manifests.extend(new_parsers.keys().cloned());
        self.parsers.extend(new_parsers);
        for artifact in &self.pending {
            for hash in artifact.source_hashes() {
                self.active_generations
                    .insert(hash.clone(), artifact.clone());
            }
        }
        self.all.append(&mut self.pending);
        Ok(())
    }

    pub fn active(&self) -> Result<Vec<ParquetArtifact>, DomainError> {
        if !self.pending.is_empty() {
            return Err(invalid());
        }
        Ok(self
            .all
            .iter()
            .filter(|a| !self.retired.contains(a.path()))
            .cloned()
            .collect())
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn all(&self) -> Result<&[ParquetArtifact], DomainError> {
        if !self.pending.is_empty() {
            return Err(invalid());
        }
        Ok(&self.all)
    }
}

fn validate_references(a: &ParquetArtifact, old: &[ParquetArtifact]) -> Result<(), DomainError> {
    let ParquetArtifact::V2(v) = a else {
        return Err(invalid());
    };
    if v.superseded_hashes.is_empty() || v.builder_version != "parquet-builder-v3" {
        return Err(invalid());
    }
    for hash in &v.superseded_hashes {
        if !old.iter().any(|a| {
            a.sha256() == hash
                && same_family(a.schema_version(), v.schema.as_str())
                && a.source_hashes()
                    .iter()
                    .any(|h| v.source_hashes.contains(h))
        }) {
            return Err(invalid());
        }
    }
    for source in &v.source_hashes {
        if !old.iter().any(|a| {
            a.source_hashes().contains(source)
                && same_family(a.schema_version(), v.schema.as_str())
                && v.superseded_hashes.contains(a.sha256())
        }) {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn same_family(a: &str, b: &str) -> bool {
    fn family(v: &str) -> Option<u8> {
        match v {
            "irmind-events-v2" | "irmind-events-v3" => Some(0),
            "irmind-entities-v1" | "irmind-entities-v2" | "irmind-entities-v3" => Some(1),
            "irmind-coobservations-v1" | "irmind-coobservations-v2" => Some(2),
            _ => None,
        }
    }
    family(a).is_some() && family(a) == family(b)
}

fn families(artifacts: &[ParquetArtifact]) -> Result<BTreeSet<(EvidenceHash, u8)>, DomainError> {
    let mut out = BTreeSet::new();
    for artifact in artifacts {
        let schema = artifact.schema_version();
        let family = if same_family(schema, "irmind-events-v3") {
            0
        } else if same_family(schema, "irmind-entities-v3") {
            1
        } else if same_family(schema, "irmind-coobservations-v2") {
            2
        } else {
            return Err(invalid());
        };
        for hash in artifact.source_hashes() {
            out.insert((hash.clone(), family));
        }
    }
    Ok(out)
}
