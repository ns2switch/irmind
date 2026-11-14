use super::{AppError, CaseId, EvidenceHash, OriginalReader, Path, unavailable};
use irmind_app::Repository as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[derive(Default)]
pub(super) struct Authority {
    case: Option<CaseId>,
    generation: u64,
    roots: Vec<PathBuf>,
    sources: BTreeMap<EvidenceHash, usize>,
}
pub(super) struct Snapshot {
    pub root: Option<PathBuf>,
    pub generation: u64,
}
impl Authority {
    fn activate(&mut self, case: &CaseId) {
        if self.case.as_ref() != Some(case) {
            self.case = Some(case.clone());
            self.generation = self.generation.wrapping_add(1);
            self.roots.clear();
            self.sources.clear();
        }
    }
    pub(super) fn snapshot(&mut self, case: &CaseId, hash: &EvidenceHash) -> Snapshot {
        self.activate(case);
        Snapshot {
            root: self
                .sources
                .get(hash)
                .and_then(|n| self.roots.get(*n))
                .cloned(),
            generation: self.generation,
        }
    }
    pub(super) fn matches(&self, case: &CaseId, generation: u64) -> bool {
        self.case.as_ref() == Some(case) && self.generation == generation
    }
    fn authorize(
        &mut self,
        case: &CaseId,
        root: PathBuf,
        hashes: &[EvidenceHash],
    ) -> Result<(), AppError> {
        self.activate(case);
        let root_id = self
            .roots
            .iter()
            .position(|p| p == &root)
            .unwrap_or(self.roots.len());
        let additional = hashes
            .iter()
            .filter(|h| !self.sources.contains_key(*h))
            .collect::<BTreeSet<_>>()
            .len();
        if root_id >= 16 || self.sources.len() + additional > 16_384 {
            return Err(unavailable(
                "Original-source authorization capacity reached (16 roots, 16384 hashes); no additional root was authorized",
            ));
        }
        if root_id == self.roots.len() {
            self.roots.push(root);
        }
        for hash in hashes {
            self.sources.insert(hash.clone(), root_id);
        }
        Ok(())
    }
}
impl OriginalReader {
    pub(super) fn authorize(
        &self,
        case: &CaseId,
        root: &Path,
        hashes: &[EvidenceHash],
    ) -> Result<(), AppError> {
        self.store.get_case(case)?;
        if hashes.is_empty() {
            self.authority
                .lock()
                .map_err(crate::storage)?
                .activate(case);
            return Ok(());
        }
        if hashes.len() > 16_384 {
            return Err(unavailable("Too many original source authorizations"));
        }
        let metadata = std::fs::symlink_metadata(root).map_err(|_| {
            unavailable("Originals directory is unavailable; select a readable local directory")
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(unavailable(
                "Originals root must be a local directory, not a symbolic link",
            ));
        }
        let root = std::fs::canonicalize(root).map_err(crate::storage)?;
        if root.as_os_str().len() > 4096 {
            return Err(unavailable("Originals directory path is too long"));
        }
        let catalog = self.store.query_catalog(case)?;
        let known = catalog
            .iter()
            .flat_map(irmind_domain::ParquetArtifact::source_hashes)
            .collect::<BTreeSet<_>>();
        if hashes.iter().any(|h| !known.contains(h)) {
            return Err(unavailable(
                "Original source is not in this case's signed active inventory",
            ));
        }
        self.authority
            .lock()
            .map_err(crate::storage)?
            .authorize(case, root, hashes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn case(n: u8) -> CaseId {
        CaseId::parse(&format!("00000000-0000-4000-8000-{n:012}")).unwrap()
    }
    fn hash(n: u32) -> EvidenceHash {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        EvidenceHash::from_bytes(bytes)
    }
    #[test]
    fn authorization_limits_are_atomic_and_case_changes_clear_every_root() {
        let mut state = Authority::default();
        let id = case(1);
        let source = hash(1);
        for n in 0..16 {
            state
                .authorize(
                    &id,
                    PathBuf::from(format!("root-{n}")),
                    std::slice::from_ref(&source),
                )
                .unwrap();
        }
        let previous = state.snapshot(&id, &source);
        assert!(
            state
                .authorize(&id, PathBuf::from("extra-root"), &[hash(2)])
                .is_err()
        );
        assert_eq!(state.roots.len(), 16);
        assert_eq!(state.sources.len(), 1);
        assert_eq!(state.snapshot(&id, &source).root, previous.root);
        state.activate(&case(2));
        assert!(state.roots.is_empty());
        assert!(state.sources.is_empty());
        assert!(!state.matches(&id, previous.generation));
    }
    #[test]
    fn hash_capacity_counts_distinct_sources_and_never_inserts_a_partial_batch() {
        let mut state = Authority::default();
        let id = case(1);
        let sources = (0..16_384).map(hash).collect::<Vec<_>>();
        state
            .authorize(&id, PathBuf::from("root"), &sources)
            .unwrap();
        assert!(
            state
                .authorize(&id, PathBuf::from("root"), &[hash(1), hash(20_000)])
                .is_err()
        );
        assert_eq!(state.sources.len(), 16_384);
        assert!(!state.sources.contains_key(&hash(20_000)));
        state
            .authorize(&id, PathBuf::from("root"), &[hash(1), hash(1)])
            .unwrap();
        assert_eq!(state.sources.len(), 16_384);
    }
}
