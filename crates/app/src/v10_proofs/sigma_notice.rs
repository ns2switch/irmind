//! Presentation from the result and table bound to an authenticated execution.
use super::{
    SIGMA_EVALUATOR_V3, SigmaClassCoverage, SigmaClassOutcome, SigmaRunResultsV3, SigmaRunStatusV1,
    V10ProofDescriptor, V10ProofFamily, sigma_execution,
};
use crate::{AppError, SignedEntry};
use irmind_domain::EvidenceHash;
use std::collections::BTreeMap;

/// The adapter resolves labels in the same ordinal order as the authenticated
/// TOML table using its existing field table parser.
pub struct SigmaProofRead {
    pub bytes: Vec<u8>,
    pub class_labels: Vec<String>,
}

pub struct SigmaV3Notice {
    pub receipt: EvidenceHash,
    pub coverage: SigmaClassCoverage,
    pub skipped_classes: Vec<(String, usize, usize)>,
    pub unavailable_rows: u64,
    pub indeterminate_rules: usize,
    pub stopped_early: bool,
}

impl crate::Engine<'_> {
    pub(crate) fn read_sigma_notice_proof(
        &self,
        case: &crate::CaseId,
        kind: u8,
        digest: [u8; 32],
        cancel: &crate::CancellationToken,
    ) -> Result<SigmaProofRead, AppError> {
        self.large_case_store
            .as_ref()
            .ok_or_else(|| AppError::Policy("Sigma proof storage is unavailable".into()))?
            .read_sigma_proof(case, kind, digest, cancel)
    }
}

impl SigmaV3Notice {
    pub fn resolve(
        entry: &SignedEntry,
        mut read: impl FnMut(u8, [u8; 32]) -> Result<SigmaProofRead, AppError>,
    ) -> Result<Option<Self>, AppError> {
        let run = sigma_execution(entry)?;
        if run.evaluator != SIGMA_EVALUATOR_V3 {
            return Ok(None);
        }
        let invalid = || AppError::InvalidChain(entry.seq);
        let mut checked = |kind, digest| {
            let object = read(kind, digest)?;
            if V10ProofDescriptor::from_body(V10ProofFamily::Sigma, kind, &object.bytes)
                .map_err(|_| invalid())?
                .hash()
                != digest
            {
                return Err(invalid());
            }
            Ok(object)
        };
        let table = checked(2, run.field_table)?;
        let body = checked(5, run.result_manifest)?;
        let results = SigmaRunResultsV3::decode(&body.bytes).map_err(|_| invalid())?;
        if results.status(run.status) != run.status
            || results.scan.results.matches.len() as u64 != run.matched_rows
        {
            return Err(invalid());
        }
        let mut skipped = BTreeMap::<usize, (usize, usize)>::new();
        for rule in 0..results.scan.results.coverage.len() {
            for (ordinal, state) in results.plan.row(rule) {
                let index = usize::try_from(ordinal).map_err(|_| invalid())?;
                match state {
                    SigmaClassOutcome::MissingBinding => skipped.entry(index).or_default().0 += 1,
                    SigmaClassOutcome::IncompatibleType => skipped.entry(index).or_default().1 += 1,
                    _ => {}
                }
            }
        }
        let skipped_classes = skipped
            .into_iter()
            .map(|(index, (missing, incompatible))| {
                let label = table.class_labels.get(index).ok_or_else(invalid)?;
                Ok((label.clone(), missing, incompatible))
            })
            .collect::<Result<_, AppError>>()?;
        Ok(Some(Self {
            receipt: EvidenceHash::from_bytes(entry.hash),
            coverage: results.plan.coverage(),
            skipped_classes,
            unavailable_rows: results
                .scan
                .unavailable_by_source
                .iter()
                .map(|(_, count)| count)
                .sum(),
            indeterminate_rules: results.scan.indeterminate_by_rule.len(),
            stopped_early: matches!(
                run.status,
                SigmaRunStatusV1::Cancelled
                    | SigmaRunStatusV1::OversizedInput
                    | SigmaRunStatusV1::TimeLimit
                    | SigmaRunStatusV1::WorkLimit
            ),
        }))
    }
}
