//! Bind the decoded proof bodies to their signed receipt before resolving material.
use super::{
    ReportAnalystSectionsV1, ReportCitationsV1, ReportCoverageV2, ReportPublishedV1,
    SigmaClassPlan, SigmaCompiledRulesV1, SigmaCoverageV1, SigmaFieldTableV1, SigmaPackAdmissionV1,
    SigmaPackManifestV1, SigmaRuleKeyV1, SigmaRunResultsV1, SigmaRunResultsV3, SigmaRunV2,
    SigmaSourceScopeV1, V10ArtifactReference, V10CheckpointView, V10ObjectSection, V10RowReference,
    V10SourceReference,
};
use crate::{AppError, CancellationToken, SignedEntry};
use irmind_domain::ParquetArtifact;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek},
};

type ProofKey = (u8, [u8; 32]);

pub struct V10SigmaRunObjects {
    pub field_table: SigmaFieldTableV1,
    pub class_plan: SigmaClassPlan,
    pub selected_sources: SigmaSourceScopeV1,
    pub compiled_rules: SigmaCompiledRulesV1,
    pub results: SigmaRunResultsV1,
    pub unavailable_by_source: Vec<(V10SourceReference, u64)>,
    pub indeterminate_by_rule: Vec<(SigmaRuleKeyV1, u64)>,
}

impl V10SigmaRunObjects {
    /// Resolve both coordinates against the authenticated case checkpoint.
    /// Check each artifact once even if several rules matched the same row.
    pub fn verify_case_rows(
        &self,
        entries: &[SignedEntry],
        receipt: &SigmaRunV2,
        mut verify_rows: impl FnMut(&ParquetArtifact, &[V10RowReference]) -> Result<(), AppError>,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let view = V10CheckpointView::resolve(entries, &receipt.checkpoint)?;
        for source in &self.selected_sources.0 {
            view.source(*source)?;
        }
        let mut active_bindings = BTreeSet::new();
        let mut artifacts = BTreeMap::<V10ArtifactReference, BTreeMap<u64, V10RowReference>>::new();
        for matched in &self.results.matches {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let row = matched.row;
            if self.selected_sources.0.binary_search(&row.source).is_err() {
                return Err(AppError::InvalidChain(row.source.manifest.sequence));
            }
            if active_bindings.insert((row.artifact, row.source)) {
                view.row_artifact(row)?;
            }
            if artifacts
                .entry(row.artifact)
                .or_default()
                .insert(row.physical_row, row)
                .is_some_and(|previous| previous != row)
            {
                return Err(AppError::InvalidChain(row.artifact.entry.sequence));
            }
        }
        for rows in artifacts.into_values() {
            let rows = rows.into_values().collect::<Vec<_>>();
            let first = *rows.first().ok_or_else(invalid)?;
            verify_rows(&view.row_artifact(first)?, &rows)?;
        }
        Ok(())
    }
}

pub fn read_v10_sigma_admission(
    section: &V10ObjectSection,
    reader: &mut (impl Read + Seek),
    receipt: &SigmaPackAdmissionV1,
    referenced: &mut BTreeSet<ProofKey>,
    cancel: &CancellationToken,
) -> Result<SigmaPackManifestV1, AppError> {
    let pack_key = (0, receipt.pack_manifest);
    let manifest = SigmaPackManifestV1::decode(&section.body(reader, pack_key, cancel)?)
        .map_err(|_| invalid())?;
    let mut keys = BTreeSet::from([pack_key]);
    for rule in &manifest.0 {
        let key = (1, rule.rule.sha256);
        if section.descriptor(key)?.size() != rule.size {
            return Err(invalid());
        }
        keys.insert(key);
    }
    section.check_commitment(&keys, &receipt.proof_set)?;
    referenced.extend(keys);
    Ok(manifest)
}

pub fn read_v10_sigma_run(
    section: &V10ObjectSection,
    reader: &mut (impl Read + Seek),
    receipt: &SigmaRunV2,
    admission: &SigmaPackManifestV1,
    referenced: &mut BTreeSet<ProofKey>,
    cancel: &CancellationToken,
) -> Result<V10SigmaRunObjects, AppError> {
    let keys = BTreeSet::from([
        (2, receipt.field_table),
        (3, receipt.selected_sources),
        (4, receipt.compiled_rules),
        (5, receipt.result_manifest),
    ]);
    section.check_commitment(&keys, &receipt.proof_set)?;
    let body = section.body(reader, (5, receipt.result_manifest), cancel)?;
    let results = SigmaRunResultsV3::decode(&body).map_err(|_| invalid())?;
    if results.status(receipt.status) != receipt.status {
        return Err(invalid());
    }
    let objects = V10SigmaRunObjects {
        class_plan: results.plan,
        field_table: SigmaFieldTableV1::decode(&section.body(
            reader,
            (2, receipt.field_table),
            cancel,
        )?)
        .map_err(|_| invalid())?,
        selected_sources: SigmaSourceScopeV1::decode(&section.body(
            reader,
            (3, receipt.selected_sources),
            cancel,
        )?)
        .map_err(|_| invalid())?,
        compiled_rules: SigmaCompiledRulesV1::decode(&section.body(
            reader,
            (4, receipt.compiled_rules),
            cancel,
        )?)
        .map_err(|_| invalid())?,
        results: results.scan.results,
        unavailable_by_source: results.scan.unavailable_by_source,
        indeterminate_by_rule: results.scan.indeterminate_by_rule,
    };
    let admitted = admission
        .0
        .iter()
        .map(|object| &object.rule)
        .collect::<BTreeSet<_>>();
    let selected = objects.selected_sources.0.iter().collect::<BTreeSet<_>>();
    let covered = objects
        .results
        .coverage
        .iter()
        .map(|rule| (&rule.rule, rule.status))
        .collect::<BTreeMap<_, _>>();
    if receipt.matched_rows != objects.results.matches.len() as u64
        || objects
            .unavailable_by_source
            .iter()
            .any(|(source, _)| !selected.contains(source))
        || covered.len() != objects.compiled_rules.0.len()
        || objects.compiled_rules.0.iter().any(|rule| {
            !admitted.contains(&rule.rule)
                || covered.get(&rule.rule).is_none_or(|status| {
                    (*status == SigmaCoverageV1::Eligible) == rule.variants.is_empty()
                })
        })
        || objects
            .results
            .matches
            .iter()
            .any(|matched| !selected.contains(&matched.row.source))
    {
        return Err(invalid());
    }
    if covered.len() != admitted.len() {
        return Err(invalid());
    }
    objects
        .class_plan
        .validate_compiled(&objects.compiled_rules, &objects.results.coverage, 1024)
        .map_err(|_| invalid())?;
    referenced.extend(keys);
    Ok(objects)
}

pub struct V10ReportObjects {
    pub citations: ReportCitationsV1,
    pub analyst_sections: Option<ReportAnalystSectionsV1>,
    pub coverage: ReportCoverageV2,
}

pub fn read_v10_report(
    section: &V10ObjectSection,
    reader: &mut (impl Read + Seek),
    receipt: &ReportPublishedV1,
    expected_coverage: &ReportCoverageV2,
    referenced: &mut BTreeSet<ProofKey>,
    cancel: &CancellationToken,
) -> Result<V10ReportObjects, AppError> {
    let rendered = (3, receipt.rendered_sha256);
    if section.descriptor(rendered)?.size() != receipt.rendered_length {
        return Err(invalid());
    }
    let mut keys = BTreeSet::from([(0, receipt.citations), (2, receipt.coverage), rendered]);
    if let Some(analyst) = receipt.analyst_sections {
        keys.insert((1, analyst));
    }
    section.check_commitment(&keys, &receipt.proof_set)?;
    let report = V10ReportObjects {
        citations: ReportCitationsV1::decode(&section.body(
            reader,
            (0, receipt.citations),
            cancel,
        )?)
        .map_err(|_| invalid())?,
        analyst_sections: receipt
            .analyst_sections
            .map(|hash| {
                ReportAnalystSectionsV1::decode(&section.body(reader, (1, hash), cancel)?)
                    .map_err(|_| invalid())
            })
            .transpose()?,
        coverage: ReportCoverageV2::decode(&section.body(reader, (2, receipt.coverage), cancel)?)
            .map_err(|_| invalid())?,
    };
    if &report.coverage != expected_coverage {
        return Err(invalid());
    }
    referenced.extend(keys);
    Ok(report)
}

fn invalid() -> AppError {
    AppError::InvalidChain(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::v10_proofs::V10ProofFamily;
    use std::io::Cursor;

    #[test]
    fn v10_report_binds_exact_v2_coverage_and_object_union() {
        let vector = super::super::report_objects::tests::coverage_vector;
        let encoded = vector("report_published_v1_with_coverage_v2");
        let receipt = ReportPublishedV1::decode(&crate::hex(&encoded)).unwrap();
        assert_eq!(receipt.encode().unwrap(), crate::hex(&encoded));
        let mut input = Cursor::new(vector("report_section_v10_with_coverage_v2"));
        let cancel = CancellationToken::new();
        let section = V10ObjectSection::scan(&mut input, V10ProofFamily::Report, &cancel).unwrap();
        let expected =
            ReportCoverageV2::decode(&vector("report_coverage_v2_two_tasks_same_local_sequence"))
                .unwrap();
        let mut referenced = BTreeSet::new();
        read_v10_report(
            &section,
            &mut input,
            &receipt,
            &expected,
            &mut referenced,
            &cancel,
        )
        .unwrap();
        section.check_union(&referenced).unwrap();

        let omitted = ReportCoverageV2::decode(&vector("reject_omitted_branch_gap")).unwrap();
        assert!(
            read_v10_report(
                &section,
                &mut input,
                &receipt,
                &omitted,
                &mut BTreeSet::new(),
                &cancel
            )
            .is_err()
        );
    }
}
