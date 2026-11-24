//! Bind the decoded proof bodies to their signed receipt before resolving material.
use super::{
    ReportAnalystSectionsV1, ReportCitationsV1, ReportCoverageV2, ReportPublishedV1,
    SigmaCompiledRulesV1, SigmaCoverageV1, SigmaFieldTableV1, SigmaPackAdmissionV1,
    SigmaPackManifestV1, SigmaRunResultsV1, SigmaRunV1, SigmaSourceScopeV1, V10ObjectSection,
};
use crate::{AppError, CancellationToken};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek},
};

type ProofKey = (u8, [u8; 32]);

pub struct V10SigmaRunObjects {
    pub field_table: SigmaFieldTableV1,
    pub selected_sources: SigmaSourceScopeV1,
    pub compiled_rules: SigmaCompiledRulesV1,
    pub results: SigmaRunResultsV1,
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
    receipt: &SigmaRunV1,
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
    let objects = V10SigmaRunObjects {
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
        results: SigmaRunResultsV1::decode(&section.body(
            reader,
            (5, receipt.result_manifest),
            cancel,
        )?)
        .map_err(|_| invalid())?,
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
