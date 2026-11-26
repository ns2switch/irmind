//! The V10 export ends with mandatory Sigma and report object counts.
use super::{AppError, CancellationToken, storage, storage_reason};
use irmind_app::v10_proofs::{V10ProofFamily, write_v10_object_section};
#[cfg(test)]
use std::io::Write;
use std::io::{Read, Seek};

#[cfg(test)]
const FAMILIES: [V10ProofFamily; 2] = [V10ProofFamily::Sigma, V10ProofFamily::Report];

use super::{CaseId, LocalStore};
use irmind_app::v10_proofs::{
    V10ObjectSection, V10ProofDescriptor, read_v10_sigma_admission, read_v10_sigma_run,
    sigma_execution, sigma_pack_operation,
};
use irmind_app::{
    SignedEntry, SignedOperation, SkillReceiptVerifier, report_object_keys, report_publication,
    verify_report_history,
};
use irmind_domain::{AuditEventKind, ParquetArtifact};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
};

pub(super) fn write(
    store: &LocalStore,
    case: &CaseId,
    output: &mut File,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let family = V10ProofFamily::Report;
    let mut objects = BTreeMap::new();
    store.for_each_audit_entry(case, |entry| {
        if entry.kind == AuditEventKind::ReportPublishedV1 {
            let receipt = report_publication(&entry)?;
            let mut descriptors = Vec::new();
            for (kind, hash) in report_object_keys(&receipt) {
                let descriptor = match objects.entry((kind, hash)) {
                    std::collections::btree_map::Entry::Occupied(entry) => *entry.get(),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let (descriptor, _) =
                            store.open_addressed_report_proof(case, kind, hash, cancel)?;
                        *entry.insert(descriptor)
                    }
                };
                descriptors.push(descriptor);
            }
            if irmind_app::v10_proofs::v10_proof_commitment(family, &descriptors)
                .map_err(|_| AppError::InvalidChain(entry.seq))?
                != receipt.proof_set
            {
                return Err(AppError::InvalidChain(entry.seq));
            }
        }
        Ok(())
    })?;
    let descriptors = objects.into_values().collect::<Vec<V10ProofDescriptor>>();
    write_v10_object_section(
        output,
        family,
        &descriptors,
        |descriptor| store.open_v10_case_object(case, family, descriptor, cancel),
        cancel,
    )
}

pub(super) struct ReportVerification<'a> {
    pub sigma_admissions: &'a BTreeMap<[u8; 32], SignedOperation>,
    pub title: &'a str,
    pub entries: &'a [SignedEntry],
    pub evidence: &'a BTreeSet<String>,
    pub skills: &'a SkillReceiptVerifier,
    pub offsets: &'a BTreeMap<String, u64>,
}

pub(super) fn verify(
    input: &mut File,
    context: &ReportVerification<'_>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let sigma = V10ObjectSection::scan(input, V10ProofFamily::Sigma, cancel)?;
    let section = V10ObjectSection::scan(input, V10ProofFamily::Report, cancel)?;
    if input.read(&mut [0]).map_err(storage)? != 0 {
        return Err(storage_reason("export has trailing bytes"));
    }
    let mut objects = input.try_clone().map_err(storage)?;
    let mut artifacts = input.try_clone().map_err(storage)?;
    verify_sigma(
        &mut objects,
        &sigma,
        context.entries,
        context.sigma_admissions,
        |artifact, rows, time, predicate| {
            let offset = *context
                .offsets
                .get(artifact.path())
                .ok_or(AppError::InvalidChain(0))?;
            super::parquet_frame::verify_v10_sigma_rows(
                &mut artifacts,
                offset,
                artifact,
                rows,
                time,
                predicate,
                cancel,
            )
        },
        cancel,
    )?;
    let mut report_objects = input.try_clone().map_err(storage)?;
    let referenced = verify_report_history(
        context.title,
        context.entries,
        context.evidence,
        Some((context.skills, &crate::TomlSkillCompiler)),
        (
            |kind, hash| section.body(&mut report_objects, (kind, hash), cancel),
            |kind, hash| {
                crate::sigma_pack::sigma_proof_read(
                    kind,
                    sigma.body(&mut objects, (kind, hash), cancel)?,
                )
            },
        ),
        |artifact, row| {
            let offset = *context
                .offsets
                .get(artifact.path())
                .ok_or(AppError::InvalidChain(row.artifact.entry.sequence))?;
            crate::verify_v10_artifact_rows(&mut artifacts, offset, artifact, &[row], cancel)
        },
        cancel,
    )?;
    section.check_union(&referenced)
}

pub(super) type SigmaRowPredicate<'a> = dyn FnMut(
        irmind_app::v10_proofs::V10RowReference,
        &irmind_domain::CommonEventV1,
        &str,
    ) -> Result<(), AppError>
    + 'a;

pub(super) fn verify_sigma(
    objects: &mut (impl Read + Seek),
    section: &V10ObjectSection,
    entries: &[SignedEntry],
    operations: &BTreeMap<[u8; 32], SignedOperation>,
    mut verify_rows: impl FnMut(
        &ParquetArtifact,
        &[irmind_app::v10_proofs::V10RowReference],
        &std::ops::Range<i64>,
        Option<&mut SigmaRowPredicate<'_>>,
    ) -> Result<(), AppError>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    irmind_app::v10_proofs::sigma_remaining_work(entries)?;
    let mut referenced = BTreeSet::new();
    let mut admissions = BTreeSet::new();
    #[cfg(feature = "sigma")]
    let (deadline, mut units) = (
        std::time::Instant::now() + std::time::Duration::from_mins(1),
        4_000_000_000u64,
    );
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SigmaRunV1)
    {
        let run = sigma_execution(entry)?;
        let operation = operations
            .get(&run.pack_admission)
            .ok_or(AppError::InvalidChain(entry.seq))?;
        let admission =
            sigma_pack_operation(operation)?.ok_or(AppError::InvalidChain(entry.seq))?;
        let pack = read_v10_sigma_admission(section, objects, &admission, &mut referenced, cancel)?;
        let materials = read_v10_sigma_run(section, objects, &run, &pack, &mut referenced, cancel)?;
        let table = crate::sigma_pack::field_table::ReviewedSigmaFieldTable::parse_for_evaluator(
            &materials.field_table,
            &run.evaluator,
        )?;
        if materials
            .compiled_rules
            .0
            .iter()
            .flat_map(|rule| &rule.variants)
            .any(|variant| *variant >= table.variants.len() as u64)
        {
            return Err(AppError::InvalidChain(entry.seq));
        }
        materials.verify_execution_scope(&run, operation, entries)?;
        #[cfg(feature = "sigma")]
        if materials.class_plan.is_some() {
            units = verify_sigma_v3(
                &run,
                &materials,
                &table,
                &pack,
                section,
                objects,
                entries,
                deadline,
                units,
                cancel,
                &mut verify_rows,
            )?;
        }
        #[cfg(not(feature = "sigma"))]
        if materials.class_plan.is_some() {
            return Err(AppError::Policy(
                "Sigma source-class verification requires a build with the Sigma evaluator".into(),
            ));
        }
        if materials.class_plan.is_none() {
            let time = run.start_utc_micros..run.end_utc_micros;
            materials.verify_case_rows(
                entries,
                &run,
                |artifact, rows| verify_rows(artifact, rows, &time, None),
                cancel,
            )?;
        }
        admissions.insert(run.pack_admission);
    }
    if admissions.len() != operations.len() {
        return Err(AppError::InvalidChain(0));
    }
    section.check_union(&referenced)
}

#[cfg(feature = "sigma")]
#[expect(
    clippy::too_many_arguments,
    reason = "the verifier binds one run to the same bounded readers and authenticated prefix"
)]
fn verify_sigma_v3(
    run: &irmind_app::v10_proofs::SigmaRunV1,
    materials: &irmind_app::v10_proofs::V10SigmaRunObjects,
    table: &crate::sigma_pack::field_table::ReviewedSigmaFieldTable,
    pack: &irmind_app::v10_proofs::SigmaPackManifestV1,
    section: &V10ObjectSection,
    objects: &mut (impl Read + Seek),
    entries: &[SignedEntry],
    deadline: std::time::Instant,
    units: u64,
    cancel: &CancellationToken,
    verify_rows: &mut impl FnMut(
        &ParquetArtifact,
        &[irmind_app::v10_proofs::V10RowReference],
        &std::ops::Range<i64>,
        Option<&mut SigmaRowPredicate<'_>>,
    ) -> Result<(), AppError>,
) -> Result<u64, AppError> {
    let time = run.start_utc_micros..run.end_utc_micros;
    let mut bodies = pack
        .0
        .iter()
        .map(|object| {
            Ok((
                object.rule.clone(),
                section.body(objects, (1, object.rule.sha256), cancel)?,
            ))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    bodies.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let rules = bodies
        .iter()
        .map(|(key, body)| (key.clone(), body.as_slice()))
        .collect::<Vec<_>>();
    crate::sigma_pack::verify_class_plan(run, materials, table, entries, &rules, deadline, cancel)?;
    let mut check =
        crate::sigma_pack::SigmaMatchCheck::new(table, materials, &rules, deadline, units, cancel);
    materials.verify_case_rows(
        entries,
        run,
        |artifact, rows| {
            verify_rows(
                artifact,
                rows,
                &time,
                Some(&mut |row, common, original| check.check(artifact, row, common, original)),
            )
        },
        cancel,
    )?;
    check.finish()
}

#[cfg(test)]
pub(super) fn write_empty(
    output: &mut impl Write,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    for family in FAMILIES {
        write_v10_object_section(
            output,
            family,
            &[],
            |_| Err::<std::io::Empty, _>(AppError::InvalidChain(0)),
            cancel,
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_empty(input: &mut impl Read) -> Result<(), AppError> {
    for _ in FAMILIES {
        let mut count = [0; 8];
        input.read_exact(&mut count).map_err(storage)?;
        if count != [0; 8] {
            return Err(AppError::InvalidChain(0));
        }
    }
    if input.read(&mut [0]).map_err(storage)? != 0 {
        return Err(storage_reason("export has trailing bytes"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::export_current::{HeaderV10, write_header};
    use super::super::{CaseSeal, hex, sha256};
    use super::*;
    use std::io::SeekFrom;

    #[test]
    fn export_v10_wire_matches_independent_header_and_count_vectors() {
        let vectors: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../testkit/fixtures/contracts/sigma_report_v10.json"
        ))
        .unwrap();
        let key = (0..32).collect::<Vec<u8>>();
        let header = HeaderV10 {
            version: 10,
            case_id: "00000000-0000-4000-8000-000000000010".into(),
            title: "Synthetic V10 layout".into(),
            severity: "low".into(),
            scope: "synthetic case".into(),
            seal: CaseSeal {
                seq: 7,
                hash: sha256(b"synthetic-audit-entry"),
                sig: (0..64).collect(),
                analyst_key_fingerprint: hex(&sha256(&key)),
                public_key: key,
            },
        };
        let mut file = tempfile::tempfile().unwrap();
        write_header(&mut file, &header).unwrap();
        let mut bytes = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut bytes).unwrap();
        let vector = &vectors["export_v10_header_frame"];
        assert_eq!(hex(&bytes), vector["bytes_hex"]);
        assert_eq!(hex(&sha256(&bytes)), vector["sha256"]);

        bytes.clear();
        let cancel = CancellationToken::new();
        write_empty(&mut bytes, &cancel).unwrap();
        let vector = &vectors["export_v10_empty_sigma_and_report_counts"];
        assert_eq!(hex(&bytes), vector["bytes_hex"]);
        assert_eq!(hex(&sha256(&bytes)), vector["sha256"]);
        verify_empty(&mut bytes.as_slice()).unwrap();
        for index in [7, 15] {
            bytes[index] = 1;
            assert!(verify_empty(&mut bytes.as_slice()).is_err());
            bytes[index] = 0;
        }
        assert!(verify_empty(&mut &bytes[..15]).is_err());
        bytes.push(0);
        assert!(verify_empty(&mut bytes.as_slice()).is_err());
    }
}
