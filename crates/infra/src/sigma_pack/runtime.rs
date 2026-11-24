//! Execute a reviewed field table over the active, signed case artifacts.
use super::{
    LocalSigmaPack,
    evaluation::SigmaVariantPrograms,
    field_table::{ReviewedSigmaFieldTable, SigmaSourceVariant},
    invalid,
};
use crate::LocalStore;
use irmind_app::{
    AppError, AuditEventKind, AuditLog, CancellationToken, Engine,
    v10_proofs::{
        PreparedSigmaExecution, SigmaCompiledRuleV1, SigmaCompiledRulesV1, SigmaCoverageV1,
        SigmaExecutionContext, SigmaExecutionSummary, SigmaFieldTableV1, SigmaFindingDraft,
        SigmaMatchV1, SigmaRuleCoverageV1, SigmaRuleKeyV1, SigmaRunResultsV1, SigmaRunV1,
        SigmaSourceScopeV1, V10ArtifactReference, V10AuditReference, V10ProofDescriptor,
        V10ProofFamily, V10RowReference, V10SourceReference, sigma_pack_operation,
        v10_proof_commitment,
    },
};
use irmind_domain::{ArtifactSchemaV2, CaseId, ParquetArtifact, SourceManifestV2};
use std::{
    collections::BTreeMap,
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};

use irmind_app::v10_proofs::SigmaRunStatusV1;

const EVALUATOR: &str = "irmind-sigma-evaluator-v1";
type RunObjects = Vec<(V10ProofDescriptor, Vec<u8>)>;

impl LocalStore {
    pub fn run_sigma(
        &self,
        engine: &Engine<'_>,
        case: &CaseId,
        pack: [u8; 32],
        time: Range<i64>,
        cancel: &CancellationToken,
    ) -> Result<SigmaExecutionSummary, AppError> {
        if time.is_empty() {
            return Err(AppError::Policy(
                "Sigma requires an increasing UTC time range".into(),
            ));
        }
        engine.execute_sigma(
            case,
            pack,
            cancel,
            |scope, operation| {
                let admission = sigma_pack_operation(operation)?.ok_or_else(invalid)?;
                let rules = self.read_signed_sigma_pack(&admission, cancel)?;
                let candidate = prepare(
                    scope,
                    &rules,
                    operation.hash,
                    &self.parquet.owned_case_path(case),
                    time,
                    cancel,
                )?;
                let key = &operation.public_key;
                crate::seal::check_sigma_append(
                    self,
                    case,
                    &candidate.receipt,
                    key,
                    &candidate.material,
                    cancel,
                )?;
                Ok(candidate)
            },
            |material, entries, cancel| {
                let items = material
                    .iter()
                    .map(|(descriptor, bytes)| (*descriptor, bytes.as_slice()))
                    .collect::<Vec<_>>();
                self.prepare_v10_case_objects(case, V10ProofFamily::Sigma, &items, cancel)?
                    .append_with(cancel, || self.append_batch(entries))
            },
        )
    }
}

fn prepare(
    scope: SigmaExecutionContext<'_>,
    pack: &LocalSigmaPack,
    admission: [u8; 32],
    directory: &Path,
    time: Range<i64>,
    cancel: &CancellationToken,
) -> Result<PreparedSigmaExecution<RunObjects>, AppError> {
    let table = cloudtrail_table();
    let reviewed = ReviewedSigmaFieldTable::parse(&table)?;
    let variant = reviewed.variants.first().ok_or_else(invalid)?;
    let work = Workset::resolve(&scope, variant)?;
    let mut rules = pack
        .manifest
        .0
        .iter()
        .zip(&pack.rules)
        .map(|(file, bytes)| (file.rule.clone(), bytes.as_slice()))
        .collect::<Vec<_>>();
    rules.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let programs = SigmaVariantPrograms::compile(variant, rules.iter().cloned())?;
    let (compiled, mut results) = rule_objects(&programs, &rules);
    let (hit_rows, status, used_units) =
        scan_matches(&scope, &work, &programs, directory, &time, cancel)?;
    let titles = hit_rows
        .iter()
        .map(|(rule, ..)| rule)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|rule| title_for(rule, &rules).map(|title| (rule.clone(), title)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let inherited = irmind_app::v10_proofs::sigma_query_limits(scope.view.entries())?;
    let mut findings = Vec::with_capacity(hit_rows.len());
    for (rule, when, source, _, row) in hit_rows {
        let title = titles.get(&rule).ok_or_else(invalid)?.clone();
        results.matches.push(SigmaMatchV1 {
            rule,
            row,
            query_limit: inherited.get(&source.hash).copied(),
        });
        findings.push(SigmaFindingDraft {
            title,
            row,
            at: when.to_rfc3339(),
        });
    }
    let material = run_objects(&table, &work.scope(), &compiled, &results)?;
    let descriptors = material
        .iter()
        .map(|(descriptor, _)| *descriptor)
        .collect::<Vec<_>>();
    let receipt = SigmaRunV1 {
        checkpoint: scope.checkpoint,
        pack_admission: admission,
        artifact_inventory: scope.view.active_artifact_inventory()?,
        selected_sources: descriptors[1].hash(),
        start_utc_micros: time.start,
        end_utc_micros: time.end,
        compiled_rules: descriptors[2].hash(),
        field_table: descriptors[0].hash(),
        evaluator: EVALUATOR.into(),
        reserved_units: scope.reserved,
        used_units,
        status,
        matched_rows: findings.len() as u64,
        result_manifest: descriptors[3].hash(),
        proof_set: v10_proof_commitment(V10ProofFamily::Sigma, &descriptors)
            .map_err(|_| invalid())?,
    };
    Ok(PreparedSigmaExecution {
        receipt,
        material,
        findings,
        skipped_rules: programs.skipped().len(),
    })
}

type Hit<'a> = (
    SigmaRuleKeyV1,
    irmind_domain::IndexedTime,
    &'a WorkSource,
    Option<u64>,
    V10RowReference,
);

fn scan_matches<'a>(
    scope: &SigmaExecutionContext<'_>,
    work: &'a Workset,
    programs: &SigmaVariantPrograms<'_>,
    directory: &Path,
    time: &Range<i64>,
    cancel: &CancellationToken,
) -> Result<(Vec<Hit<'a>>, SigmaRunStatusV1, u64), AppError> {
    let mut scan = programs.start(scope.reserved);
    let mut hit_rows = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    for (locator, artifact) in &work.artifacts {
        let mut file = irmind_fs::open_regular_no_follow(directory, Path::new(artifact.path()))
            .map_err(|_| invalid())?;
        crate::verify_v10_artifact_rows(&mut file, 0, artifact, &[], cancel)?;
        scan.scan_authenticated(
            file,
            time.clone(),
            deadline,
            cancel,
            |physical_row, event, key| {
                let origin = event.origin();
                let signed = work
                    .sources
                    .get(origin.source().as_str())
                    .ok_or_else(invalid)?;
                let when = event.timestamp().ok_or_else(invalid)?;
                let row = V10RowReference {
                    artifact: *locator,
                    source: signed.reference,
                    record: origin.record(),
                    physical_row,
                };
                scope.view.row_artifact(row)?;
                hit_rows.push((key.clone(), when, signed, origin.offset(), row));
                Ok(())
            },
        )?;
        if scan.status() != irmind_app::v10_proofs::SigmaRunStatusV1::Complete {
            break;
        }
    }
    hit_rows.sort_unstable_by(
        |(rule, time, source, offset, row),
         (other_rule, other_time, other_source, other_offset, other_row)| {
            rule.cmp(other_rule).then_with(|| {
                (
                    time.instant(),
                    &source.name,
                    row.source.evidence_sha256,
                    offset,
                    row.record,
                    row,
                )
                    .cmp(&(
                        other_time.instant(),
                        &other_source.name,
                        other_row.source.evidence_sha256,
                        other_offset,
                        other_row.record,
                        other_row,
                    ))
            })
        },
    );
    Ok((hit_rows, scan.status(), scan.used_units()))
}

struct WorkSource {
    reference: V10SourceReference,
    name: String,
    hash: String,
}

struct Workset {
    artifacts: Vec<(V10ArtifactReference, ParquetArtifact)>,
    sources: BTreeMap<String, WorkSource>,
}

impl Workset {
    fn resolve(
        scope: &SigmaExecutionContext<'_>,
        variant: &SigmaSourceVariant,
    ) -> Result<Self, AppError> {
        let entries = scope.view.entries();
        let (artifacts, chosen) = select_artifacts(entries, variant)?;
        let mut sources = BTreeMap::new();
        for entry in entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        {
            let manifest = SourceManifestV2::decode(&entry.payload).map_err(|_| invalid())?;
            let hash = manifest.source.sha256.as_str().to_owned();
            let Some(artifact) = chosen.get(&hash) else {
                continue;
            };
            let reference = V10SourceReference {
                manifest: V10AuditReference {
                    sequence: entry.seq,
                    entry_sha256: entry.hash,
                },
                evidence_sha256: digest(&hash)?,
            };
            scope.view.artifact(reference, *artifact)?;
            if sources
                .insert(
                    hash.clone(),
                    WorkSource {
                        reference,
                        name: manifest.source.source,
                        hash,
                    },
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
        if sources.is_empty() || sources.len() != chosen.len() {
            return Err(AppError::Policy(
                "No signed event artifacts match the installed Sigma field table".into(),
            ));
        }
        Ok(Self { artifacts, sources })
    }

    fn scope(&self) -> SigmaSourceScopeV1 {
        let mut refs = self
            .sources
            .values()
            .map(|source| source.reference)
            .collect::<Vec<_>>();
        refs.sort_unstable();
        SigmaSourceScopeV1(refs)
    }
}

type SelectedArtifacts = (
    Vec<(V10ArtifactReference, ParquetArtifact)>,
    BTreeMap<String, V10ArtifactReference>,
);

fn select_artifacts(
    entries: &[irmind_app::SignedEntry],
    variant: &SigmaSourceVariant,
) -> Result<SelectedArtifacts, AppError> {
    let active = irmind_app::artifact_catalog(entries)?
        .active
        .into_iter()
        .map(|artifact| (artifact.path().to_owned(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut chosen = BTreeMap::new();
    let mut artifacts = Vec::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::ParquetArtifactV3)
    {
        let artifact =
            ParquetArtifact::decode(entry.kind, &entry.payload).map_err(|_| invalid())?;
        if !active.contains_key(artifact.path()) {
            continue;
        }
        let ParquetArtifact::V3(envelope) = &artifact;
        if envelope.core().schema != ArtifactSchemaV2::CommonEvents {
            continue;
        }
        let bindings = envelope.pipeline().bindings();
        let Some(first) = bindings.first() else {
            return Err(invalid());
        };
        if first.decoder().id() != variant.parser_id
            || first.decoder().version() != variant.parser_version
            || first.mapping().is_none_or(|mapping| {
                mapping.id() != variant.mapping_id || mapping.version() != variant.mapping_version
            })
        {
            continue;
        }
        let locator = V10ArtifactReference {
            entry: V10AuditReference {
                sequence: entry.seq,
                entry_sha256: entry.hash,
            },
            artifact_sha256: digest(artifact.sha256().as_str())?,
        };
        for binding in bindings {
            chosen.insert(binding.input().source().as_str().to_owned(), locator);
        }
        artifacts.push((locator, artifact));
    }
    Ok((artifacts, chosen))
}

fn digest(text: &str) -> Result<[u8; 32], AppError> {
    let mut digest = [0; 32];
    hex::decode_to_slice(text, &mut digest).map_err(|_| invalid())?;
    Ok(digest)
}

fn rule_objects(
    programs: &SigmaVariantPrograms<'_>,
    rules: &[(SigmaRuleKeyV1, &[u8])],
) -> (SigmaCompiledRulesV1, SigmaRunResultsV1) {
    let skipped = programs
        .skipped()
        .iter()
        .map(|(key, status)| (key, *status))
        .collect::<BTreeMap<_, _>>();
    let compiled = rules
        .iter()
        .map(|(rule, _)| SigmaCompiledRuleV1 {
            rule: rule.clone(),
            variants: if skipped.contains_key(rule) {
                vec![]
            } else {
                vec![0]
            },
        })
        .collect();
    let coverage = rules
        .iter()
        .map(|(rule, _)| {
            let status = skipped
                .get(rule)
                .copied()
                .unwrap_or(SigmaCoverageV1::Eligible);
            SigmaRuleCoverageV1 {
                rule: rule.clone(),
                status,
                detail: (status != SigmaCoverageV1::Eligible).then(|| {
                    "Rule does not match the reviewed CloudTrail selectors or supported fields"
                        .into()
                }),
            }
        })
        .collect();
    (
        SigmaCompiledRulesV1(compiled),
        SigmaRunResultsV1 {
            coverage,
            matches: Vec::new(),
        },
    )
}

fn title_for(key: &SigmaRuleKeyV1, rules: &[(SigmaRuleKeyV1, &[u8])]) -> Result<String, AppError> {
    let index = rules
        .binary_search_by(|(rule, _)| rule.cmp(key))
        .map_err(|_| invalid())?;
    let document = irmind_sigma::admit_rule(rules[index].1).map_err(|_| invalid())?;
    match document.fields().get("title") {
        Some(irmind_sigma::RuleValue::Text(value)) if !value.trim().is_empty() => Ok(value.clone()),
        _ => Ok(key.id.clone()),
    }
}

fn run_objects(
    table: &SigmaFieldTableV1,
    scope: &SigmaSourceScopeV1,
    compiled: &SigmaCompiledRulesV1,
    results: &SigmaRunResultsV1,
) -> Result<RunObjects, AppError> {
    [
        table.encode(),
        scope.encode(),
        compiled.encode(),
        results.encode(),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, encoded)| {
        let bytes = encoded.map_err(|_| invalid())?;
        let kind = u8::try_from(index + 2).map_err(|_| invalid())?;
        let descriptor = V10ProofDescriptor::from_body(V10ProofFamily::Sigma, kind, &bytes)
            .map_err(|_| invalid())?;
        Ok((descriptor, bytes))
    })
    .collect()
}

fn cloudtrail_table() -> SigmaFieldTableV1 {
    SigmaFieldTableV1 {
        id: "irmind-sigma-cloudtrail".into(),
        version: "v1".into(),
        toml: include_str!("cloudtrail-v1.toml").into(),
    }
}
