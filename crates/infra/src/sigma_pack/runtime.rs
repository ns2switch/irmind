//! Execute a reviewed field table over the active, signed case artifacts.
use super::{
    LocalSigmaPack,
    evaluation::{MAX_MATCHES, SigmaVariantPrograms},
    field_table::{ReviewedSigmaFieldTable, SigmaSourceVariant},
    invalid, plan,
};
use crate::LocalStore;
use irmind_app::{
    AppError, AuditEventKind, AuditLog, CancellationToken, Engine,
    source_mapping::{MappingCatalog, MappingProvenance},
    v10_proofs::{
        PreparedSigmaExecution, SigmaCompiledRulesV1, SigmaCoverageV1, SigmaExecutionContext,
        SigmaExecutionSummary, SigmaFieldTableV1, SigmaFindingDraft, SigmaMatchV1, SigmaRuleKeyV1,
        SigmaRunResultsV1, SigmaRunResultsV2, SigmaRunResultsV3, SigmaRunV1, SigmaSourceScopeV1,
        V10ArtifactReference, V10AuditReference, V10ProofDescriptor, V10ProofFamily,
        V10RowReference, V10SourceReference, sigma_pack_operation, v10_proof_commitment,
    },
};
use irmind_domain::{
    ArtifactSchemaV2, CaseId, MappingBindingV1, ParquetArtifact, SourceManifestV2,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    path::Path,
    time::{Duration, Instant},
};

use irmind_app::v10_proofs::SigmaRunStatusV1;
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
                let catalog = self.parquet.mapping_catalog().ok_or_else(invalid)?;
                let candidate = prepare(
                    scope,
                    catalog,
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
    catalog: &MappingCatalog,
    pack: &LocalSigmaPack,
    admission: [u8; 32],
    directory: &Path,
    time: Range<i64>,
    cancel: &CancellationToken,
) -> Result<PreparedSigmaExecution<RunObjects>, AppError> {
    let (table, reviewed) =
        ReviewedSigmaFieldTable::materialize_native(enrolled_field_table(), catalog)?;
    let work = Workset::resolve(&scope, &reviewed, catalog)?;
    let mut rules = pack
        .manifest
        .0
        .iter()
        .zip(&pack.rules)
        .map(|(file, bytes)| (file.rule.clone(), bytes.as_slice()))
        .collect::<Vec<_>>();
    rules.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let (plan, compiled, mut results) = plan::compile(
        &reviewed,
        &work.variants,
        &rules,
        Instant::now() + Duration::from_secs(15),
        cancel,
    )?;
    let ScanOutcome {
        hits: hit_rows,
        status,
        used_units,
        unavailable_by_source,
        indeterminate_by_rule,
    } = scan_matches(
        &scope, &work, &reviewed, &compiled, &rules, directory, &time, cancel,
    )?;
    let skipped_rules = results
        .coverage
        .iter()
        .filter(|rule| rule.status != SigmaCoverageV1::Eligible)
        .count();
    let findings = materialize_findings(scope.view.entries(), &rules, hit_rows, &mut results)?;
    let source_counts = work.signed_gap_counts(&unavailable_by_source)?;
    let indeterminate_by_rule = indeterminate_by_rule.into_iter().collect::<Vec<_>>();
    let v2 = SigmaRunResultsV2 {
        results,
        unavailable_by_source: source_counts,
        indeterminate_by_rule: indeterminate_by_rule.clone(),
    };
    let class_coverage = plan.coverage();
    let skipped_classes = plan::skipped_classes(&plan, &reviewed, compiled.0.len())?;
    let v3 = SigmaRunResultsV3 { scan: v2, plan };
    let status = v3.status(status);
    let material = run_objects(&table, &work.scope(), &compiled, &v3)?;
    let descriptors = material
        .iter()
        .map(|(descriptor, _)| *descriptor)
        .collect::<Vec<_>>();
    let proof_set =
        v10_proof_commitment(V10ProofFamily::Sigma, &descriptors).map_err(|_| invalid())?;
    let receipt = SigmaRunV1 {
        checkpoint: scope.checkpoint,
        pack_admission: admission,
        artifact_inventory: scope.view.active_artifact_inventory()?,
        selected_sources: descriptors[1].hash(),
        start_utc_micros: time.start,
        end_utc_micros: time.end,
        compiled_rules: descriptors[2].hash(),
        field_table: descriptors[0].hash(),
        evaluator: reviewed.evaluator().into(),
        reserved_units: scope.reserved,
        used_units,
        status,
        matched_rows: findings.len() as u64,
        result_manifest: descriptors[3].hash(),
        proof_set,
    };
    Ok(PreparedSigmaExecution {
        receipt,
        material,
        findings,
        skipped_rules,
        class_coverage,
        skipped_classes,
        unavailable_by_source: work.named_gap_counts(unavailable_by_source)?,
        indeterminate_by_rule,
    })
}

fn materialize_findings(
    entries: &[irmind_app::SignedEntry],
    rules: &[(SigmaRuleKeyV1, &[u8])],
    hit_rows: Vec<Hit<'_>>,
    results: &mut SigmaRunResultsV1,
) -> Result<Vec<SigmaFindingDraft>, AppError> {
    let titles = hit_rows
        .iter()
        .map(|(rule, ..)| rule)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|rule| title_for(rule, rules).map(|title| (rule.clone(), title)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let inherited = irmind_app::v10_proofs::sigma_query_limits(entries)?;
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
    Ok(findings)
}

type Hit<'a> = (
    SigmaRuleKeyV1,
    irmind_domain::IndexedTime,
    &'a WorkSource,
    Option<u64>,
    V10RowReference,
);

struct ScanOutcome<'a> {
    hits: Vec<Hit<'a>>,
    status: SigmaRunStatusV1,
    used_units: u64,
    unavailable_by_source: BTreeMap<irmind_domain::EvidenceHash, u64>,
    indeterminate_by_rule: BTreeMap<SigmaRuleKeyV1, u64>,
}

#[allow(clippy::too_many_arguments)]
#[expect(
    clippy::too_many_lines,
    reason = "the class loop retains scan stops and accumulated coverage together"
)]
fn scan_matches<'a>(
    scope: &SigmaExecutionContext<'_>,
    work: &'a Workset,
    table: &ReviewedSigmaFieldTable,
    compiled: &SigmaCompiledRulesV1,
    rules: &[(SigmaRuleKeyV1, &[u8])],
    directory: &Path,
    time: &Range<i64>,
    cancel: &CancellationToken,
) -> Result<ScanOutcome<'a>, AppError> {
    let mut hit_rows = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut status = SigmaRunStatusV1::Complete;
    let mut remaining = scope.reserved;
    let mut unavailable_by_source = BTreeMap::new();
    let mut indeterminate_by_rule = BTreeMap::new();
    for &index in &work.variants {
        let rules = rules
            .iter()
            .zip(&compiled.0)
            .filter(|(_, rule)| rule.variants.binary_search(&(index as u64)).is_ok())
            .map(|(raw, _)| raw.clone())
            .collect::<Vec<_>>();
        if rules.is_empty()
            && table.variants[index].exact_cluster_field().is_none()
            && !table.variants[index].has_decimal_projection()
        {
            continue;
        }
        if cancel.is_cancelled() {
            status = SigmaRunStatusV1::Cancelled;
            break;
        }
        if Instant::now() >= deadline {
            status = SigmaRunStatusV1::TimeLimit;
            break;
        }
        let programs = SigmaVariantPrograms::compile(&table.variants[index], rules)?;
        let mut scan = programs.start_with_match_limit(remaining, MAX_MATCHES - hit_rows.len());
        for (locator, artifact, variants) in &work.artifacts {
            if !variants.contains(&index) {
                continue;
            }
            let mut file = irmind_fs::open_regular_no_follow(directory, Path::new(artifact.path()))
                .map_err(|_| invalid())?;
            match crate::seal::verify_sigma_scan_artifact(&mut file, artifact, || {
                if scan.stop(deadline, cancel) {
                    Err(AppError::Cancelled)
                } else {
                    Ok(())
                }
            }) {
                Ok(()) => {}
                Err(AppError::Cancelled) => break,
                Err(error) => return Err(error),
            }
            scan.scan_authenticated(
                file,
                time.clone(),
                deadline,
                cancel,
                |physical_row, event, key| {
                    hit_rows.push(resolve_hit(
                        scope,
                        work,
                        *locator,
                        physical_row,
                        event,
                        key,
                    )?);
                    Ok(())
                },
            )?;
            if scan.status() != SigmaRunStatusV1::Complete {
                break;
            }
        }
        remaining = remaining
            .checked_sub(scan.used_units())
            .ok_or_else(invalid)?;
        status = scan.status();
        add_counts(&mut unavailable_by_source, scan.unavailable_by_source)?;
        add_counts(&mut indeterminate_by_rule, scan.indeterminate_by_rule)?;
        if status != SigmaRunStatusV1::Complete {
            break;
        }
    }
    sort_hits(&mut hit_rows);
    if status == SigmaRunStatusV1::Complete && !indeterminate_by_rule.is_empty() {
        status = SigmaRunStatusV1::ExactFieldsUnavailable;
    }
    Ok(ScanOutcome {
        hits: hit_rows,
        status,
        used_units: scope.reserved - remaining,
        unavailable_by_source,
        indeterminate_by_rule,
    })
}

fn resolve_hit<'a>(
    scope: &SigmaExecutionContext<'_>,
    work: &'a Workset,
    artifact: V10ArtifactReference,
    physical_row: u64,
    event: &irmind_domain::CommonEventV1,
    key: &SigmaRuleKeyV1,
) -> Result<Hit<'a>, AppError> {
    let origin = event.origin();
    let signed = work
        .sources
        .get(origin.source().as_str())
        .ok_or_else(invalid)?;
    let when = event.timestamp().ok_or_else(invalid)?;
    let row = V10RowReference {
        artifact,
        source: signed.reference,
        record: origin.record(),
        physical_row,
    };
    scope.view.row_artifact(row)?;
    Ok((key.clone(), when, signed, origin.offset(), row))
}

fn add_counts<K: Ord>(
    totals: &mut BTreeMap<K, u64>,
    counts: BTreeMap<K, u64>,
) -> Result<(), AppError> {
    for (key, count) in counts {
        let total = totals.entry(key).or_default();
        *total = total.checked_add(count).ok_or_else(invalid)?;
    }
    Ok(())
}

fn sort_hits(hit_rows: &mut Vec<Hit<'_>>) {
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
    hit_rows.dedup_by(|left, right| left.0 == right.0 && left.4 == right.4);
}

struct WorkSource {
    reference: V10SourceReference,
    name: String,
    hash: String,
}

type WorkArtifact = (V10ArtifactReference, ParquetArtifact, Vec<usize>);

struct Workset {
    artifacts: Vec<WorkArtifact>,
    variants: BTreeSet<usize>,
    sources: BTreeMap<String, WorkSource>,
}

impl Workset {
    fn resolve(
        scope: &SigmaExecutionContext<'_>,
        table: &ReviewedSigmaFieldTable,
        catalog: &MappingCatalog,
    ) -> Result<Self, AppError> {
        let entries = scope.view.entries();
        let (artifacts, chosen) = select_artifacts(entries, table, |binding| {
            binding.mapping().is_some_and(|mapping| {
                catalog.manifests().any(|manifest| {
                    manifest.identity() == mapping
                        && matches!(
                            manifest.provenance(),
                            MappingProvenance::NativeBuild { .. }
                                | MappingProvenance::BundledDefinition { .. }
                        )
                })
            })
        })?;
        let variants = artifacts
            .iter()
            .flat_map(|(_, _, variants)| variants.iter().copied())
            .collect();
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
        if sources.len() != chosen.len() {
            return Err(AppError::Policy(
                "Sigma source scope does not resolve to the signed original manifests".into(),
            ));
        }
        Ok(Self {
            artifacts,
            variants,
            sources,
        })
    }

    fn signed_gap_counts(
        &self,
        counts: &BTreeMap<irmind_domain::EvidenceHash, u64>,
    ) -> Result<Vec<(V10SourceReference, u64)>, AppError> {
        let counts = counts
            .iter()
            .map(|(source, count)| {
                self.sources
                    .get(source.as_str())
                    .map(|signed| (signed.reference, *count))
                    .ok_or_else(invalid)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(counts.into_iter().collect())
    }

    fn named_gap_counts(
        &self,
        counts: BTreeMap<irmind_domain::EvidenceHash, u64>,
    ) -> Result<Vec<(String, u64)>, AppError> {
        counts
            .into_iter()
            .map(|(source, count)| {
                self.sources
                    .get(source.as_str())
                    .map(|signed| (signed.name.clone(), count))
                    .ok_or_else(invalid)
            })
            .collect()
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

type SelectedArtifacts = (Vec<WorkArtifact>, BTreeMap<String, V10ArtifactReference>);

fn select_artifacts(
    entries: &[irmind_app::SignedEntry],
    table: &ReviewedSigmaFieldTable,
    eligible: impl Fn(&MappingBindingV1) -> bool,
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
        if !eligible(first) {
            continue;
        }
        let variants = table
            .variants
            .iter()
            .enumerate()
            .filter(|(_, variant)| matches_binding(variant, first))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if variants.is_empty() {
            continue;
        }
        if bindings.iter().any(|binding| {
            variants
                .iter()
                .any(|&index| !matches_binding(&table.variants[index], binding))
        }) {
            return Err(invalid());
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
        artifacts.push((locator, artifact, variants));
    }
    Ok((artifacts, chosen))
}

fn matches_binding(variant: &SigmaSourceVariant, binding: &MappingBindingV1) -> bool {
    binding.decoder().id() == variant.parser_id
        && binding.decoder().version() == variant.parser_version
        && binding.mapping().is_some_and(|mapping| {
            mapping.id() == variant.mapping_id && mapping.version() == variant.mapping_version
        })
}

fn digest(text: &str) -> Result<[u8; 32], AppError> {
    let mut digest = [0; 32];
    hex::decode_to_slice(text, &mut digest).map_err(|_| invalid())?;
    Ok(digest)
}

#[cfg(test)]
pub(super) fn rule_objects(
    table: &ReviewedSigmaFieldTable,
    available: &BTreeSet<usize>,
    rules: &[(SigmaRuleKeyV1, &[u8])],
    cancel: &CancellationToken,
) -> Result<(SigmaCompiledRulesV1, SigmaRunResultsV1), AppError> {
    use super::evaluation::covers;
    use irmind_app::v10_proofs::{SigmaCompiledRuleV1, SigmaRuleCoverageV1};

    let mut variants_by_rule = vec![Vec::new(); rules.len()];
    let mut failures = vec![None; rules.len()];
    for &index in available {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let programs =
            SigmaVariantPrograms::compile(&table.variants[index], rules.iter().cloned())?;
        let skipped = programs
            .skipped()
            .iter()
            .map(|(key, status)| (key, *status))
            .collect::<BTreeMap<_, _>>();
        for (position, (key, _)) in rules.iter().enumerate() {
            match skipped.get(key) {
                None => variants_by_rule[position].push(index as u64),
                Some(SigmaCoverageV1::UnsupportedLogsource) => {}
                Some(status) => {
                    if *status == SigmaCoverageV1::UnsupportedField || failures[position].is_none()
                    {
                        failures[position] = Some(*status);
                    }
                }
            }
        }
    }
    let mut compiled = Vec::with_capacity(rules.len());
    let mut coverage = Vec::with_capacity(rules.len());
    for (((rule, raw), mut variants), failure) in rules.iter().zip(variants_by_rule).zip(failures) {
        let status = if let Some(status) = failure {
            variants.clear();
            status
        } else if variants.is_empty() {
            let document = irmind_sigma::admit_rule(raw).map_err(|_| invalid())?;
            if table
                .variants
                .iter()
                .any(|variant| covers(&document, variant))
            {
                SigmaCoverageV1::UnavailableSource
            } else {
                SigmaCoverageV1::UnsupportedLogsource
            }
        } else {
            SigmaCoverageV1::Eligible
        };
        let detail = match status {
            SigmaCoverageV1::Eligible => None,
            SigmaCoverageV1::UnsupportedLogsource => {
                Some("No reviewed variant matches the rule logsource")
            }
            SigmaCoverageV1::UnsupportedField => {
                Some("A matching source class lacks an exact binding for a rule field")
            }
            SigmaCoverageV1::UnavailableSource => {
                Some("No signed event artifact matches the rule's reviewed source classes")
            }
            SigmaCoverageV1::UnsupportedRule => {
                Some("A matching source class does not support the rule's modifiers or condition")
            }
        };
        compiled.push(SigmaCompiledRuleV1 {
            rule: rule.clone(),
            variants,
        });
        coverage.push(SigmaRuleCoverageV1 {
            rule: rule.clone(),
            status,
            detail: detail.map(str::to_owned),
        });
    }
    Ok((
        SigmaCompiledRulesV1(compiled),
        SigmaRunResultsV1 {
            coverage,
            matches: Vec::new(),
        },
    ))
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
    results: &SigmaRunResultsV3,
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

pub(super) fn enrolled_field_table() -> SigmaFieldTableV1 {
    SigmaFieldTableV1 {
        id: "irmind-sigma-source-coverage".into(),
        version: "v5".into(),
        toml: concat!(
            include_str!("cloudtrail-v1.toml"),
            "\n",
            include_str!("windows-v1.toml"),
            "\n",
            include_str!("linux-v1.toml"),
            "\n",
            include_str!("network-v1.toml"),
            "\n",
            include_str!("cloud-identity-v1.toml"),
            "\n",
            include_str!("endpoint-v1.toml"),
        )
        .into(),
    }
}

pub(crate) fn verify_class_plan(
    receipt: &SigmaRunV1,
    materials: &irmind_app::v10_proofs::V10SigmaRunObjects,
    table: &ReviewedSigmaFieldTable,
    entries: &[irmind_app::SignedEntry],
    rules: &[(SigmaRuleKeyV1, &[u8])],
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    use irmind_app::v10_proofs::V10CheckpointView;
    let view = V10CheckpointView::resolve(entries, &receipt.checkpoint)?;
    let source_hashes = materials
        .selected_sources
        .0
        .iter()
        .map(|source| irmind_domain::EvidenceHash::from_bytes(source.evidence_sha256))
        .collect::<BTreeSet<_>>();
    let (artifacts, chosen) = select_artifacts(view.entries(), table, |_| true)?;
    for source in &materials.selected_sources.0 {
        let hash = irmind_domain::EvidenceHash::from_bytes(source.evidence_sha256);
        let artifact = chosen.get(hash.as_str()).ok_or_else(invalid)?;
        view.artifact(*source, *artifact)?;
    }
    let available = artifacts
        .iter()
        .filter(|(_, artifact, _)| {
            let ParquetArtifact::V3(envelope) = artifact;
            envelope
                .pipeline()
                .bindings()
                .iter()
                .any(|binding| source_hashes.contains(binding.input().source()))
        })
        .flat_map(|(_, _, variants)| variants.iter().copied())
        .collect();
    let (plan, compiled, output) = plan::compile(table, &available, rules, deadline, cancel)?;
    if materials.class_plan.as_ref() != Some(&plan)
        || materials.compiled_rules != compiled
        || materials.results.coverage != output.coverage
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) struct SigmaMatchCheck<'a> {
    table: &'a ReviewedSigmaFieldTable,
    matches: BTreeMap<V10RowReference, Vec<&'a SigmaRuleKeyV1>>,
    rules: &'a [(SigmaRuleKeyV1, &'a [u8])],
    compiled: &'a SigmaCompiledRulesV1,
    deadline: Instant,
    units: u64,
    cancel: &'a CancellationToken,
    cached: Option<(usize, &'a SigmaRuleKeyV1, SigmaVariantPrograms<'a>)>,
}

impl<'a> SigmaMatchCheck<'a> {
    pub(crate) fn new(
        table: &'a ReviewedSigmaFieldTable,
        materials: &'a irmind_app::v10_proofs::V10SigmaRunObjects,
        rules: &'a [(SigmaRuleKeyV1, &'a [u8])],
        deadline: Instant,
        units: u64,
        cancel: &'a CancellationToken,
    ) -> Self {
        let mut matches = BTreeMap::<_, Vec<_>>::new();
        for found in &materials.results.matches {
            matches.entry(found.row).or_default().push(&found.rule);
        }
        Self {
            table,
            matches,
            rules,
            compiled: &materials.compiled_rules,
            deadline,
            units,
            cancel,
            cached: None,
        }
    }

    pub(crate) fn finish(&self) -> Result<u64, AppError> {
        plan::check_budget(self.deadline, self.cancel)?;
        Ok(self.units)
    }

    pub(crate) fn check(
        &mut self,
        artifact: &ParquetArtifact,
        row: V10RowReference,
        common: &irmind_domain::CommonEventV1,
        original: &str,
    ) -> Result<(), AppError> {
        let ParquetArtifact::V3(envelope) = artifact;
        let origin = common.origin();
        irmind_app::v10_proofs::verify_v10_row_identity(
            row,
            origin.source().as_str(),
            origin.record(),
        )?;
        let binding = envelope
            .pipeline()
            .bindings()
            .iter()
            .find(|binding| {
                binding.input().source() == origin.source()
                    && binding.decoder().id() == origin.parser()
                    && binding.decoder().version() == origin.parser_version()
            })
            .ok_or_else(invalid)?;
        let keys = self.matches.get(&row).ok_or_else(invalid)?;
        for &key in keys {
            plan::check_budget(self.deadline, self.cancel)?;
            let position = self
                .rules
                .binary_search_by(|(candidate, _)| candidate.cmp(key))
                .map_err(|_| invalid())?;
            let rule = self.compiled.0.get(position).ok_or_else(invalid)?;
            let mut confirmed = false;
            for &ordinal in &rule.variants {
                let index = usize::try_from(ordinal).map_err(|_| invalid())?;
                let variant = self.table.variants.get(index).ok_or_else(invalid)?;
                if !matches_binding(variant, binding) {
                    continue;
                }
                if self
                    .cached
                    .as_ref()
                    .is_none_or(|(class, previous, _)| *class != index || previous != &key)
                {
                    let programs = SigmaVariantPrograms::compile(
                        variant,
                        [(key.clone(), self.rules[position].1)],
                    )?;
                    if programs.eligible() != 1 {
                        return Err(invalid());
                    }
                    self.cached = Some((index, key, programs));
                }
                let (_, _, programs) = self.cached.as_ref().ok_or_else(invalid)?;
                let mut attempt = programs.start_with_match_limit(self.units, 1);
                if !attempt.row(common, Some(original), self.cancel, |_| {
                    confirmed = true;
                    Ok(())
                })? {
                    return Err(invalid());
                }
                self.units = self
                    .units
                    .checked_sub(attempt.used_units())
                    .ok_or_else(invalid)?;
                if confirmed {
                    break;
                }
            }
            if !confirmed {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn signed_sigma_plan_requires_every_matching_source_binding() {
        let mut table = SigmaFieldTableV1 {
            toml: include_str!("cloudtrail-v1.toml").into(),
            ..enrolled_field_table()
        };
        let other = table
            .toml
            .replace("dataset = \"cloudtrail\"", "dataset = \"other-dataset\"")
            .replace("service = \"cloudtrail\"", "service = \"other\"")
            .replace("name = \"Outcome\"", "name = \"OtherOutcome\"");
        table.toml.push_str(&other);
        let reviewed = ReviewedSigmaFieldTable::parse(&table).unwrap();
        let rule = "title: Synthetic coverage test\nlogsource: {product: aws}\ndetection: {selection: {Outcome: failure}, condition: selection}\n";
        let rules = [(
            SigmaRuleKeyV1 {
                id: "synthetic-coverage".into(),
                sha256: irmind_app::sha256(rule.as_bytes()),
            },
            rule.as_bytes(),
        )];
        let cancel = CancellationToken::new();
        for (available, status, expected) in [
            (BTreeSet::from([0]), SigmaCoverageV1::Eligible, vec![0]),
            (
                BTreeSet::from([0, 1]),
                SigmaCoverageV1::UnsupportedField,
                vec![],
            ),
            (BTreeSet::new(), SigmaCoverageV1::UnavailableSource, vec![]),
        ] {
            let (compiled, results) = rule_objects(&reviewed, &available, &rules, &cancel).unwrap();
            assert_eq!(compiled.0[0].variants, expected);
            assert_eq!(results.coverage[0].status, status);
        }
    }
}
