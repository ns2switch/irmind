use super::{
    evaluation::{covers, field_kind},
    field_table::ReviewedSigmaFieldTable,
    invalid,
};
use irmind_app::{
    AppError, CancellationToken,
    v10_proofs::{
        SigmaClassOutcome, SigmaClassPlan, SigmaCompiledRuleV1, SigmaCompiledRulesV1,
        SigmaCoverageV1, SigmaRuleCoverageV1, SigmaRuleKeyV1, SigmaRunResultsV1,
    },
};
use irmind_sigma::{SigmaProgram, admit_rule};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

pub(super) fn compile(
    table: &ReviewedSigmaFieldTable,
    available: &BTreeSet<usize>,
    rules: &[(SigmaRuleKeyV1, &[u8])],
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<(SigmaClassPlan, SigmaCompiledRulesV1, SigmaRunResultsV1), AppError> {
    use SigmaClassOutcome::{Eligible, IncompatibleType, MissingBinding, Outside};
    let mut plan = SigmaClassPlan::new(
        available.iter().map(|&index| index as u64).collect(),
        rules.len(),
    )
    .map_err(|_| invalid())?;
    let bindings = class_bindings(table, available)?;
    let mut compiled = Vec::with_capacity(rules.len());
    let mut coverage = Vec::with_capacity(rules.len());

    for (position, (key, raw)) in rules.iter().enumerate() {
        check_budget(deadline, cancel)?;
        if key.sha256 != irmind_app::sha256(raw) {
            return Err(invalid());
        }
        let document = admit_rule(raw).map_err(|_| invalid())?;
        let mut variants = Vec::new();
        let (status, detail) = if let Ok(required) = SigmaProgram::validate_rule(&document) {
            let mut missing = false;
            let mut incompatible = false;
            for (class, (&ordinal, fields)) in available.iter().zip(&bindings).enumerate() {
                check_budget(deadline, cancel)?;
                let outcome = if !covers(&document, &table.variants[ordinal]) {
                    Outside
                } else if required.iter().any(|field| !fields.contains_key(*field)) {
                    missing = true;
                    MissingBinding
                } else {
                    match SigmaProgram::compile(&document, fields) {
                        Ok(_) => {
                            variants.push(ordinal as u64);
                            Eligible
                        }
                        Err(
                            irmind_sigma::CompileError::WrongType
                            | irmind_sigma::CompileError::UnsupportedModifier
                            | irmind_sigma::CompileError::Pattern,
                        ) => {
                            incompatible = true;
                            IncompatibleType
                        }
                        Err(_) => return Err(invalid()),
                    }
                };
                plan.set(position, class, outcome).map_err(|_| invalid())?;
            }
            summarize(&variants, missing, incompatible, || {
                table
                    .variants
                    .iter()
                    .any(|variant| covers(&document, variant))
            })
        } else {
            (
                SigmaCoverageV1::UnsupportedRule,
                Some("Rule rejected before source-class compilation"),
            )
        };
        compiled.push(SigmaCompiledRuleV1 {
            rule: key.clone(),
            variants,
        });
        coverage.push(SigmaRuleCoverageV1 {
            rule: key.clone(),
            status,
            detail: detail.map(str::to_owned),
        });
    }
    check_budget(deadline, cancel)?;
    Ok((
        plan,
        SigmaCompiledRulesV1(compiled),
        SigmaRunResultsV1 {
            coverage,
            matches: Vec::new(),
        },
    ))
}

fn class_bindings(
    table: &ReviewedSigmaFieldTable,
    available: &BTreeSet<usize>,
) -> Result<Vec<BTreeMap<String, irmind_sigma::SigmaFieldKind>>, AppError> {
    available
        .iter()
        .map(|&index| {
            let class = table.variants.get(index).ok_or_else(invalid)?;
            Ok(class
                .fields
                .iter()
                .map(|binding| (binding.name.clone(), field_kind(binding.value_type)))
                .collect::<BTreeMap<_, _>>())
        })
        .collect()
}

pub(super) fn skipped_classes(
    plan: &SigmaClassPlan,
    reviewed: &ReviewedSigmaFieldTable,
    rule_count: usize,
) -> Result<Vec<(String, usize, usize)>, AppError> {
    use SigmaClassOutcome::{IncompatibleType, MissingBinding};
    let mut skipped_classes = BTreeMap::<_, (usize, usize)>::new();
    for rule in 0..rule_count {
        for (ordinal, outcome) in plan.row(rule) {
            match outcome {
                MissingBinding => skipped_classes.entry(ordinal).or_default().0 += 1,
                IncompatibleType => skipped_classes.entry(ordinal).or_default().1 += 1,
                _ => {}
            }
        }
    }
    skipped_classes
        .into_iter()
        .map(|(ordinal, (missing, kinds))| {
            let class = &reviewed.variants[usize::try_from(ordinal).map_err(|_| invalid())?];
            let label = format!(
                "{} · {}/{}/{} · {}",
                class.parser_id,
                class.product.as_deref().unwrap_or("*"),
                class.service.as_deref().unwrap_or("*"),
                class.category.as_deref().unwrap_or("*"),
                class.mapping_id,
            );
            Ok((label, missing, kinds))
        })
        .collect()
}

fn summarize(
    eligible: &[u64],
    missing: bool,
    incompatible: bool,
    reviewed: impl FnOnce() -> bool,
) -> (SigmaCoverageV1, Option<&'static str>) {
    use SigmaCoverageV1::{
        Eligible, UnavailableSource, UnsupportedField, UnsupportedLogsource, UnsupportedRule,
    };
    if !eligible.is_empty() {
        (Eligible, None)
    } else if missing {
        (
            UnsupportedField,
            Some("A matching source class lacks an exact binding for a rule field"),
        )
    } else if incompatible {
        (
            UnsupportedRule,
            Some("A matching source class has an incompatible rule field type"),
        )
    } else if reviewed() {
        (
            UnavailableSource,
            Some("No signed event artifact matches the rule's reviewed source classes"),
        )
    } else {
        (
            UnsupportedLogsource,
            Some("No reviewed variant matches the rule logsource"),
        )
    }
}

pub(crate) fn check_budget(deadline: Instant, cancel: &CancellationToken) -> Result<(), AppError> {
    if cancel.is_cancelled() {
        return Err(AppError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(AppError::Policy(
            "Sigma class planning or verification reached its deadline".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::v10_proofs::{SigmaFieldTableV1, SigmaRunResultsV3};
    use std::time::Duration;

    #[test]
    fn source_class_planner_reproduces_approved_decisions_from_rules() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../testkit/fixtures/contracts/sigma_source_class_compilation.json"
        ))
        .unwrap();
        let bytes =
            |value: &serde_json::Value| hex::decode(value["bytes_hex"].as_str().unwrap()).unwrap();
        let table = SigmaFieldTableV1::decode(&bytes(&vectors["field_table"])).unwrap();
        let table = ReviewedSigmaFieldTable::parse(&table).unwrap();
        let cancel = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        for (name, vector) in vectors["valid"].as_object().unwrap() {
            let expected = SigmaRunResultsV3::decode(&bytes(&vector["results"])).unwrap();
            let compiled = SigmaCompiledRulesV1::decode(&bytes(&vector["compiled_rules"])).unwrap();
            let available = expected
                .plan
                .classes()
                .iter()
                .map(|&ordinal| usize::try_from(ordinal).unwrap())
                .collect();
            let rules = compiled
                .0
                .iter()
                .map(|rule| {
                    (
                        rule.rule.clone(),
                        vectors["synthetic_rules"][&rule.rule.id]
                            .as_str()
                            .unwrap()
                            .as_bytes(),
                    )
                })
                .collect::<Vec<_>>();
            let (plan, selected, summaries) =
                compile(&table, &available, &rules, deadline, &cancel).unwrap();
            assert_eq!(plan, expected.plan, "{name}");
            assert!(selected == compiled, "{name}");
            assert!(
                summaries.coverage == expected.scan.results.coverage,
                "{name}"
            );
        }
        cancel.cancel();
        assert!(matches!(
            compile(&table, &BTreeSet::new(), &[], deadline, &cancel),
            Err(AppError::Cancelled)
        ));
    }
}

#[cfg(all(test, not(debug_assertions)))]
#[allow(clippy::unwrap_used)]
#[test]
#[ignore = "offline release audit of one SHA-256-pinned SigmaHQ rule"]
#[expect(
    clippy::too_many_lines,
    reason = "keep the per-file measurement and its reported totals together"
)]
fn sigma_audit_v2_v3_one_rule() {
    use crate::sigma_pack::{inspect_local_sigma_pack, runtime};
    use irmind_app::v10_proofs::SigmaFieldTableV1;
    use std::{env, fs, time::Duration};

    let cancel = CancellationToken::new();
    let archive_rule = fs::read(env::var_os("IRMIND_SIGMAHQ_INPUT").unwrap()).unwrap();
    let table = fs::read_to_string(env::var_os("IRMIND_SIGMAHQ_TABLE").unwrap()).unwrap();
    let table = ReviewedSigmaFieldTable::parse(&SigmaFieldTableV1 {
        id: "synthetic-release-audit".into(),
        version: "v3".into(),
        toml: table
            .replace(
                "mapping_version = \"@gke-paths-v2-",
                "mapping_version = \"gke-paths-v2-synthetic-",
            )
            .replace("mapping_version = \"@", "mapping_version = \"synthetic-"),
    })
    .unwrap();
    let input = tempfile::tempdir().unwrap();
    fs::write(input.path().join("audit.yml"), &archive_rule).unwrap();
    let start = Instant::now();
    let Ok(pack) = inspect_local_sigma_pack(input.path(), &cancel) else {
        println!("SIGMA_AUDIT\t0");
        return;
    };
    if env::var("IRMIND_SIGMAHQ_CORRELATION").unwrap() == "1" {
        println!("SIGMA_AUDIT\t0");
        return;
    }
    let available = (0..table.variants.len()).collect();
    let rules = [(pack.manifest.0[0].rule.clone(), pack.rules[0].as_slice())];
    let (v2, _) = runtime::rule_objects(&table, &available, &rules, &cancel).unwrap();
    let v2_us = start.elapsed().as_micros();
    let start = Instant::now();
    let (matrix, v3, _) = compile(
        &table,
        &available,
        &rules,
        start + Duration::from_secs(2),
        &cancel,
    )
    .unwrap();
    let format = match (v3.0[0].variants.is_empty(), matrix.coverage().skipped_pairs) {
        (true, _) => "none",
        (false, 0) => "all",
        (false, _) => "some",
    };
    let outcomes = matrix
        .row(0)
        .map(|(_, outcome)| outcome)
        .collect::<Vec<_>>();
    let count = |kind| outcomes.iter().filter(|&&item| item == kind).count();
    println!(
        "SIGMA_AUDIT\t1\t{}\t{format}\t{}\t{}\t{}\t{}\t{v2_us}\t{}",
        u8::from(!v2.0[0].variants.is_empty()),
        count(SigmaClassOutcome::Eligible),
        count(SigmaClassOutcome::MissingBinding),
        count(SigmaClassOutcome::IncompatibleType),
        v2.0[0].variants.len(),
        start.elapsed().as_micros(),
    );
    let document = admit_rule(&pack.rules[0]).unwrap();
    if let Ok(required) = SigmaProgram::validate_rule(&document) {
        let mut fields = BTreeSet::<&str>::new();
        for (ordinal, outcome) in matrix.row(0) {
            if outcome == SigmaClassOutcome::MissingBinding {
                let class = &table.variants[usize::try_from(ordinal).unwrap()];
                fields.extend(
                    required
                        .iter()
                        .copied()
                        .filter(|&name| !class.fields.iter().any(|binding| binding.name == name)),
                );
            }
        }
        for field in fields {
            if !field.is_empty()
                && field.len() <= 128
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-$()".contains(&byte))
            {
                println!("SIGMA_GAP\t{field}");
            }
        }
    }
}
