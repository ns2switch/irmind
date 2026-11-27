use super::{
    MAX_RULES, MAX_VARIANTS, SigmaCompiledRulesV1, SigmaCoverageV1, SigmaRuleCoverageV1,
    SigmaScanResults, check_size, increasing, put_count,
};
use crate::v10_proofs::{INVALID, Result, SigmaRunStatusV1, Wire};

const DOMAIN: &[u8] = b"irmind-sigma-run-results-v3\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SigmaClassOutcome {
    Outside = 0,
    Eligible = 1,
    MissingBinding = 2,
    IncompatibleType = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigmaClassPlan {
    classes: Vec<u64>,
    rule_count: usize,
    cells: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SigmaClassCoverage {
    pub all_rules: usize,
    pub some_rules: usize,
    pub no_rules: usize,
    pub eligible_pairs: usize,
    pub skipped_pairs: usize,
}

impl SigmaClassPlan {
    pub fn new(classes: Vec<u64>, rule_count: usize) -> Result<Self> {
        if classes.len() > MAX_VARIANTS
            || classes
                .last()
                .is_some_and(|&index| index >= MAX_VARIANTS as u64)
            || rule_count > MAX_RULES
        {
            return Err(INVALID);
        }
        increasing(&classes, |index| *index)?;
        let cells = vec![0; rule_count * classes.len().div_ceil(4)];
        Ok(Self {
            classes,
            rule_count,
            cells,
        })
    }

    pub fn set(&mut self, rule: usize, class: usize, value: SigmaClassOutcome) -> Result<()> {
        if rule >= self.rule_count || class >= self.classes.len() {
            return Err(INVALID);
        }
        let index = rule * self.classes.len().div_ceil(4) + class / 4;
        let shift = 2 * (class % 4);
        self.cells[index] = (self.cells[index] & !(3 << shift)) | ((value as u8) << shift);
        Ok(())
    }

    pub fn classes(&self) -> &[u64] {
        &self.classes
    }

    pub fn row(&self, rule: usize) -> impl Iterator<Item = (u64, SigmaClassOutcome)> + '_ {
        self.classes
            .iter()
            .copied()
            .enumerate()
            .filter_map(move |(class, ordinal)| {
                let index = rule
                    .checked_mul(self.classes.len().div_ceil(4))?
                    .checked_add(class / 4)?;
                let value = match (self.cells.get(index)? >> (2 * (class % 4))) & 3 {
                    0 => SigmaClassOutcome::Outside,
                    1 => SigmaClassOutcome::Eligible,
                    2 => SigmaClassOutcome::MissingBinding,
                    _ => SigmaClassOutcome::IncompatibleType,
                };
                Some((ordinal, value))
            })
    }

    pub fn coverage(&self) -> SigmaClassCoverage {
        let mut summary = SigmaClassCoverage::default();
        for rule in 0..self.rule_count {
            let mut eligible = 0;
            let mut skipped = 0;
            for (_, outcome) in self.row(rule) {
                match outcome {
                    SigmaClassOutcome::Eligible => eligible += 1,
                    SigmaClassOutcome::MissingBinding | SigmaClassOutcome::IncompatibleType => {
                        skipped += 1;
                    }
                    SigmaClassOutcome::Outside => {}
                }
            }
            summary.eligible_pairs += eligible;
            summary.skipped_pairs += skipped;
            if eligible == 0 {
                summary.no_rules += 1;
            } else if skipped > 0 {
                summary.some_rules += 1;
            } else {
                summary.all_rules += 1;
            }
        }
        summary
    }

    pub fn validate_compiled(
        &self,
        compiled: &SigmaCompiledRulesV1,
        coverage: &[SigmaRuleCoverageV1],
        table_count: usize,
    ) -> Result<()> {
        if self.rule_count != compiled.0.len()
            || self.rule_count != coverage.len()
            || self
                .classes
                .last()
                .is_some_and(|&ordinal| ordinal >= table_count as u64)
        {
            return Err(INVALID);
        }
        for (index, (rule, summary)) in compiled.0.iter().zip(coverage).enumerate() {
            let eligible = self.row(index).filter_map(|(ordinal, outcome)| {
                (outcome == SigmaClassOutcome::Eligible).then_some(ordinal)
            });
            if rule.rule != summary.rule
                || !eligible.eq(rule.variants.iter().copied())
                || rule.variants.is_empty() == (summary.status == SigmaCoverageV1::Eligible)
            {
                return Err(INVALID);
            }
        }
        Ok(())
    }

    fn read(wire: &mut Wire<'_>, expected_rules: usize) -> Result<Self> {
        let classes = wire.bounded_list(MAX_VARIANTS, 8, Wire::u64)?;
        let rule_count = usize::try_from(wire.u64()?).map_err(|_| INVALID)?;
        if rule_count != expected_rules {
            return Err(INVALID);
        }
        let mut plan = Self::new(classes, rule_count)?;
        let raw = wire.take(plan.cells.len())?;
        let remainder = plan.classes.len() % 4;
        if remainder != 0
            && raw.chunks_exact(plan.classes.len().div_ceil(4)).any(|row| {
                row.last()
                    .is_some_and(|value| value >> (2 * remainder) != 0)
            })
        {
            return Err(INVALID);
        }
        plan.cells.copy_from_slice(raw);
        Ok(plan)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        put_count(out, self.classes.len())?;
        for &class in &self.classes {
            out.extend_from_slice(&class.to_be_bytes());
        }
        put_count(out, self.rule_count)?;
        out.extend_from_slice(&self.cells);
        check_size(out.len())
    }
}

pub struct SigmaRunResultsV3 {
    pub scan: SigmaScanResults,
    pub plan: SigmaClassPlan,
}

impl SigmaRunResultsV3 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, DOMAIN)?;
        let scan = SigmaScanResults::read_lists(&mut wire)?;
        let plan = SigmaClassPlan::read(&mut wire, scan.results.coverage.len())?;
        wire.finish()?;
        Ok(Self { scan, plan })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.plan.rule_count != self.scan.results.coverage.len() {
            return Err(INVALID);
        }
        let mut out = DOMAIN.to_vec();
        self.scan.write_lists(&mut out)?;
        self.plan.write(&mut out)?;
        Ok(out)
    }

    pub fn status(&self, scan: SigmaRunStatusV1) -> SigmaRunStatusV1 {
        use SigmaRunStatusV1::{
            Cancelled, Complete, CoverageLimited, ExactFieldsUnavailable, OversizedInput,
            TimeLimit, WorkLimit,
        };
        if matches!(scan, Cancelled | OversizedInput | TimeLimit | WorkLimit) {
            return scan;
        }
        let coverage = self.plan.coverage();
        if coverage.no_rules > 0 || coverage.skipped_pairs > 0 {
            CoverageLimited
        } else if self.scan.indeterminate_by_rule.is_empty() {
            Complete
        } else {
            ExactFieldsUnavailable
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::v10_proofs::{SigmaRunV2, V10ProofDescriptor, V10ProofFamily, v10_proof_commitment};

    fn bytes(value: &serde_json::Value) -> Vec<u8> {
        hex::decode(value["bytes_hex"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn approved_v3_results_reproduce_wire_bytes() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../testkit/fixtures/contracts/sigma_source_class_compilation.json"
        ))
        .unwrap();
        for (name, vector) in vectors["valid"].as_object().unwrap() {
            let body = bytes(&vector["results"]);
            let result = SigmaRunResultsV3::decode(&body).unwrap();
            let status = SigmaRunStatusV1::read(&mut Wire(&[u8::try_from(
                vector["status_code"].as_u64().unwrap(),
            )
            .unwrap()]))
            .unwrap();
            assert_eq!(result.encode().unwrap(), body, "{name}");
            assert_eq!(result.status(status), status, "{name}");
            let compiled = SigmaCompiledRulesV1::decode(&bytes(&vector["compiled_rules"])).unwrap();
            result
                .plan
                .validate_compiled(&compiled, &result.scan.results.coverage, 5)
                .unwrap();
            let proofs = [
                &vectors["field_table"],
                &vector["scope"],
                &vector["compiled_rules"],
                &vector["results"],
            ]
            .into_iter()
            .zip(2..=5)
            .map(|(value, kind)| {
                V10ProofDescriptor::from_body(V10ProofFamily::Sigma, kind, &bytes(value)).unwrap()
            })
            .collect::<Vec<_>>();
            assert_eq!(
                crate::hex(&v10_proof_commitment(V10ProofFamily::Sigma, &proofs).unwrap()),
                vector["proof_set_sha256"],
                "{name}"
            );
        }
    }

    #[test]
    fn exact_field_gap_counts_survive_the_current_result_codec() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../testkit/fixtures/contracts/sigma_exact_source_fields.json"
        ))
        .unwrap();
        let vector = &vectors["partial_run_wire"];
        let body = bytes(&vector["results"]);
        let result = SigmaRunResultsV3::decode(&body).unwrap();
        assert_eq!(result.encode().unwrap(), body);
        assert_eq!(
            result.status(SigmaRunStatusV1::Complete),
            SigmaRunStatusV1::ExactFieldsUnavailable
        );
        assert_eq!(result.scan.results.matches.len(), 1);
        assert_eq!(
            result
                .scan
                .unavailable_by_source
                .iter()
                .map(|entry| entry.1)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(
            result
                .scan
                .indeterminate_by_rule
                .iter()
                .map(|entry| entry.1)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        for name in ["duplicate_source", "zero_source_rows"] {
            assert!(
                SigmaRunResultsV3::decode(&bytes(&vector["invalid_results"][name])).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn approved_invalid_v3_matrices_and_statuses_fail_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../testkit/fixtures/contracts/sigma_source_class_compilation.json"
        ))
        .unwrap();
        for name in [
            "nonzero_padding",
            "duplicate_class",
            "wrong_rule_count",
            "truncated_matrix",
            "trailing_byte",
        ] {
            assert!(
                SigmaRunResultsV3::decode(&bytes(&vectors["reject"][name]["results"])).is_err(),
                "{name}"
            );
        }
        for name in [
            "class_outside_table",
            "class_outside_scope",
            "compiled_and_matrix_disagree",
        ] {
            let vector = &vectors["reject"][name];
            let result = SigmaRunResultsV3::decode(&bytes(&vector["results"])).unwrap();
            let compiled = SigmaCompiledRulesV1::decode(&bytes(&vector["compiled_rules"])).unwrap();
            assert!(
                result
                    .plan
                    .validate_compiled(&compiled, &result.scan.results.coverage, 5)
                    .is_err(),
                "{name}"
            );
        }
        let vector = &vectors["reject"]["complete_with_pair_gaps"];
        let result = SigmaRunResultsV3::decode(&bytes(&vector["results"])).unwrap();
        assert_eq!(
            result.status(SigmaRunStatusV1::Complete),
            SigmaRunStatusV1::CoverageLimited
        );
        let mut receipt = SigmaRunV2::decode(&crate::v10_proofs::tests::new_run()).unwrap();
        receipt.evaluator = "irmind-sigma-evaluator-v2".into();
        assert!(receipt.encode().is_err());
    }
}
