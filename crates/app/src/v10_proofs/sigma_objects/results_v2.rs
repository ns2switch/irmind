use super::{MAX_RULES, SigmaCoverageV1, SigmaRuleKeyV1, SigmaRunResultsV1, check_size, put_count};
use crate::v10_proofs::{INVALID, Result, V10SourceReference, Wire};
use std::collections::BTreeSet;

const RESULTS: &[u8] = b"irmind-sigma-run-results-v2\0";

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaRunResultsV2 {
    pub results: SigmaRunResultsV1,
    pub unavailable_by_source: Vec<(V10SourceReference, u64)>,
    pub indeterminate_by_rule: Vec<(SigmaRuleKeyV1, u64)>,
}

impl SigmaRunResultsV2 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, RESULTS)?;
        let result = Self::read_lists(&mut wire)?;
        wire.finish()?;
        Ok(result)
    }

    pub(super) fn read_lists(wire: &mut Wire<'_>) -> Result<Self> {
        let results = SigmaRunResultsV1::read_lists(wire)?;
        let unavailable_by_source = wire.list(80, |wire| {
            Ok((V10SourceReference::read(wire)?, wire.u64()?))
        })?;
        let indeterminate_by_rule = wire.bounded_list(MAX_RULES, 45, |wire| {
            Ok((SigmaRuleKeyV1::read(wire)?, wire.u64()?))
        })?;
        let result = Self {
            results,
            unavailable_by_source,
            indeterminate_by_rule,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = RESULTS.to_vec();
        self.write_lists(&mut out)?;
        Ok(out)
    }

    pub(super) fn write_lists(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        self.results.write_lists(out)?;
        put_count(out, self.unavailable_by_source.len())?;
        for (source, count) in &self.unavailable_by_source {
            source.write(out)?;
            out.extend_from_slice(&count.to_be_bytes());
            check_size(out.len())?;
        }
        put_count(out, self.indeterminate_by_rule.len())?;
        for (rule, count) in &self.indeterminate_by_rule {
            rule.write(out)?;
            out.extend_from_slice(&count.to_be_bytes());
            check_size(out.len())?;
        }
        check_size(out.len())?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self
            .unavailable_by_source
            .windows(2)
            .any(|pair| pair[0].0.manifest.sequence >= pair[1].0.manifest.sequence)
            || self.indeterminate_by_rule.len() > MAX_RULES
            || self
                .indeterminate_by_rule
                .windows(2)
                .any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(INVALID);
        }
        let unavailable_rows =
            self.unavailable_by_source
                .iter()
                .try_fold(0u64, |total, (_, count)| {
                    if *count == 0 {
                        return Err(INVALID);
                    }
                    total.checked_add(*count).ok_or(INVALID)
                })?;
        let eligible: BTreeSet<_> = self
            .results
            .coverage
            .iter()
            .filter_map(|entry| (entry.status == SigmaCoverageV1::Eligible).then_some(&entry.rule))
            .collect();
        if self.indeterminate_by_rule.iter().any(|(rule, count)| {
            *count == 0 || *count > unavailable_rows || !eligible.contains(rule)
        }) {
            return Err(INVALID);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::v10_proofs::{SigmaRunStatusV1, SigmaRunV1};

    #[test]
    fn canonical_partial_result_matches_the_approved_vector() {
        let bundle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../testkit/fixtures/contracts/sigma_exact_source_fields.json"
        ))
        .unwrap();
        let vector = &bundle["partial_run_wire"];
        let bytes =
            |item: &serde_json::Value| hex::decode(item["bytes_hex"].as_str().unwrap()).unwrap();
        let body = bytes(&vector["results"]);
        let result = SigmaRunResultsV2::decode(&body).unwrap();
        assert_eq!(result.encode().unwrap(), body);
        assert_eq!(result.results.matches.len(), 1);
        assert_eq!(
            result
                .unavailable_by_source
                .iter()
                .map(|(_, count)| *count)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(
            result
                .indeterminate_by_rule
                .iter()
                .map(|(_, count)| *count)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        for name in ["duplicate_source", "zero_source_rows"] {
            assert!(SigmaRunResultsV2::decode(&bytes(&vector["invalid_results"][name])).is_err());
        }
        let receipt = vector["receipt"]["bytes_hex"].as_str().unwrap();
        let run = SigmaRunV1::decode(receipt).unwrap();
        assert_eq!(run.status, SigmaRunStatusV1::ExactFieldsUnavailable);
        assert_eq!(run.result_manifest, crate::sha256(&body));
        assert_eq!(run.encode().unwrap(), receipt);
    }
}
