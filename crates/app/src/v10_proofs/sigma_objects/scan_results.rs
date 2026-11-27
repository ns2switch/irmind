use super::{MAX_RULES, SigmaCoverageV1, SigmaMatchedRows, SigmaRuleKeyV1, check_size, put_count};
use crate::v10_proofs::{INVALID, Result, V10SourceReference, Wire};
use std::collections::BTreeSet;

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaScanResults {
    pub results: SigmaMatchedRows,
    pub unavailable_by_source: Vec<(V10SourceReference, u64)>,
    pub indeterminate_by_rule: Vec<(SigmaRuleKeyV1, u64)>,
}

impl SigmaScanResults {
    pub(super) fn read_lists(wire: &mut Wire<'_>) -> Result<Self> {
        let results = SigmaMatchedRows::read_lists(wire)?;
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
