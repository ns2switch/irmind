//! Canonical Sigma proof bodies. Rule and field-table semantics are validated by the compiler.
use super::{
    Digest, INVALID, Result, V10AuditReference, V10RowReference, V10SourceReference, Wire,
    put_text,
    report_objects::{check_size, increasing, put_count},
};
use std::collections::{BTreeMap, BTreeSet};

const PACK: &[u8] = b"irmind-sigma-pack-manifest-v1\0";
const TABLE: &[u8] = b"irmind-sigma-field-table-v1\0";
const SCOPE: &[u8] = b"irmind-sigma-source-scope-v1\0";
const COMPILED: &[u8] = b"irmind-sigma-compiled-rules-v1\0";
mod results_v2;
pub use results_v2::SigmaRunResultsV2;

const RESULTS: &[u8] = b"irmind-sigma-run-results-v1\0";
const MAX_RULES: usize = 4096;
const MAX_RULE_BYTES: u64 = 64 * 1024;
const MAX_TABLE_BYTES: usize = 512 * 1024;
const MAX_VARIANTS: usize = 1024;
const MAX_IDENTIFIER: usize = 128;
const MAX_METADATA: usize = 512;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SigmaRuleKeyV1 {
    pub id: String,
    pub sha256: Digest,
}

impl SigmaRuleKeyV1 {
    fn read(wire: &mut Wire<'_>) -> Result<Self> {
        Ok(Self {
            id: identifier(wire.text(MAX_IDENTIFIER)?)?,
            sha256: wire.fixed()?,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.id.chars().any(char::is_control) {
            return Err(INVALID);
        }
        put_text(out, &self.id, MAX_IDENTIFIER)?;
        out.extend_from_slice(&self.sha256);
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaPackRuleV1 {
    pub path: String,
    pub rule: SigmaRuleKeyV1,
    pub version: Option<String>,
    pub author: Option<String>,
    pub size: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaPackManifestV1(pub Vec<SigmaPackRuleV1>);

impl SigmaPackManifestV1 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, PACK)?;
        let rules = wire.bounded_list(MAX_RULES, 5 + 5 + 1 + 1 + 32 + 8, |wire| {
            let path = wire.text(MAX_METADATA)?;
            let id = identifier(wire.text(MAX_IDENTIFIER)?)?;
            let version = optional_text(wire, MAX_IDENTIFIER)?;
            let author = optional_text(wire, MAX_METADATA)?;
            let sha256 = wire.fixed()?;
            let size = wire.u64()?;
            Ok(SigmaPackRuleV1 {
                path,
                rule: SigmaRuleKeyV1 { id, sha256 },
                version,
                author,
                size,
            })
        })?;
        wire.finish()?;
        let manifest = Self(rules);
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = PACK.to_vec();
        put_count(&mut out, self.0.len())?;
        for item in &self.0 {
            put_text(&mut out, &item.path, MAX_METADATA)?;
            put_text(&mut out, &item.rule.id, MAX_IDENTIFIER)?;
            write_optional_text(&mut out, item.version.as_deref(), MAX_IDENTIFIER)?;
            write_optional_text(&mut out, item.author.as_deref(), MAX_METADATA)?;
            out.extend_from_slice(&item.rule.sha256);
            out.extend_from_slice(&item.size.to_be_bytes());
        }
        Ok(out)
    }

    fn validate(&self) -> Result<()> {
        if !(1..=MAX_RULES).contains(&self.0.len())
            || self
                .0
                .windows(2)
                .any(|items| items[0].path >= items[1].path)
        {
            return Err(INVALID);
        }
        let mut ids = BTreeSet::new();
        let mut bytes = 0u64;
        for item in &self.0 {
            bytes = bytes.checked_add(item.size).ok_or(INVALID)?;
            if bytes > 64 * 1024 * 1024
                || !(1..=MAX_RULE_BYTES).contains(&item.size)
                || !ids.insert(item.rule.id.as_str())
                || item.rule.id.chars().any(char::is_control)
                || item.path.contains(['\\', ':'])
                || item.path.chars().any(char::is_control)
                || item
                    .path
                    .split('/')
                    .any(|part| matches!(part, "" | "." | ".."))
            {
                return Err(INVALID);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaFieldTableV1 {
    pub id: String,
    pub version: String,
    pub toml: String,
}

impl SigmaFieldTableV1 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        check_table_size(body.len())?;
        let mut wire = Wire::object(body, TABLE)?;
        let table = Self {
            id: identifier(wire.text(MAX_IDENTIFIER)?)?,
            version: identifier(wire.text(MAX_IDENTIFIER)?)?,
            toml: wire.text(MAX_TABLE_BYTES)?,
        };
        wire.finish()?;
        Ok(table)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if [&self.id, &self.version]
            .into_iter()
            .any(|text| text.chars().any(char::is_control))
        {
            return Err(INVALID);
        }
        let mut out = TABLE.to_vec();
        put_text(&mut out, &self.id, MAX_IDENTIFIER)?;
        put_text(&mut out, &self.version, MAX_IDENTIFIER)?;
        put_text(&mut out, &self.toml, MAX_TABLE_BYTES)?;
        check_table_size(out.len())?;
        Ok(out)
    }
}

fn check_table_size(bytes: usize) -> Result<()> {
    if bytes > MAX_TABLE_BYTES {
        return Err(INVALID);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigmaSourceScopeV1(pub Vec<V10SourceReference>);

impl SigmaSourceScopeV1 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, SCOPE)?;
        let sources = wire.list(72, V10SourceReference::read)?;
        wire.finish()?;
        increasing(&sources, |source| source.manifest.sequence)?;
        Ok(Self(sources))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        increasing(&self.0, |source| source.manifest.sequence)?;
        let mut out = SCOPE.to_vec();
        put_count(&mut out, self.0.len())?;
        for source in &self.0 {
            source.write(&mut out)?;
            check_size(out.len())?;
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigmaCompiledRuleV1 {
    pub rule: SigmaRuleKeyV1,
    pub variants: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigmaCompiledRulesV1(pub Vec<SigmaCompiledRuleV1>);

impl SigmaCompiledRulesV1 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, COMPILED)?;
        let rules = wire.bounded_list(MAX_RULES, 5 + 32 + 8, |wire| {
            let rule = SigmaRuleKeyV1::read(wire)?;
            let variants = wire.bounded_list(MAX_VARIANTS, 8, Wire::u64)?;
            Ok(SigmaCompiledRuleV1 { rule, variants })
        })?;
        wire.finish()?;
        let compiled = Self(rules);
        compiled.validate()?;
        Ok(compiled)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = COMPILED.to_vec();
        put_count(&mut out, self.0.len())?;
        for rule in &self.0 {
            rule.rule.write(&mut out)?;
            put_count(&mut out, rule.variants.len())?;
            for index in &rule.variants {
                out.extend_from_slice(&index.to_be_bytes());
            }
            check_size(out.len())?;
        }
        Ok(out)
    }

    fn validate(&self) -> Result<()> {
        increasing_rules(&self.0, |item| &item.rule)?;
        for rule in &self.0 {
            if rule.variants.len() > MAX_VARIANTS
                || rule
                    .variants
                    .last()
                    .is_some_and(|last| *last >= MAX_VARIANTS as u64)
            {
                return Err(INVALID);
            }
            increasing(&rule.variants, |index| *index)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SigmaCoverageV1 {
    Eligible = 0,
    UnsupportedLogsource = 1,
    UnsupportedField = 2,
    UnavailableSource = 3,
    UnsupportedRule = 4,
}

impl SigmaCoverageV1 {
    fn read(wire: &mut Wire<'_>) -> Result<Self> {
        match wire.byte()? {
            0 => Ok(Self::Eligible),
            1 => Ok(Self::UnsupportedLogsource),
            2 => Ok(Self::UnsupportedField),
            3 => Ok(Self::UnavailableSource),
            4 => Ok(Self::UnsupportedRule),
            _ => Err(INVALID),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaRuleCoverageV1 {
    pub rule: SigmaRuleKeyV1,
    pub status: SigmaCoverageV1,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigmaMatchV1 {
    pub rule: SigmaRuleKeyV1,
    pub row: V10RowReference,
    pub query_limit: Option<V10AuditReference>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SigmaRunResultsV1 {
    pub coverage: Vec<SigmaRuleCoverageV1>,
    pub matches: Vec<SigmaMatchV1>,
}

impl SigmaRunResultsV1 {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut wire = Wire::object(body, RESULTS)?;
        let result = Self::read_lists(&mut wire)?;
        wire.finish()?;
        Ok(result)
    }

    fn read_lists(wire: &mut Wire<'_>) -> Result<Self> {
        let coverage = wire.bounded_list(MAX_RULES, 5 + 32 + 1 + 1, |wire| {
            Ok(SigmaRuleCoverageV1 {
                rule: SigmaRuleKeyV1::read(wire)?,
                status: SigmaCoverageV1::read(wire)?,
                detail: optional_text(wire, MAX_METADATA)?,
            })
        })?;
        let matches = wire.list(5 + 32 + 160 + 1, |wire| {
            let rule = SigmaRuleKeyV1::read(wire)?;
            let row = V10RowReference::read(wire)?;
            let query_limit = match wire.byte()? {
                0 => None,
                1 => Some(V10AuditReference::read(wire)?),
                _ => return Err(INVALID),
            };
            Ok(SigmaMatchV1 {
                rule,
                row,
                query_limit,
            })
        })?;
        let result = Self { coverage, matches };
        result.validate()?;
        Ok(result)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = RESULTS.to_vec();
        self.write_lists(&mut out)?;
        Ok(out)
    }

    fn write_lists(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        put_count(out, self.coverage.len())?;
        for entry in &self.coverage {
            entry.rule.write(out)?;
            out.push(entry.status as u8);
            write_optional_text(out, entry.detail.as_deref(), MAX_METADATA)?;
        }
        put_count(out, self.matches.len())?;
        for item in &self.matches {
            item.rule.write(out)?;
            item.row.write(out)?;
            if let Some(receipt) = item.query_limit {
                out.push(1);
                receipt.write(out)?;
            } else {
                out.push(0);
            }
            check_size(out.len())?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        increasing_rules(&self.coverage, |item| &item.rule)?;
        if self
            .matches
            .windows(2)
            .any(|items| items[0].rule > items[1].rule)
        {
            return Err(INVALID);
        }
        let states = self
            .coverage
            .iter()
            .map(|item| (&item.rule, item.status))
            .collect::<BTreeMap<_, _>>();
        if self
            .coverage
            .iter()
            .any(|item| (item.status == SigmaCoverageV1::Eligible) == item.detail.is_some())
        {
            return Err(INVALID);
        }
        let mut seen = BTreeSet::new();
        for item in &self.matches {
            if states.get(&item.rule) != Some(&SigmaCoverageV1::Eligible)
                || !seen.insert((&item.rule, item.row))
            {
                return Err(INVALID);
            }
        }
        Ok(())
    }
}

fn increasing_rules<T>(items: &[T], key: impl Fn(&T) -> &SigmaRuleKeyV1) -> Result<()> {
    if items.len() > MAX_RULES
        || items
            .windows(2)
            .any(|items| key(&items[0]) >= key(&items[1]))
    {
        return Err(INVALID);
    }
    Ok(())
}

fn identifier(value: String) -> Result<String> {
    if value.chars().any(char::is_control) {
        return Err(INVALID);
    }
    Ok(value)
}

fn optional_text(wire: &mut Wire<'_>, limit: usize) -> Result<Option<String>> {
    match wire.byte()? {
        0 => Ok(None),
        1 => wire.text(limit).map(Some),
        _ => Err(INVALID),
    }
}

fn write_optional_text(out: &mut Vec<u8>, text: Option<&str>, limit: usize) -> Result<()> {
    if let Some(text) = text {
        out.push(1);
        put_text(out, text, limit)?;
    } else {
        out.push(0);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::v10_proofs::report_objects::tests::object;

    #[test]
    fn approved_sigma_proof_bodies_round_trip() {
        let pack = object("sigma_pack_manifest");
        assert_eq!(
            SigmaPackManifestV1::decode(&pack)
                .unwrap()
                .encode()
                .unwrap(),
            pack
        );
        assert!(SigmaPackManifestV1::decode(&object("reject_body_trailing_byte")).is_err());
        let table = object("sigma_field_table");
        assert_eq!(
            SigmaFieldTableV1::decode(&table).unwrap().encode().unwrap(),
            table
        );
        let scope = object("sigma_source_scope");
        assert_eq!(
            SigmaSourceScopeV1::decode(&scope)
                .unwrap()
                .encode()
                .unwrap(),
            scope
        );
        let compiled = object("sigma_compiled_rules");
        assert_eq!(
            SigmaCompiledRulesV1::decode(&compiled)
                .unwrap()
                .encode()
                .unwrap(),
            compiled
        );
        let results = object("sigma_results");
        assert_eq!(
            SigmaRunResultsV1::decode(&results)
                .unwrap()
                .encode()
                .unwrap(),
            results
        );
    }
}
