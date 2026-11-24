//! Pure typed Sigma predicates. The caller supplies authenticated fields for one enrolled variant.
use crate::{
    RuleDocument, RuleValue,
    condition::{Condition, ConditionError},
};
use regex::{Regex, RegexBuilder};
use std::{collections::BTreeMap, net::IpAddr};

const MAX_ALTERNATIVES: usize = 256;
const MAX_PATTERN: usize = 4096;
const MAX_SUBJECT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigmaFieldKind {
    Text,
    Integer,
    Boolean,
    Ip,
    TextList,
    IntegerList,
    IpList,
}

#[derive(Clone, Copy, Debug)]
pub enum SigmaScalar<'a> {
    Null,
    Text(&'a str),
    Integer(i64),
    Boolean(bool),
    Ip(IpAddr),
}

#[derive(Clone, Copy)]
pub enum SigmaField<'a> {
    Absent,
    Single(SigmaScalar<'a>),
    List(&'a [SigmaScalar<'a>]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompileError {
    Condition(ConditionError),
    MissingBinding,
    InvalidSelection,
    UnsupportedModifier,
    WrongType,
    Pattern,
    Limit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationError {
    WorkLimit,
    OversizedInput,
    FieldTypeMismatch,
}

pub struct SigmaProgram {
    condition: Condition,
    selections: Vec<Vec<Vec<FieldTest>>>,
}

struct FieldTest {
    name: String,
    kind: SigmaFieldKind,
    predicates: Vec<Predicate>,
    all: bool,
}

enum Predicate {
    Exists(bool),
    Null,
    Boolean(bool),
    Integer(IntegerComparison, i64),
    Pattern(Regex, u64),
    Network(Network),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntegerComparison {
    Equal,
    NotEqual,
    Lt,
    Le,
    Gt,
    Ge,
}

impl SigmaProgram {
    pub fn compile(
        rule: &RuleDocument,
        bindings: &BTreeMap<String, SigmaFieldKind>,
    ) -> Result<Self, CompileError> {
        let Some(RuleValue::Mapping(detection)) = rule.fields().get("detection") else {
            return Err(CompileError::InvalidSelection);
        };
        let mut remaining = MAX_ALTERNATIVES;
        let mut names = Vec::new();
        let mut selections = Vec::new();
        for (name, value) in detection {
            if name == "condition" {
                continue;
            }
            let maps = match value {
                RuleValue::Mapping(_) => std::slice::from_ref(value),
                RuleValue::Sequence(maps) if !maps.is_empty() => maps.as_slice(),
                _ => return Err(CompileError::InvalidSelection),
            };
            let mut group = Vec::with_capacity(maps.len());
            for map in maps {
                let RuleValue::Mapping(fields) = map else {
                    return Err(CompileError::InvalidSelection);
                };
                if fields.is_empty() {
                    return Err(CompileError::InvalidSelection);
                }
                let tests = fields
                    .iter()
                    .map(|(name, value)| compile_test(name, value, bindings, &mut remaining))
                    .collect::<Result<Vec<_>, _>>()?;
                group.push(tests);
            }
            names.push(name.as_str());
            selections.push(group);
        }
        let expressions = match detection.get("condition") {
            Some(RuleValue::Text(expression)) => vec![expression.as_str()],
            Some(RuleValue::Sequence(items)) => items
                .iter()
                .map(|value| match value {
                    RuleValue::Text(text) => Ok(text.as_str()),
                    _ => Err(CompileError::InvalidSelection),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(CompileError::InvalidSelection),
        };
        let condition = Condition::compile(expressions, &names).map_err(CompileError::Condition)?;
        Ok(Self {
            condition,
            selections,
        })
    }

    /// Charge a rule-wide mutable counter supplied by the caller. Return failures
    /// as errors so boolean negation cannot turn failures into matches.
    pub fn evaluate<'a>(
        &self,
        mut field: impl FnMut(&str) -> Result<SigmaField<'a>, EvaluationError>,
        units_remaining: &mut u64,
    ) -> Result<bool, EvaluationError> {
        charge(units_remaining, 1)?;
        self.condition.evaluate(&mut |index| {
            for group in &self.selections[index] {
                let mut matched = true;
                for test in group {
                    charge(units_remaining, 1)?;
                    let value = field(&test.name)?;
                    if !test.evaluate(&value, units_remaining)? {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

impl FieldTest {
    fn evaluate(&self, field: &SigmaField<'_>, units: &mut u64) -> Result<bool, EvaluationError> {
        match field {
            SigmaField::Absent | SigmaField::Single(SigmaScalar::Null) => {}
            SigmaField::Single(value) if value_matches(self.kind, *value, false) => {}
            SigmaField::List(values) if values.len() <= 1024 && is_list(self.kind) => {
                charge(units, values.len() as u64)?;
                if values
                    .iter()
                    .any(|value| !value_matches(self.kind, *value, true))
                {
                    return Err(EvaluationError::FieldTypeMismatch);
                }
            }
            SigmaField::List(values) if values.len() > 1024 => {
                return Err(EvaluationError::OversizedInput);
            }
            _ => return Err(EvaluationError::FieldTypeMismatch),
        }
        for predicate in &self.predicates {
            let matched = predicate.evaluate(field, units)?;
            if matched != self.all {
                return Ok(matched);
            }
        }
        Ok(self.all)
    }
}

impl Predicate {
    fn evaluate(&self, field: &SigmaField<'_>, units: &mut u64) -> Result<bool, EvaluationError> {
        if let Self::Exists(expected) = self {
            return Ok(*expected != matches!(field, SigmaField::Absent));
        }
        match field {
            SigmaField::Absent => Ok(false),
            SigmaField::Single(value) => self.scalar(*value, units),
            SigmaField::List(values) => {
                for value in *values {
                    if self.scalar(*value, units)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn scalar(&self, value: SigmaScalar<'_>, units: &mut u64) -> Result<bool, EvaluationError> {
        charge(units, 1)?;
        Ok(match (self, value) {
            (Self::Null, SigmaScalar::Null) => true,
            (Self::Boolean(expected), SigmaScalar::Boolean(actual)) => *expected == actual,
            (Self::Integer(comparison, expected), SigmaScalar::Integer(actual)) => match comparison
            {
                IntegerComparison::Equal => actual == *expected,
                IntegerComparison::NotEqual => actual != *expected,
                IntegerComparison::Lt => actual < *expected,
                IntegerComparison::Le => actual <= *expected,
                IntegerComparison::Gt => actual > *expected,
                IntegerComparison::Ge => actual >= *expected,
            },
            (Self::Pattern(pattern, complexity), SigmaScalar::Text(text)) => {
                if text.len() > MAX_SUBJECT {
                    return Err(EvaluationError::OversizedInput);
                }
                charge(units, (text.len() as u64 + 1) * complexity)?;
                pattern.is_match(text)
            }
            (Self::Network(network), SigmaScalar::Ip(address)) => network.contains(address),
            _ => false,
        })
    }
}

fn charge(units: &mut u64, cost: u64) -> Result<(), EvaluationError> {
    *units = units.checked_sub(cost).ok_or(EvaluationError::WorkLimit)?;
    Ok(())
}

fn is_list(kind: SigmaFieldKind) -> bool {
    matches!(
        kind,
        SigmaFieldKind::TextList | SigmaFieldKind::IntegerList | SigmaFieldKind::IpList
    )
}

fn value_matches(kind: SigmaFieldKind, value: SigmaScalar<'_>, list: bool) -> bool {
    matches!(
        (kind, value, list),
        (_, SigmaScalar::Null, _)
            | (SigmaFieldKind::Text, SigmaScalar::Text(_), false)
            | (SigmaFieldKind::TextList, SigmaScalar::Text(_), true)
            | (SigmaFieldKind::Integer, SigmaScalar::Integer(_), false)
            | (SigmaFieldKind::IntegerList, SigmaScalar::Integer(_), true)
            | (SigmaFieldKind::Boolean, SigmaScalar::Boolean(_), false)
            | (SigmaFieldKind::Ip, SigmaScalar::Ip(_), false)
            | (SigmaFieldKind::IpList, SigmaScalar::Ip(_), true)
    )
}

fn compile_test(
    key: &str,
    value: &RuleValue,
    bindings: &BTreeMap<String, SigmaFieldKind>,
    remaining: &mut usize,
) -> Result<FieldTest, CompileError> {
    let mut parts = key.split('|');
    let name = parts.next().ok_or(CompileError::MissingBinding)?;
    let kind = *bindings.get(name).ok_or(CompileError::MissingBinding)?;
    let modifiers = parts.collect::<Vec<_>>();
    let values = match value {
        RuleValue::Sequence(values) if !values.is_empty() => values.as_slice(),
        RuleValue::Sequence(_) => return Err(CompileError::InvalidSelection),
        _ => std::slice::from_ref(value),
    };
    let all = modifiers.contains(&"all");
    if modifiers.iter().filter(|part| **part == "all").count() > 1 || (all && values.len() < 2) {
        return Err(CompileError::UnsupportedModifier);
    }
    let modifiers = modifiers
        .iter()
        .copied()
        .filter(|part| *part != "all")
        .collect::<Vec<_>>();
    if modifiers.len() > 8
        || modifiers
            .iter()
            .enumerate()
            .any(|(index, item)| modifiers[..index].contains(item))
    {
        return Err(CompileError::UnsupportedModifier);
    }
    let mut predicates = Vec::with_capacity(values.len());
    for value in values {
        let expansion = expansion_count(value, &modifiers)?;
        *remaining = remaining
            .checked_sub(expansion)
            .ok_or(CompileError::Limit)?;
        predicates.push(compile_predicate(kind, value, &modifiers)?);
    }
    Ok(FieldTest {
        name: name.into(),
        kind,
        predicates,
        all,
    })
}

fn expansion_count(value: &RuleValue, modifiers: &[&str]) -> Result<usize, CompileError> {
    let mut count = if modifiers.contains(&"base64offset") {
        3usize
    } else {
        1
    };
    if let RuleValue::Text(text) = value
        && modifiers.contains(&"windash")
    {
        for ch in text.chars() {
            if matches!(ch, '-' | '/' | '–' | '—' | '―') {
                count = count
                    .checked_mul(5)
                    .filter(|count| *count <= MAX_ALTERNATIVES)
                    .ok_or(CompileError::Limit)?;
            }
        }
    }
    Ok(count)
}

fn compile_predicate(
    kind: SigmaFieldKind,
    value: &RuleValue,
    modifiers: &[&str],
) -> Result<Predicate, CompileError> {
    match (value, modifiers) {
        (RuleValue::Boolean(flag), ["exists"]) => Ok(Predicate::Exists(*flag)),
        (RuleValue::Null, []) => Ok(Predicate::Null),
        (RuleValue::Boolean(flag), []) if kind == SigmaFieldKind::Boolean => {
            Ok(Predicate::Boolean(*flag))
        }
        (RuleValue::Integer(number), _)
            if matches!(kind, SigmaFieldKind::Integer | SigmaFieldKind::IntegerList) =>
        {
            let comparison = match modifiers {
                [] => IntegerComparison::Equal,
                ["neq"] => IntegerComparison::NotEqual,
                ["lt"] => IntegerComparison::Lt,
                ["lte"] => IntegerComparison::Le,
                ["gt"] => IntegerComparison::Gt,
                ["gte"] => IntegerComparison::Ge,
                _ => return Err(CompileError::UnsupportedModifier),
            };
            Ok(Predicate::Integer(comparison, *number))
        }
        (RuleValue::Text(value), [] | ["cidr"])
            if matches!(kind, SigmaFieldKind::Ip | SigmaFieldKind::IpList) =>
        {
            Network::parse(value, !modifiers.is_empty()).map(Predicate::Network)
        }
        (RuleValue::Text(text), _)
            if matches!(kind, SigmaFieldKind::Text | SigmaFieldKind::TextList) =>
        {
            compile_text(text, modifiers)
        }
        _ => Err(CompileError::WrongType),
    }
}

fn compile_text(text: &str, modifiers: &[&str]) -> Result<Predicate, CompileError> {
    if text.len() > MAX_PATTERN {
        return Err(CompileError::Limit);
    }
    if let ["re", flags @ ..] = modifiers {
        if flags.iter().any(|flag| !matches!(*flag, "i" | "m" | "s")) {
            return Err(CompileError::UnsupportedModifier);
        }
        // Reject backend-dependent special groups and escapes outside the Sigma subset.
        if text.contains("(?") || text.contains("(*") {
            return Err(CompileError::Pattern);
        }
        return build_regex(
            text,
            flags.contains(&"i"),
            flags.contains(&"m"),
            flags.contains(&"s"),
        );
    }
    if let [encoder @ ("base64" | "base64offset"), tail @ ..] = modifiers {
        return compile_base64(text, encoder, tail);
    }
    let mut left = true;
    let mut right = true;
    let mut cased = false;
    let mut windash = false;
    let mut positioning = false;
    for modifier in modifiers {
        match *modifier {
            "cased" => cased = true,
            "windash" if !positioning => windash = true,
            "contains" | "startswith" | "endswith" if !positioning => {
                left = *modifier == "startswith";
                right = *modifier == "endswith";
                positioning = true;
            }
            _ => return Err(CompileError::UnsupportedModifier),
        }
    }
    let mut pattern = if left {
        String::from("\\A")
    } else {
        String::new()
    };
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if chars
                .peek()
                .is_some_and(|ch| matches!(ch, '\\' | '*' | '?')) =>
            {
                if let Some(ch) = chars.next() {
                    escape_literal(&mut pattern, ch);
                }
            }
            '*' => pattern.push_str(".*"),
            '?' => pattern.push('.'),
            '-' | '/' | '–' | '—' | '―' if windash => pattern.push_str("[-/–—―]"),
            literal => escape_literal(&mut pattern, literal),
        }
    }
    if right {
        pattern.push_str("\\z");
    }
    build_regex(&pattern, !cased, false, true)
}

fn compile_base64(
    text: &str,
    encoder: &str,
    modifiers: &[&str],
) -> Result<Predicate, CompileError> {
    if text.is_empty() || text.contains(['*', '?']) {
        return Err(CompileError::Pattern);
    }
    let (left, right) = match modifiers {
        [] => (true, true),
        ["contains"] => (false, false),
        ["startswith"] => (true, false),
        ["endswith"] => (false, true),
        _ => return Err(CompileError::UnsupportedModifier),
    };
    let alternatives = if encoder == "base64offset" {
        if text.len() < 3 {
            return Err(CompileError::Pattern);
        }
        (0..3)
            .map(|offset| {
                let prefixed = [vec![0u8; offset], text.as_bytes().to_vec()].concat();
                let rendered = base64(&prefixed);
                let start = (offset * 8).div_ceil(6);
                let end = prefixed.len() * 8 / 6;
                regex::escape(&rendered[start..end])
            })
            .collect::<Vec<_>>()
    } else {
        vec![regex::escape(&base64(text.as_bytes()))]
    };
    let pattern = format!(
        "{}(?:{}){}",
        if left { "\\A" } else { "" },
        alternatives.join("|"),
        if right { "\\z" } else { "" },
    );
    build_regex(&pattern, false, false, true)
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(input.len().div_ceil(3) * 4);
    for bytes in input.chunks(3) {
        let first = bytes[0];
        let second = bytes.get(1).copied().unwrap_or_default();
        let third = bytes.get(2).copied().unwrap_or_default();
        encoded.push(TABLE[usize::from(first >> 2)].into());
        encoded.push(TABLE[usize::from(((first & 3) << 4) | (second >> 4))].into());
        if bytes.len() >= 2 {
            encoded.push(TABLE[usize::from(((second & 15) << 2) | (third >> 6))].into());
        } else {
            encoded.push('=');
        }
        if bytes.len() == 3 {
            encoded.push(TABLE[usize::from(third & 63)].into());
        } else {
            encoded.push('=');
        }
    }
    encoded
}

fn build_regex(
    pattern: &str,
    insensitive: bool,
    multiline: bool,
    dot_newline: bool,
) -> Result<Predicate, CompileError> {
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(insensitive)
        .multi_line(multiline)
        .dot_matches_new_line(dot_newline)
        .size_limit(64 * 1024)
        .dfa_size_limit(64 * 1024)
        .nest_limit(24)
        .build()
        .map_err(|_| CompileError::Pattern)?;
    Ok(Predicate::Pattern(regex, pattern.len().max(1) as u64))
}

fn escape_literal(pattern: &mut String, ch: char) {
    if matches!(
        ch,
        '\\' | '.'
            | '+'
            | '*'
            | '?'
            | '('
            | ')'
            | '|'
            | '['
            | ']'
            | '{'
            | '}'
            | '^'
            | '$'
            | '#'
            | '&'
            | '-'
            | '~'
    ) {
        pattern.push('\\');
    }
    pattern.push(ch);
}

struct Network {
    base: IpAddr,
    length: u32,
}

impl Network {
    fn parse(value: &str, cidr: bool) -> Result<Self, CompileError> {
        let (base, length) = if cidr {
            let (address, length) = value.split_once('/').ok_or(CompileError::Pattern)?;
            (
                address
                    .parse::<IpAddr>()
                    .map_err(|_| CompileError::Pattern)?,
                Some(length.parse::<u32>().map_err(|_| CompileError::Pattern)?),
            )
        } else {
            (value.parse().map_err(|_| CompileError::Pattern)?, None)
        };
        let max = if base.is_ipv4() { 32 } else { 128 };
        let length = length.unwrap_or(max);
        if length > max {
            return Err(CompileError::Pattern);
        }
        Ok(Self { base, length })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.base, address, self.length) {
            (IpAddr::V4(_), IpAddr::V4(_), 0) | (IpAddr::V6(_), IpAddr::V6(_), 0) => true,
            (IpAddr::V4(base), IpAddr::V4(address), length) => {
                u32::from(base) >> (32 - length) == u32::from(address) >> (32 - length)
            }
            (IpAddr::V6(base), IpAddr::V6(address), length) => {
                u128::from(base) >> (128 - length) == u128::from(address) >> (128 - length)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::admit_rule;

    fn document(detection: &str) -> RuleDocument {
        let rule =
            format!("title: Synthetic\nlogsource: {{product: fixture}}\ndetection:\n{detection}");
        admit_rule(rule.as_bytes()).unwrap()
    }

    fn program(kind: SigmaFieldKind, selection: &str) -> Result<SigmaProgram, CompileError> {
        SigmaProgram::compile(
            &document(&format!("  selection: {selection}\n  condition: selection")),
            &BTreeMap::from([("value".into(), kind)]),
        )
    }

    fn evaluate(program: &SigmaProgram, event: SigmaField<'_>) -> Result<bool, EvaluationError> {
        program.evaluate(|_| Ok(event), &mut 1_000_000)
    }

    #[test]
    fn common_predicates_match_typed_fields_without_coercion() {
        let text = program(SigmaFieldKind::Text, r"{value|contains|all: ['a\*', 'bb']}").unwrap();
        assert_eq!(
            evaluate(&text, SigmaField::Single(SigmaScalar::Text("A* + BB"))),
            Ok(true)
        );
        assert_eq!(
            evaluate(&text, SigmaField::Single(SigmaScalar::Text("A! + BB"))),
            Ok(false)
        );
        assert!(matches!(
            program(SigmaFieldKind::Integer, "{value: '3'}"),
            Err(CompileError::WrongType)
        ));
        let network = program(SigmaFieldKind::IpList, "{value|cidr: '2001:db8::/32'}").unwrap();
        let ips = [
            SigmaScalar::Ip("192.0.2.1".parse().unwrap()),
            SigmaScalar::Ip("2001:db8:1::f".parse().unwrap()),
        ];
        assert_eq!(evaluate(&network, SigmaField::List(&ips)), Ok(true));
        assert!(program(SigmaFieldKind::Ip, "{value|cidr: '192.0.2.1/33'}").is_err());
    }

    #[test]
    fn presence_distinguishes_null_missing_and_empty_values() {
        let exists = program(SigmaFieldKind::Text, "{value|exists: true}").unwrap();
        assert_eq!(evaluate(&exists, SigmaField::Absent), Ok(false));
        assert_eq!(
            evaluate(&exists, SigmaField::Single(SigmaScalar::Null)),
            Ok(true)
        );
        assert_eq!(
            evaluate(&exists, SigmaField::Single(SigmaScalar::Text(""))),
            Ok(true)
        );
        let null = program(SigmaFieldKind::Text, "{value: null}").unwrap();
        assert_eq!(evaluate(&null, SigmaField::Absent), Ok(false));
        assert_eq!(
            evaluate(&null, SigmaField::Single(SigmaScalar::Null)),
            Ok(true)
        );
    }

    #[test]
    fn rejects_missing_bindings_and_unknown_modifiers_before_evaluation() {
        let absent = program(SigmaFieldKind::Text, "{unknown|contains: sample}");
        assert!(matches!(absent, Err(CompileError::MissingBinding)));
        let unsupported = program(SigmaFieldKind::Text, "{value|expand: sample}");
        assert!(matches!(
            unsupported,
            Err(CompileError::UnsupportedModifier)
        ));
        let unsupported = program(SigmaFieldKind::Text, "{value|re: '(?=x)'}");
        assert!(matches!(unsupported, Err(CompileError::Pattern)));
        let unsupported = program(SigmaFieldKind::Text, "{value|windash: '----'}");
        assert!(matches!(unsupported, Err(CompileError::Limit)));
    }

    #[test]
    fn case_sensitive_encoded_matching_and_windash() {
        let encoded = program(SigmaFieldKind::Text, "{value|base64: 'abc'}").unwrap();
        assert_eq!(
            evaluate(&encoded, SigmaField::Single(SigmaScalar::Text("YWJj"))),
            Ok(true)
        );
        assert_eq!(
            evaluate(&encoded, SigmaField::Single(SigmaScalar::Text("yWJj"))),
            Ok(false)
        );
        let encoded =
            program(SigmaFieldKind::Text, "{value|base64offset|contains: 'abc'}").unwrap();
        for candidate in ["YWJj", "YWFieGNk", "emFiY2Y=", "enphYmNm"] {
            // The second fixture contains an unrelated sequence.
            assert_eq!(
                evaluate(&encoded, SigmaField::Single(SigmaScalar::Text(candidate))),
                Ok(candidate != "YWFieGNk")
            );
        }
        let flags = program(SigmaFieldKind::Text, "{value|windash|contains: '-mode'}").unwrap();
        for flag in ["-mode", "/MODE", "―mode"] {
            assert_eq!(
                evaluate(&flags, SigmaField::Single(SigmaScalar::Text(flag))),
                Ok(true)
            );
        }
    }

    #[test]
    fn read_failures_do_not_turn_into_matches_under_negation() {
        let rule = document(
            "  selection: {value|contains: demo}\n  condition: [not selection, selection]",
        );
        let program = SigmaProgram::compile(
            &rule,
            &BTreeMap::from([("value".into(), SigmaFieldKind::Text)]),
        )
        .unwrap();
        assert_eq!(
            program.evaluate(
                |_| Ok(SigmaField::Single(SigmaScalar::Text("demo"))),
                &mut 0
            ),
            Err(EvaluationError::WorkLimit)
        );
        assert_eq!(
            program.evaluate(
                |_| Ok(SigmaField::Single(SigmaScalar::Integer(7))),
                &mut 100
            ),
            Err(EvaluationError::FieldTypeMismatch)
        );
        let oversized = "a".repeat(MAX_SUBJECT + 1);
        assert_eq!(
            evaluate(&program, SigmaField::Single(SigmaScalar::Text(&oversized))),
            Err(EvaluationError::OversizedInput)
        );
    }
}
