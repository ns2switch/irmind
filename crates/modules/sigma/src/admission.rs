use saphyr_parser::{Event, Parser, ScalarStyle};
use std::{collections::BTreeMap, fmt};

const MAX_BYTES: usize = 64 * 1024;
const MAX_EVENTS: usize = 4_096;
const MAX_DEPTH: usize = 24;
const MAX_SCALAR_BYTES: usize = 32 * 1024;
const MAX_KEY_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Decimal(String),
    Text(String),
    Sequence(Vec<Self>),
    Mapping(BTreeMap<String, Self>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleDocument {
    root: BTreeMap<String, RuleValue>,
}

impl RuleDocument {
    pub fn fields(&self) -> &BTreeMap<String, RuleValue> {
        &self.root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    ByteLimit,
    InvalidUtf8,
    Bom,
    Directive,
    Document,
    Syntax,
    Anchor,
    Alias,
    Tag,
    Merge,
    Key,
    DuplicateKey,
    Scalar,
    StructureLimit,
    RuleShape,
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::ByteLimit => "Sigma rule exceeds 64 KiB",
            Self::InvalidUtf8 => "Sigma rule requires well-formed UTF-8",
            Self::Bom => "Sigma rule contains a byte-order marker",
            Self::Directive => "Sigma rule contains a YAML directive",
            Self::Document => "Sigma rule requires exactly one YAML document",
            Self::Syntax => "Sigma rule has invalid YAML syntax",
            Self::Anchor => "Sigma rule contains a YAML anchor",
            Self::Alias => "Sigma rule contains a YAML alias",
            Self::Tag => "Sigma rule contains an explicit YAML tag",
            Self::Merge => "Sigma rule contains a YAML merge key",
            Self::Key => "Sigma mapping keys require bounded nonempty text",
            Self::DuplicateKey => "Sigma rule contains a duplicate mapping key",
            Self::Scalar => "Sigma rule has a scalar outside the supported bounds",
            Self::StructureLimit => "Sigma rule exceeds its YAML depth or event limit",
            Self::RuleShape => {
                "Sigma rule requires a title, logsource and named detection condition"
            }
        })
    }
}

impl std::error::Error for AdmissionError {}

pub fn admit_rule(bytes: &[u8]) -> Result<RuleDocument, AdmissionError> {
    if bytes.len() > MAX_BYTES {
        return Err(AdmissionError::ByteLimit);
    }
    let input = std::str::from_utf8(bytes).map_err(|_| AdmissionError::InvalidUtf8)?;
    if input.contains('\u{feff}') {
        return Err(AdmissionError::Bom);
    }
    if input.split(['\r', '\n']).any(|line| line.starts_with('%')) {
        return Err(AdmissionError::Directive);
    }
    let mut document = Document::default();
    for (index, event) in Parser::new_from_str(input).enumerate() {
        if index == MAX_EVENTS {
            return Err(AdmissionError::StructureLimit);
        }
        let (event, _) = event.map_err(|_| AdmissionError::Syntax)?;
        if event == Event::StreamEnd {
            return document.finish();
        }
        document.accept(event)?;
    }
    Err(AdmissionError::Document)
}

#[derive(Default)]
struct Document {
    stack: Vec<Frame>,
    root: Option<RuleValue>,
    started: bool,
    ended: bool,
}

enum Frame {
    Sequence(Vec<RuleValue>),
    Mapping {
        values: BTreeMap<String, RuleValue>,
        key: Option<String>,
    },
}

impl Document {
    fn accept(&mut self, event: Event<'_>) -> Result<(), AdmissionError> {
        match event {
            Event::StreamStart => Ok(()),
            Event::DocumentStart(_) if !self.started => {
                self.started = true;
                Ok(())
            }
            Event::DocumentEnd if self.started && !self.ended && self.stack.is_empty() => {
                self.ended = true;
                Ok(())
            }
            Event::DocumentStart(_) | Event::DocumentEnd | Event::StreamEnd => {
                Err(AdmissionError::Document)
            }
            Event::Alias(_) => Err(AdmissionError::Alias),
            Event::Scalar(value, style, anchor, tag) => {
                check_node(anchor, tag.is_some())?;
                self.push(parse_scalar(&value, style)?)
            }
            Event::SequenceStart(anchor, tag) => {
                check_node(anchor, tag.is_some())?;
                self.open(Frame::Sequence(Vec::new()))
            }
            Event::MappingStart(anchor, tag) => {
                check_node(anchor, tag.is_some())?;
                self.open(Frame::Mapping {
                    values: BTreeMap::new(),
                    key: None,
                })
            }
            Event::MappingEnd => match self.stack.pop() {
                Some(Frame::Mapping { values, key: None }) => self.push(RuleValue::Mapping(values)),
                _ => Err(AdmissionError::Syntax),
            },
            Event::SequenceEnd => match self.stack.pop() {
                Some(Frame::Sequence(values)) => self.push(RuleValue::Sequence(values)),
                _ => Err(AdmissionError::Syntax),
            },
            Event::Nothing => Err(AdmissionError::Syntax),
        }
    }

    fn open(&mut self, frame: Frame) -> Result<(), AdmissionError> {
        if !self.started || self.ended {
            return Err(AdmissionError::Document);
        }
        if self.stack.len() == MAX_DEPTH {
            return Err(AdmissionError::StructureLimit);
        }
        if matches!(self.stack.last(), Some(Frame::Mapping { key: None, .. })) {
            return Err(AdmissionError::Key);
        }
        self.stack.push(frame);
        Ok(())
    }

    fn push(&mut self, value: RuleValue) -> Result<(), AdmissionError> {
        if !self.started || self.ended {
            return Err(AdmissionError::Document);
        }
        match self.stack.last_mut() {
            Some(Frame::Mapping { values, key }) => {
                if let Some(name) = key.take() {
                    values.insert(name, value);
                    return Ok(());
                }
                let RuleValue::Text(name) = value else {
                    return Err(AdmissionError::Key);
                };
                if name == "<<" {
                    return Err(AdmissionError::Merge);
                }
                if name.is_empty()
                    || name.len() > MAX_KEY_BYTES
                    || name.chars().any(char::is_control)
                {
                    return Err(AdmissionError::Key);
                }
                if values.contains_key(&name) {
                    return Err(AdmissionError::DuplicateKey);
                }
                *key = Some(name);
            }
            Some(Frame::Sequence(values)) => values.push(value),
            None if self.root.is_none() => self.root = Some(value),
            None => return Err(AdmissionError::Document),
        }
        Ok(())
    }

    fn finish(self) -> Result<RuleDocument, AdmissionError> {
        if !self.ended || !self.stack.is_empty() {
            return Err(AdmissionError::Document);
        }
        let Some(RuleValue::Mapping(root)) = self.root else {
            return Err(AdmissionError::RuleShape);
        };
        validate_shape(&root)?;
        Ok(RuleDocument { root })
    }
}

fn validate_shape(root: &BTreeMap<String, RuleValue>) -> Result<(), AdmissionError> {
    let Some(RuleValue::Text(title)) = root.get("title") else {
        return Err(AdmissionError::RuleShape);
    };
    let Some(RuleValue::Mapping(logsource)) = root.get("logsource") else {
        return Err(AdmissionError::RuleShape);
    };
    let Some(RuleValue::Mapping(detection)) = root.get("detection") else {
        return Err(AdmissionError::RuleShape);
    };
    let valid_condition = match detection.get("condition") {
        Some(RuleValue::Text(condition)) => !condition.trim().is_empty(),
        Some(RuleValue::Sequence(conditions)) => {
            !conditions.is_empty() && conditions.len() <= 64 && conditions.iter().all(|value| {
                matches!(value, RuleValue::Text(expression) if !expression.trim().is_empty())
            })
        }
        _ => false,
    };
    if title.trim().is_empty()
        || !valid_condition
        || detection.len() < 2
        || logsource.is_empty()
        || logsource.iter().any(|(key, value)| {
            !matches!(
                key.as_str(),
                "product" | "service" | "category" | "definition"
            ) || !matches!(value, RuleValue::Text(text) if !text.trim().is_empty())
        })
        || !["product", "service", "category"]
            .iter()
            .any(|key| logsource.contains_key(*key))
        || root.contains_key("correlation")
        || root.contains_key("filter")
    {
        return Err(AdmissionError::RuleShape);
    }
    Ok(())
}

fn check_node(anchor: usize, tagged: bool) -> Result<(), AdmissionError> {
    if anchor != 0 {
        return Err(AdmissionError::Anchor);
    }
    if tagged {
        return Err(AdmissionError::Tag);
    }
    Ok(())
}

fn parse_scalar(value: &str, style: ScalarStyle) -> Result<RuleValue, AdmissionError> {
    if value.len() > MAX_SCALAR_BYTES {
        return Err(AdmissionError::Scalar);
    }
    if style != ScalarStyle::Plain {
        return Ok(RuleValue::Text(value.to_owned()));
    }
    match value {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(RuleValue::Null),
        "true" | "True" | "TRUE" => return Ok(RuleValue::Boolean(true)),
        "false" | "False" | "FALSE" => return Ok(RuleValue::Boolean(false)),
        ".nan" | ".NaN" | ".NAN" | ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF"
        | "-.inf" | "-.Inf" | "-.INF" => return Err(AdmissionError::Scalar),
        _ => {}
    }
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return value
            .parse()
            .map(RuleValue::Integer)
            .map_err(|_| AdmissionError::Scalar);
    }
    if let Some(number) = radix_integer(value) {
        return number
            .map(RuleValue::Integer)
            .map_err(|_| AdmissionError::Scalar);
    }
    if digits
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit() || byte == b'.')
        && let Ok(number) = value.parse::<f64>()
    {
        return if number.is_finite() {
            Ok(RuleValue::Decimal(value.to_owned()))
        } else {
            Err(AdmissionError::Scalar)
        };
    }
    Ok(RuleValue::Text(value.to_owned()))
}

fn radix_integer(value: &str) -> Option<Result<i64, std::num::ParseIntError>> {
    let (digits, base) = value
        .strip_prefix("0x")
        .filter(|s| !s.is_empty() && s.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|s| (s, 16))
        .or_else(|| {
            value
                .strip_prefix("0o")
                .filter(|s| !s.is_empty() && s.bytes().all(|byte| matches!(byte, b'0'..=b'7')))
                .map(|s| (s, 8))
        })?;
    Some(i64::from_str_radix(digits, base))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
