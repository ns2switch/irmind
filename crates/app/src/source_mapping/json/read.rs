use super::{SourceJsonLimits, SourceRecordError, SourceValue};
use crate::source_mapping::SourceNumber;
use std::collections::BTreeMap;

pub(super) fn decode(
    input: &[u8],
    limits: SourceJsonLimits,
) -> Result<SourceValue, SourceRecordError> {
    let value = parse(input, limits)?;
    if !matches!(value, SourceValue::Object(_)) {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn parse(
    input: &[u8],
    limits: SourceJsonLimits,
) -> Result<SourceValue, SourceRecordError> {
    if input.len() > limits.bytes {
        return Err(SourceRecordError::Limit);
    }
    let mut parser = Parser {
        input,
        cursor: 0,
        limits,
        nodes: 0,
        fields: 0,
    };
    let result = parser.value(0)?;
    parser.whitespace();
    if parser.cursor != input.len() {
        return Err(invalid());
    }
    Ok(result)
}

struct Parser<'a> {
    input: &'a [u8],
    cursor: usize,
    limits: SourceJsonLimits,
    nodes: usize,
    fields: usize,
}
impl Parser<'_> {
    fn whitespace(&mut self) {
        while matches!(
            self.input.get(self.cursor),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.cursor += 1;
        }
    }
    fn byte(&mut self) -> Result<u8, SourceRecordError> {
        let value = *self.input.get(self.cursor).ok_or_else(invalid)?;
        self.cursor += 1;
        Ok(value)
    }
    fn expect(&mut self, expected: u8) -> Result<(), SourceRecordError> {
        self.whitespace();
        if self.byte()? != expected {
            return Err(invalid());
        }
        Ok(())
    }
    fn value(&mut self, depth: usize) -> Result<SourceValue, SourceRecordError> {
        self.whitespace();
        self.nodes += 1;
        if self.nodes > self.limits.nodes || depth > self.limits.depth {
            return Err(SourceRecordError::Limit);
        }
        match self.input.get(self.cursor) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(SourceValue::Text),
            Some(b't') => self.literal(b"true", SourceValue::Boolean(true)),
            Some(b'f') => self.literal(b"false", SourceValue::Boolean(false)),
            Some(b'n') => self.literal(b"null", SourceValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(invalid()),
        }
    }
    fn object(&mut self, depth: usize) -> Result<SourceValue, SourceRecordError> {
        self.expect(b'{')?;
        self.whitespace();
        let mut fields = BTreeMap::new();
        if self.input.get(self.cursor) != Some(&b'}') {
            loop {
                self.fields += 1;
                if self.fields > self.limits.fields {
                    return Err(SourceRecordError::Limit);
                }
                let name = self.string()?;
                if name.is_empty() || name.len() > 256 {
                    return Err(SourceRecordError::InvalidPath);
                }
                self.expect(b':')?;
                let value = self.value(depth + 1)?;
                if fields.insert(name, value).is_some() {
                    return Err(SourceRecordError::DuplicateField);
                }
                self.whitespace();
                if self.input.get(self.cursor) != Some(&b',') {
                    break;
                }
                self.cursor += 1;
            }
        }
        self.expect(b'}')?;
        Ok(SourceValue::Object(fields))
    }
    fn array(&mut self, depth: usize) -> Result<SourceValue, SourceRecordError> {
        self.expect(b'[')?;
        self.whitespace();
        let mut values = Vec::new();
        if self.input.get(self.cursor) != Some(&b']') {
            loop {
                values.push(self.value(depth + 1)?);
                self.whitespace();
                if self.input.get(self.cursor) != Some(&b',') {
                    break;
                }
                self.cursor += 1;
            }
        }
        self.expect(b']')?;
        Ok(SourceValue::Array(values))
    }
    fn string(&mut self) -> Result<String, SourceRecordError> {
        self.whitespace();
        let start = self.cursor;
        if self.byte()? != b'"' {
            return Err(invalid());
        }
        let mut escaped = false;
        loop {
            match self.byte()? {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => break,
                _ => {}
            }
        }
        serde_json::from_slice(&self.input[start..self.cursor]).map_err(|_| invalid())
    }
    fn number(&mut self) -> Result<SourceValue, SourceRecordError> {
        let start = self.cursor;
        while self
            .input
            .get(self.cursor)
            .is_some_and(|b| b.is_ascii_digit() || b"-.eE+".contains(b))
        {
            self.cursor += 1;
            if self.cursor - start > 128 {
                return Err(SourceRecordError::Limit);
            }
        }
        let value = std::str::from_utf8(&self.input[start..self.cursor]).map_err(|_| invalid())?;
        SourceNumber::try_new(value).map(SourceValue::Number)
    }
    fn literal(
        &mut self,
        literal: &[u8],
        value: SourceValue,
    ) -> Result<SourceValue, SourceRecordError> {
        if self.input.get(self.cursor..self.cursor + literal.len()) != Some(literal) {
            return Err(invalid());
        }
        self.cursor += literal.len();
        Ok(value)
    }
}
fn invalid() -> SourceRecordError {
    SourceRecordError::InvalidEncoding
}
