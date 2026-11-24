//! Sigma 2.1 boolean conditions with bounded selections and expansion.
//! <https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html#condition>

const MAX_CONDITION_BYTES: usize = 8_192;
const MAX_TOKENS: usize = 512;
const MAX_NESTING: usize = 24;
const MAX_BRANCHES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionError {
    Limit,
    Syntax,
    UnknownSelection,
}

pub(super) enum Condition {
    Selection(usize),
    Any(Vec<Self>),
    All(Vec<Self>),
    Not(Box<Self>),
}

impl Condition {
    pub(super) fn compile<'a>(
        expressions: impl IntoIterator<Item = &'a str>,
        names: &[&str],
    ) -> Result<Self, ConditionError> {
        if names.is_empty()
            || names.len() > MAX_BRANCHES
            || names.iter().any(|name| !identifier(name))
        {
            return Err(ConditionError::Limit);
        }
        let mut branches = MAX_BRANCHES;
        let mut alternatives = Vec::new();
        for expression in expressions {
            if expression.len() > MAX_CONDITION_BYTES {
                return Err(ConditionError::Limit);
            }
            let tokens = tokens(expression)?;
            let mut parser = Parser {
                tokens: &tokens,
                names,
                branches: &mut branches,
            };
            let result = parser.or(0)?;
            if !parser.tokens.is_empty() {
                return Err(ConditionError::Syntax);
            }
            alternatives.push(result);
        }
        if alternatives.is_empty() {
            return Err(ConditionError::Syntax);
        }
        Ok(group(alternatives, Self::Any))
    }

    pub(super) fn evaluate<E>(
        &self,
        selection: &mut impl FnMut(usize) -> Result<bool, E>,
    ) -> Result<bool, E> {
        match self {
            Self::Selection(index) => selection(*index),
            Self::Any(nodes) => {
                for node in nodes {
                    if node.evaluate(selection)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::All(nodes) => {
                for node in nodes {
                    if !node.evaluate(selection)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Not(node) => node.evaluate(selection).map(|matched| !matched),
        }
    }
}

struct Parser<'a> {
    tokens: &'a [&'a str],
    names: &'a [&'a str],
    branches: &'a mut usize,
}

impl<'a> Parser<'a> {
    fn or(&mut self, depth: usize) -> Result<Condition, ConditionError> {
        let mut nodes = vec![self.and(depth)?];
        while self.consume("or") {
            nodes.push(self.and(depth)?);
        }
        Ok(group(nodes, Condition::Any))
    }

    fn and(&mut self, depth: usize) -> Result<Condition, ConditionError> {
        let mut nodes = vec![self.atom(depth)?];
        while self.consume("and") {
            nodes.push(self.atom(depth)?);
        }
        Ok(group(nodes, Condition::All))
    }

    fn atom(&mut self, depth: usize) -> Result<Condition, ConditionError> {
        if depth == MAX_NESTING {
            return Err(ConditionError::Limit);
        }
        match self.next().ok_or(ConditionError::Syntax)? {
            "(" => {
                let node = self.or(depth + 1)?;
                if !self.consume(")") {
                    return Err(ConditionError::Syntax);
                }
                Ok(node)
            }
            "not" => Ok(Condition::Not(Box::new(self.atom(depth + 1)?))),
            "1" => self.quantified(Condition::Any),
            "all" => self.quantified(Condition::All),
            name if identifier(name) => {
                let index = self
                    .names
                    .iter()
                    .position(|candidate| *candidate == name)
                    .ok_or(ConditionError::UnknownSelection)?;
                self.charge(1)?;
                Ok(Condition::Selection(index))
            }
            _ => Err(ConditionError::Syntax),
        }
    }

    fn quantified(
        &mut self,
        op: fn(Vec<Condition>) -> Condition,
    ) -> Result<Condition, ConditionError> {
        if !self.consume("of") {
            return Err(ConditionError::Syntax);
        }
        let pattern = self.next().ok_or(ConditionError::Syntax)?;
        if !pattern.bytes().all(|byte| name_byte(byte) || byte == b'*') || pattern == "*" {
            return Err(ConditionError::Syntax);
        }
        let selections = self
            .names
            .iter()
            .enumerate()
            .filter(|(_, name)| {
                if pattern == "them" {
                    !name.starts_with('_')
                } else {
                    matches_pattern(pattern, name)
                }
            })
            .map(|(index, _)| Condition::Selection(index))
            .collect::<Vec<_>>();
        if selections.is_empty() {
            return Err(ConditionError::UnknownSelection);
        }
        self.charge(selections.len())?;
        Ok(group(selections, op))
    }

    fn charge(&mut self, count: usize) -> Result<(), ConditionError> {
        *self.branches = self
            .branches
            .checked_sub(count)
            .ok_or(ConditionError::Limit)?;
        Ok(())
    }

    fn next(&mut self) -> Option<&'a str> {
        let (first, rest) = self.tokens.split_first()?;
        self.tokens = rest;
        Some(first)
    }

    fn consume(&mut self, expected: &str) -> bool {
        if self.tokens.first() == Some(&expected) {
            self.tokens = &self.tokens[1..];
            return true;
        }
        false
    }
}

fn group(mut nodes: Vec<Condition>, op: impl FnOnce(Vec<Condition>) -> Condition) -> Condition {
    if nodes.len() == 1
        && let Some(node) = nodes.pop()
    {
        return node;
    }
    op(nodes)
}

fn tokens(mut value: &str) -> Result<Vec<&str>, ConditionError> {
    let mut tokens = Vec::new();
    loop {
        value = value.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
        if value.is_empty() {
            return Ok(tokens);
        }
        if tokens.len() == MAX_TOKENS {
            return Err(ConditionError::Limit);
        }
        let length = if value.starts_with(['(', ')']) {
            1
        } else {
            value
                .find(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '(' | ')'))
                .unwrap_or(value.len())
        };
        let (token, rest) = value.split_at(length);
        tokens.push(token);
        value = rest;
    }
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !matches!(value, "and" | "or" | "not" | "all" | "of" | "them" | "1")
        && value.bytes().all(name_byte)
}

fn name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    let mut pieces = pattern.split('*');
    let Some(prefix) = pieces.next() else {
        return false;
    };
    let Some(mut rest) = value.strip_prefix(prefix) else {
        return false;
    };
    let mut pieces = pieces.peekable();
    if pieces.peek().is_none() {
        return rest.is_empty();
    }
    while let Some(piece) = pieces.next() {
        if pieces.peek().is_none() {
            return rest.ends_with(piece);
        }
        let Some((_, suffix)) = rest.split_once(piece) else {
            return false;
        };
        rest = suffix;
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn eval(condition: &str, values: [bool; 3]) -> bool {
        Condition::compile([condition], &["first_a", "other_a", "_private"])
            .unwrap()
            .evaluate(&mut |index| Ok::<_, ()>(values[index]))
            .unwrap()
    }

    #[test]
    fn conditions_use_sigma_precedence_and_bounded_wildcards() {
        assert!(eval(
            "first_a or other_a and not _private",
            [true, false, true]
        ));
        assert!(!eval(
            "(first_a or other_a) and not _private",
            [true, false, true]
        ));
        assert!(eval("1 of *st_*", [true, false, false]));
        assert!(!eval("all of *_a", [true, false, false]));
        assert!(!eval("1 of them", [false, false, true]));
        assert!(eval("1 of _priv*", [false, false, true]));
        assert!(Condition::compile(["field", "missing"], &["field"]).is_err());
        assert!(Condition::compile(["1 of missing*"], &["field"]).is_err());
        assert!(
            Condition::compile([&format!("{}field", "not ".repeat(24))[..]], &["field"]).is_err()
        );
    }

    #[test]
    fn negation_cannot_convert_an_unavailable_field_to_a_match() {
        let program = Condition::compile(["not field"], &["field"]).unwrap();
        assert_eq!(
            program.evaluate(&mut |_| Err("unavailable")),
            Err("unavailable")
        );
    }
}
