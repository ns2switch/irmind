use super::fields::Line;
use std::{
    borrow::Cow,
    collections::{BTreeMap, btree_map::Entry},
};
#[derive(Default)]
pub(super) struct Arguments<'a> {
    parts: BTreeMap<(usize, usize), Cow<'a, str>>,
    declared: Option<usize>,
    inconsistent: bool,
}
impl<'a> Arguments<'a> {
    pub(super) fn add(&mut self, line: &Line<'a>) {
        if let Some(count) = line
            .field("argc")
            .and_then(|count| count.parse::<usize>().ok())
        {
            self.inconsistent |= count > 1024 || self.declared.is_some_and(|old| old != count);
            self.declared = Some(count);
        }
        for &name in line.fields.keys() {
            let Some((argument, part)) = position(name) else {
                continue;
            };
            let Some(value) = line.decoded(name) else {
                continue;
            };
            match self.parts.entry((argument, part)) {
                Entry::Vacant(entry) => {
                    entry.insert(value);
                }
                Entry::Occupied(entry) => self.inconsistent |= entry.get() != &value,
            }
        }
    }
    pub(super) fn finish(self) -> (Vec<String>, bool) {
        let mut values = BTreeMap::<usize, String>::new();
        let mut next_part = BTreeMap::<usize, usize>::new();
        let mut complete = !self.inconsistent;
        for ((argument, part), value) in self.parts {
            let expected = next_part.entry(argument).or_default();
            complete &= *expected == part;
            *expected = part + 1;
            values.entry(argument).or_default().push_str(&value);
        }
        complete &= self.declared.is_some_and(|count| count == values.len());
        let mut output = Vec::new();
        for (argument, value) in values {
            complete &= argument == output.len();
            output.push(value);
        }
        (output, complete)
    }
}
fn position(name: &str) -> Option<(usize, usize)> {
    let name = name.strip_prefix('a')?;
    let (index, part) = name.split_once('[').map_or((name, "0"), |(index, part)| {
        (index, part.strip_suffix(']').unwrap_or("invalid"))
    });
    if index.is_empty()
        || part.is_empty()
        || !index.bytes().all(|byte| byte.is_ascii_digit())
        || !part.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let (index, part) = (index.parse::<usize>().ok()?, part.parse::<usize>().ok()?);
    (index < 1024 && part < 1024).then_some((index, part))
}
