use super::{SelectorPredicate, SourceSelector};
use crate::source_mapping::{SourcePath, SourcePathSegment};
use std::collections::BTreeMap;

pub(super) fn witness(first: &SourceSelector, second: &SourceSelector) -> Option<String> {
    if first.parser != second.parser {
        return None;
    }
    let version = first.versions.intersection(&second.versions).next()?;
    if first
        .format
        .as_ref()
        .zip(second.format.as_ref())
        .is_some_and(|(a, b)| a != b)
    {
        return None;
    }
    let mut discriminators = first.discriminators.clone();
    for (key, value) in &second.discriminators {
        if discriminators
            .insert(*key, value.clone())
            .is_some_and(|old| &old != value)
        {
            return None;
        }
    }
    let mut fields: BTreeMap<SourcePath, SelectorPredicate> = BTreeMap::new();
    for condition in first.conditions.iter().chain(&second.conditions) {
        let value = match fields.get(&condition.path) {
            Some(previous) => intersect(previous, &condition.predicate)?,
            None => condition.predicate.clone(),
        };
        fields.insert(condition.path.clone(), value);
    }
    if !structurally_possible(&fields) {
        return None;
    }
    // Debug escapes source strings; the TUI still applies its output guard.
    Some(format!(
        "{}@{}; format={:?}; discriminators={discriminators:?}; fields={fields:?}",
        first.parser,
        version,
        first.format.as_ref().or(second.format.as_ref())
    ))
}

fn intersect(a: &SelectorPredicate, b: &SelectorPredicate) -> Option<SelectorPredicate> {
    use SelectorPredicate::{Exact, IntegerInterval, Missing, Null, Present};
    if a == b {
        return Some(a.clone());
    }
    match (a, b) {
        (Present, value) | (value, Present) if !matches!(value, Missing | Null) => {
            Some(value.clone())
        }
        (IntegerInterval { first: a, last: b }, IntegerInterval { first: c, last: d }) => {
            let (first, last) = ((*a).max(*c), (*b).min(*d));
            (first <= last).then_some(IntegerInterval { first, last })
        }
        (Exact(value), IntegerInterval { first, last })
        | (IntegerInterval { first, last }, Exact(value)) => value
            .integer()
            .filter(|v| (*first..=*last).contains(v))
            .map(|_| Exact(value.clone())),
        _ => None,
    }
}

fn structurally_possible(fields: &BTreeMap<SourcePath, SelectorPredicate>) -> bool {
    let mut containers: BTreeMap<Vec<SourcePathSegment>, bool> = BTreeMap::new();
    for (path, predicate) in fields {
        if *predicate == SelectorPredicate::Missing {
            continue;
        }
        let segments = path.segments();
        for (index, segment) in segments.iter().enumerate() {
            let prefix = segments[..index].to_vec();
            let array = matches!(segment, SourcePathSegment::Index(_));
            if (index == 0 && array)
                || containers
                    .insert(prefix, array)
                    .is_some_and(|old| old != array)
            {
                return false;
            }
        }
        for (parent, constraint) in fields {
            if parent.segments().len() < segments.len()
                && segments.starts_with(parent.segments())
                && !matches!(constraint, SelectorPredicate::Present)
            {
                return false;
            }
        }
    }
    true
}
