use super::CatalogError;
use std::cmp::Ordering;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Version {
    core: [String; 3],
    prerelease: Vec<String>,
}
impl Version {
    pub(super) fn parse(text: &str) -> Result<Self, CatalogError> {
        if text.is_empty() || text.len() > 64 || !text.is_ascii() {
            return Err(CatalogError::InvalidData);
        }
        let (version, build) = text
            .split_once('+')
            .map_or((text, None), |(a, b)| (a, Some(b)));
        if build.is_some_and(|value| !identifiers(value, false)) {
            return Err(CatalogError::InvalidData);
        }
        let (core, prerelease) = version
            .split_once('-')
            .map_or((version, None), |(a, b)| (a, Some(b)));
        let core: [&str; 3] = core
            .split('.')
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| CatalogError::InvalidData)?;
        if core.iter().any(|v| !number(v)) || prerelease.is_some_and(|v| !identifiers(v, true)) {
            return Err(CatalogError::InvalidData);
        }
        Ok(Self {
            core: core.map(str::to_owned),
            prerelease: prerelease
                .map_or_else(Vec::new, |v| v.split('.').map(str::to_owned).collect()),
        })
    }
    pub(super) fn compare(&self, other: &Self) -> Ordering {
        for (a, b) in self.core.iter().zip(&other.core) {
            let order = numeric_cmp(a, b);
            if order != Ordering::Equal {
                return order;
            }
        }
        match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }
        for (a, b) in self.prerelease.iter().zip(&other.prerelease) {
            let numeric = |v: &str| v.bytes().all(|c| c.is_ascii_digit());
            let order = match (numeric(a), numeric(b)) {
                (true, true) => numeric_cmp(a, b),
                (true, false) => Ordering::Less,
                (false, true) => Ordering::Greater,
                (false, false) => a.cmp(b),
            };
            if order != Ordering::Equal {
                return order;
            }
        }
        self.prerelease.len().cmp(&other.prerelease.len())
    }
}
fn number(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|c| c.is_ascii_digit())
        && (text.len() == 1 || !text.starts_with('0'))
}
fn identifiers(text: &str, prerelease: bool) -> bool {
    text.split('.').all(|v| {
        !v.is_empty()
            && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            && (!prerelease || !v.bytes().all(|c| c.is_ascii_digit()) || number(v))
    })
}
fn numeric_cmp(a: &str, b: &str) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}
pub(super) fn release_tag(tag: &str) -> Result<(), CatalogError> {
    if tag.len() > 64 || tag.contains('+') {
        return Err(CatalogError::InvalidData);
    }
    Version::parse(tag.strip_prefix('v').ok_or(CatalogError::InvalidData)?)?;
    Ok(())
}
