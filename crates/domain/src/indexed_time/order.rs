use super::{DomainError, IndexedInstant};
use std::cmp::Ordering;

/// Borrowed keys avoid allocating an entity/source string for each comparison.
#[derive(Clone, Copy)]
pub struct StableRecordKey<'a> {
    pub instant: Option<IndexedInstant>,
    pub source: &'a str,
    pub source_hash: &'a str,
    pub source_offset: Option<u64>,
    pub record_index: u64,
}

pub fn compare_record_keys(
    left: StableRecordKey<'_>,
    right: StableRecordKey<'_>,
    newest_first: bool,
) -> Result<Ordering, DomainError> {
    if left.source == right.source
        && left.source_hash == right.source_hash
        && left.source_offset.is_some() != right.source_offset.is_some()
    {
        return Err(DomainError::InvalidManifest);
    }
    let time = match (left.instant, right.instant) {
        (Some(a), Some(b)) => {
            if newest_first {
                b.cmp(&a)
            } else {
                a.cmp(&b)
            }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    };
    Ok(time
        .then_with(|| left.source.as_bytes().cmp(right.source.as_bytes()))
        .then_with(|| {
            left.source_hash
                .as_bytes()
                .cmp(right.source_hash.as_bytes())
        })
        .then_with(|| match (left.source_offset, right.source_offset) {
            (Some(a), Some(b)) => a.cmp(&b),
            _ => left.record_index.cmp(&right.record_index),
        })
        .then_with(|| left.record_index.cmp(&right.record_index)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn source_offsets_missing_time_and_direction_are_stable() {
        let a = StableRecordKey {
            instant: Some(IndexedInstant::new(-1, 900).unwrap()),
            source: "a/log",
            source_hash: "a",
            source_offset: Some(20),
            record_index: 1,
        };
        let b = StableRecordKey {
            instant: Some(IndexedInstant::new(0, 0).unwrap()),
            ..a
        };
        assert_eq!(compare_record_keys(a, b, false), Ok(Ordering::Less));
        assert_eq!(compare_record_keys(a, b, true), Ok(Ordering::Greater));
        assert_eq!(
            compare_record_keys(StableRecordKey { instant: None, ..a }, b, true),
            Ok(Ordering::Greater)
        );
        assert_eq!(
            compare_record_keys(
                a,
                StableRecordKey {
                    source_offset: Some(30),
                    ..a
                },
                false
            ),
            Ok(Ordering::Less)
        );
        assert!(
            compare_record_keys(
                a,
                StableRecordKey {
                    source_offset: None,
                    ..b
                },
                false
            )
            .is_err()
        );
        assert_eq!(
            compare_record_keys(
                a,
                StableRecordKey {
                    source: "b/log",
                    source_offset: None,
                    ..a
                },
                false
            ),
            Ok(Ordering::Less)
        );
    }
}
