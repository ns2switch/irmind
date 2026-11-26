#![cfg(feature = "sigma")]
#![allow(clippy::unwrap_used)]

use irmind_app::{
    CancellationToken, hex, sha256,
    v10_proofs::{SigmaPackManifestV1, SigmaPackRuleV1, SigmaRuleKeyV1},
};
use std::{
    fs,
    io::{Cursor, Read},
};

#[test]
#[ignore = "requires the original hash-pinned external SigmaHQ release asset"]
fn authenticates_every_entry_in_the_pinned_sigmahq_release() {
    let path = std::env::var_os("IRMIND_SIGMAHQ_ARCHIVE").unwrap();
    let bytes = fs::read(path).unwrap();
    let pin = sha256(&bytes);
    assert_eq!(
        hex(&pin),
        "5725c91b5813587ad6a4b0b8e0233fa44348b1595f818d8b7fd39d6033385085"
    );
    let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
    assert_eq!(archive.len(), 3303);
    let expected = (0..archive.len())
        .find_map(|idx| {
            let entry = archive.by_index(idx).unwrap();
            let path = entry.name().unwrap().into_owned();
            if !std::path::Path::new(&path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
                || entry.size() > 64 * 1024
            {
                return None;
            }
            let size = entry.size();
            let mut raw = Vec::new();
            entry.take(size + 1).read_to_end(&mut raw).unwrap();
            let document = irmind_sigma::admit_rule(&raw).ok()?;
            let hash = sha256(&raw);
            let text = |key| match document.fields().get(key) {
                Some(irmind_sigma::RuleValue::Text(value)) => Some(value.clone()),
                _ => None,
            };
            let item = SigmaPackRuleV1 {
                path,
                rule: SigmaRuleKeyV1 {
                    id: text("id").unwrap_or_else(|| format!("sha256:{}", hex(&hash))),
                    sha256: hash,
                },
                version: text("version"),
                author: text("author"),
                size,
            };
            Some((item, raw))
        })
        .unwrap();
    let (item, raw) = expected;
    let selection = SigmaPackManifestV1(vec![item]);
    let inspected = irmind_infra::sigma_pack::inspect_sigmahq_archive(
        &bytes,
        pin,
        &selection,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(inspected.rules, vec![raw]);
}
