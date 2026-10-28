#![no_main]
use irmind_domain::SiemQuery;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    let Ok(args) = serde_json::from_slice::<BTreeMap<String, String>>(bytes) else {
        return;
    };
    if let Some(query) = SiemQuery::parse(&args) {
        assert!(query.value().len() <= 128);
        assert!(
            !query
                .value()
                .chars()
                .any(|ch| matches!(ch, '*' | '`' | '|' | '$'))
        );
        assert!((1..=20).contains(&query.limit()));
        assert!((1..=86_400).contains(&(query.to().unix_seconds() - query.from().unix_seconds())));
    }
});
