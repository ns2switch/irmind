#![no_main]
#![forbid(unsafe_code)]

use irmind_app::v10_proofs::SigmaFieldTableV1;
use irmind_infra::sigma_pack::field_table::ReviewedSigmaFieldTable;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 512 * 1024 {
        return;
    }
    let Ok(toml) = std::str::from_utf8(data) else {
        return;
    };
    let table = SigmaFieldTableV1 {
        id: "synthetic-fuzz-contract".into(),
        version: "v1".into(),
        toml: toml.into(),
    };
    let _ = ReviewedSigmaFieldTable::parse(&table);
});
