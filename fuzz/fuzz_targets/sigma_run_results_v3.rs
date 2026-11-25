#![no_main]
#![forbid(unsafe_code)]

use irmind_app::v10_proofs::SigmaRunResultsV3;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    if let Ok(result) = SigmaRunResultsV3::decode(body) {
        assert_eq!(result.encode().unwrap(), body);
        let _ = result.plan.coverage();
    }
});
