#![no_main]

use irmind_mod_sigma::admit_rule;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = admit_rule(input);
});
