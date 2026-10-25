#![no_main]
use irmind_domain::{SplQueryClass, classify_spl_query};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    let text = String::from_utf8_lossy(bytes);
    if classify_spl_query(&text) == SplQueryClass::SafeLiteral {
        assert!(text.len() <= 128);
        assert!(
            text.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-:@/".contains(&byte))
        );
    }
});
