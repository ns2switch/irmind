#![no_main]
use irmind_app::{SignedEntry, sha256};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(entry) = serde_json::from_slice::<SignedEntry>(bytes) {
        let first = entry.canonical();
        let second = entry.canonical();
        assert_eq!(first, second);
        assert_eq!(sha256(&first), sha256(&second));
        let mut changed = entry;
        changed.payload.push('\0');
        let different = changed.canonical();
        assert_ne!(first, different);
        assert_ne!(sha256(&first), sha256(&different));
    }
});
