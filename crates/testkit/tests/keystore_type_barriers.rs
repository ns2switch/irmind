#![forbid(unsafe_code)]

#[test]
fn signing_private_key_is_not_readable_through_the_port() {
    trybuild::TestCases::new().compile_fail("tests/ui/keystore_private_key.rs");
}
