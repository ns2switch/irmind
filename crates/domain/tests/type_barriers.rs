#![forbid(unsafe_code)]

#[test]
fn authorization_and_taint_boundaries_are_private() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/authorized_call_private.rs");
    cases.compile_fail("tests/ui/taint_cannot_be_removed.rs");
    cases.compile_fail("tests/ui/taint_value_is_private.rs");
    cases.compile_fail("tests/ui/taint_visit_cannot_return_raw.rs");
}
