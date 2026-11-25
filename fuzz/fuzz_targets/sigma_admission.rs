#![no_main]

use irmind_sigma::{SigmaField, SigmaFieldKind, SigmaProgram, SigmaScalar, admit_rule};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fuzz_target!(|input: &[u8]| {
    let Ok(rule) = admit_rule(input) else {
        return;
    };
    let _ = SigmaProgram::validate_rule(&rule);
    let bindings = BTreeMap::from([
        ("Image".into(), SigmaFieldKind::Text),
        ("CommandLine".into(), SigmaFieldKind::Text),
        ("EventID".into(), SigmaFieldKind::Integer),
    ]);
    if let Ok(program) = SigmaProgram::compile(&rule, &bindings) {
        let _ = program.evaluate(
            |field| {
                let value = match field {
                    "EventID" => SigmaScalar::Integer(49),
                    _ => SigmaScalar::Text("synthetic test.exe"),
                };
                Ok(SigmaField::Single(value))
            },
            &mut 50_000,
        );
    }
});
