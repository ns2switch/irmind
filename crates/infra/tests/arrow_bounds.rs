#![forbid(unsafe_code)]

use arrow_array::{
    ArrayAccessor as _, BooleanArray, DictionaryArray, FixedSizeBinaryArray, Int32Array, RunArray,
    StringArray, StringViewArray, types::Int32Type,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn constant_diagnostic<T>(read: impl FnOnce() -> T) -> TestResult {
    let payload = catch_unwind(AssertUnwindSafe(read))
        .err()
        .ok_or("out-of-range array access did not fail")?;
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .ok_or("array bounds failure has no text diagnostic")?;
    assert_eq!(message, "Arrow array index out of bounds");
    Ok(())
}

#[test]
fn primitive_and_binary_arrays_keep_checks_with_constant_diagnostics() -> TestResult {
    let booleans = BooleanArray::from(vec![true]);
    assert!(booleans.value(0));
    constant_diagnostic(|| booleans.value(1))?;
    let strings = StringArray::from(vec!["SYNTHETIC-ACCOUNT"]);
    assert_eq!(strings.value(0), "SYNTHETIC-ACCOUNT");
    constant_diagnostic(|| strings.value(1))?;
    let views = StringViewArray::from(vec!["SYNTHETIC-ACCOUNT"]);
    assert_eq!(views.value(0), "SYNTHETIC-ACCOUNT");
    constant_diagnostic(|| views.value(1))?;
    let fixed = FixedSizeBinaryArray::try_from_iter([b"account".as_slice()].into_iter())?;
    assert_eq!(fixed.value(0), b"account");
    constant_diagnostic(|| fixed.value(1))?;
    let integers = Int32Array::from(vec![42]);
    assert_eq!(integers.value(0), 42);
    constant_diagnostic(|| integers.value(1))?;
    Ok(())
}

#[test]
fn dictionary_and_run_arrays_keep_checks_with_constant_diagnostics() -> TestResult {
    let dictionary = DictionaryArray::<Int32Type>::from_iter([Some("SYNTHETIC-ACCOUNT")]);
    let typed = dictionary
        .downcast_dict::<StringArray>()
        .ok_or("invalid dictionary fixture")?;
    assert_eq!(typed.value(0), "SYNTHETIC-ACCOUNT");
    constant_diagnostic(|| typed.value(1))?;
    let ends = Int32Array::from(vec![1]);
    let values = StringArray::from(vec!["SYNTHETIC-SERVICE-ACCOUNT"]);
    let runs = RunArray::<Int32Type>::try_new(&ends, &values)?;
    let typed = runs
        .downcast::<StringArray>()
        .ok_or("invalid run fixture")?;
    assert_eq!(typed.value(0), "SYNTHETIC-SERVICE-ACCOUNT");
    constant_diagnostic(|| typed.value(1))?;
    Ok(())
}
