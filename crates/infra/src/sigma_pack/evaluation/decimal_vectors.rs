use super::*;
use crate::sigma_pack::field_table::ReviewedSigmaFieldTable;
use irmind_app::v10_proofs::{
    SIGMA_EVALUATOR_V3, SIGMA_EVALUATOR_V4, SigmaFieldTableV1, SigmaRunV1,
};

#[test]
fn decimal_projection_and_v4_receipts_follow_the_approved_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../../docs/development/sigma-azure-result-type-vectors/wire.json"
    ))
    .unwrap();
    let table = hex::decode(vectors["table"]["bytes_hex"].as_str().unwrap()).unwrap();
    let table = SigmaFieldTableV1::decode(&table).unwrap();
    assert!(ReviewedSigmaFieldTable::parse_for_evaluator(&table, SIGMA_EVALUATOR_V3).is_err());
    assert!(ReviewedSigmaFieldTable::parse_for_evaluator(&table, SIGMA_EVALUATOR_V4).is_ok());
    for sample in vectors["projections"].as_array().unwrap() {
        let result = decimal_result_type(sample["row"].get("ResultType"));
        let encoded = match result {
            DecimalResult::Number(value) => [&[0], value.to_be_bytes().as_slice()].concat(),
            DecimalResult::Absent => vec![1],
            DecimalResult::WrongType => vec![2],
            DecimalResult::Invalid => vec![3],
            DecimalResult::Overflow => vec![4],
        };
        assert_eq!(hex::encode(encoded), sample["expected"].as_str().unwrap());
    }

    for scenario in ["hit", "indeterminate"] {
        let encoded = vectors[scenario]["receipt"]["bytes_hex"].as_str().unwrap();
        let receipt = SigmaRunV1::decode(encoded).unwrap();
        assert_eq!(receipt.evaluator, SIGMA_EVALUATOR_V4);
        assert_eq!(receipt.encode().unwrap(), encoded);
        let bytes =
            hex::decode(vectors[scenario]["results"]["bytes_hex"].as_str().unwrap()).unwrap();
        assert_eq!(irmind_app::sha256(&bytes), receipt.result_manifest);
    }
    let bad = &vectors["invalid_results_swap"];
    let receipt = SigmaRunV1::decode(bad["receipt"]["bytes_hex"].as_str().unwrap()).unwrap();
    let result = hex::decode(bad["results"]["bytes_hex"].as_str().unwrap()).unwrap();
    assert_ne!(irmind_app::sha256(&result), receipt.result_manifest);
    let downgrade = SigmaRunV1::decode(
        vectors["invalid_evaluator_downgrade"]["bytes_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert!(ReviewedSigmaFieldTable::parse_for_evaluator(&table, &downgrade.evaluator).is_err());
    for (key, wrong) in [
        ("SigninLogs", "AADNonInteractiveUserSignInLogs"),
        ("parser-entra", "parser-json"),
        ("integer", "text"),
        ("null_policy = \"absent\"", "null_policy = \"present\""),
    ] {
        let mut invalid = table.clone();
        invalid.toml = invalid.toml.replace(key, wrong);
        assert!(
            ReviewedSigmaFieldTable::parse_for_evaluator(&invalid, SIGMA_EVALUATOR_V4).is_err()
        );
    }
}
