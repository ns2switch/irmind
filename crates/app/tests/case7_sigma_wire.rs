#![allow(clippy::unwrap_used)]

use irmind_app::{
    SignedOperation,
    v10_proofs::{SigmaCompiledRulesV1, SigmaPackAdmissionV1, SigmaRunResultsV3},
};

#[test]
fn retained_sigma_objects_decode_and_reproduce_the_case_7_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../docs/development/case-7-export-v11-vectors/wire.json"
    ))
    .unwrap();
    let body = |name: &str| {
        let item = &vectors["sigma"][name];
        hex::decode(item["hex"].as_str().unwrap()).unwrap()
    };

    let results = body("result_v3_no_sources");
    let decoded = SigmaRunResultsV3::decode(&results).unwrap();
    assert_eq!(decoded.encode().unwrap(), results);

    let compiled = body("compiled_rules");
    let rules = SigmaCompiledRulesV1::decode(&compiled).unwrap();
    assert_eq!(rules.encode().unwrap(), compiled);

    for name in ["local_global_admission", "pinned_global_admission"] {
        let signed: SignedOperation = serde_json::from_slice(&body(name)).unwrap();
        let admission = SigmaPackAdmissionV1::decode(&signed.operation).unwrap();
        assert_eq!(admission.encode().unwrap(), signed.operation);
    }
}
