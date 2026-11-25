#![no_main]

use irmind_app::{
    CancellationToken, hex, sha256,
    v10_proofs::{SigmaPackManifestV1, SigmaPackRuleV1, SigmaRuleKeyV1},
};
use libfuzzer_sys::fuzz_target;

const RULE: &[u8] = b"title: Synthetic archive rule\nlogsource: {product: aws}\ndetection: {selection: {Outcome: success}, condition: selection}\n";

fuzz_target!(|archive: &[u8]| {
    let digest = sha256(RULE);
    let manifest = SigmaPackManifestV1(vec![SigmaPackRuleV1 {
        path: "synthetic.yml".into(),
        rule: SigmaRuleKeyV1 { id: format!("sha256:{}", hex(&digest)), sha256: digest },
        version: None,
        author: None,
        size: RULE.len() as u64,
    }]);
    // Treat the candidate bytes as pinned to exercise structure and inflation.
    let _ = irmind_infra::sigma_pack::inspect_sigmahq_archive(
        archive, sha256(archive), &manifest, &CancellationToken::new(),
    );
});
