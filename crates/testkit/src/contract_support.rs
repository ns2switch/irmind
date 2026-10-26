use crate::*;

struct ContractAnalyst(SigningKey);

impl AnalystApprovalVerifier for ContractAnalyst {
    fn verify_analyst(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(bytes): Result<[u8; 64], _> = signature.try_into() else {
            return false;
        };
        self.0
            .verifying_key()
            .verify(message, &ed25519_dalek::Signature::from_bytes(&bytes))
            .is_ok()
    }
}

pub(super) fn contract_call(
    tool: Tool,
    source: &str,
    args: BTreeMap<String, String>,
) -> Result<AuthorizedCall, String> {
    let case = Case {
        id: CaseId::parse("22222222-2222-2222-2222-222222222222")
            .map_err(|error| format!("{error:?}"))?,
        title: "port contract".into(),
        severity: Severity::High,
        scope: format!(
            "v1;sources={source};accounts=123456789012;hosts=host-1;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z"
        ),
        sealed: false,
    };
    match evaluate(
        &case,
        ProposedCall { tool, args },
        1,
        ExecutionMode::Attended,
        1_700_000_000,
    ) {
        Decision::Allow(call) => Ok(call),
        Decision::NeedsApproval(pending) => {
            let analyst = ContractAnalyst(SigningKey::from_bytes(&[49; 32]));
            let signature = analyst.0.sign(&pending.challenge());
            pending
                .resolve(&signature.to_bytes(), &analyst, 1_700_000_000)
                .map_err(|error| format!("signed approval failed: {error:?}"))
        }
        Decision::Deny(reason) => Err(format!("contract proposal denied: {reason}")),
    }
}

pub(super) fn contract_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
}
