use irmind_domain::{AuthorizedCall, CaseId, ProposedCall, Tool};
use std::collections::BTreeMap;

fn main() {
    let _forged = AuthorizedCall {
        case_id: CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap(),
        proposal: ProposedCall { tool: Tool::GraphSummary, args: BTreeMap::new() },
        decision_seq: 1,
    };
}
