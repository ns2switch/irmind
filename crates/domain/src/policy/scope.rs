use super::Gate;
use crate::{Case, CaseScope, GraphQueryFilter, ProposedCall, Tool};

const SCOPED_TOOLS: &[Tool] = &[
    Tool::SiemSearch,
    Tool::SiemGetAlert,
    Tool::CloudAuditEvents,
    Tool::ThreatIntelInternal,
    Tool::CloudIdentity,
    Tool::EdrHostInfo,
    Tool::EdrProcessTree,
    Tool::EdrDetections,
];

fn is_scoped(tool: &Tool) -> bool {
    SCOPED_TOOLS.contains(tool)
}

fn is_filtered_graph(tool: &Tool) -> bool {
    matches!(
        tool,
        Tool::EntityLookup
            | Tool::Neighbors
            | Tool::EntityTimeline
            | Tool::GraphPath
            | Tool::TextSearch
    )
}

pub(super) fn scope_gate(case: &Case, proposal: &ProposedCall) -> Gate {
    if is_filtered_graph(&proposal.tool) {
        let Ok(scope) = CaseScope::parse(&case.scope) else {
            return Gate::Deny("invalid case scope");
        };
        return if GraphQueryFilter::from_args(&proposal.args)
            .is_ok_and(|filter| filter.within_scope(&scope))
        {
            Gate::Continue
        } else {
            Gate::Deny("graph filter outside case scope")
        };
    }
    if !is_scoped(&proposal.tool) {
        return Gate::Continue;
    }
    let Ok(scope) = CaseScope::parse(&case.scope) else {
        return Gate::Deny("invalid case scope");
    };
    if in_scope(&scope, proposal) {
        Gate::Continue
    } else {
        Gate::Approval
    }
}

pub(super) fn in_scope(scope: &CaseScope, proposal: &ProposedCall) -> bool {
    if is_filtered_graph(&proposal.tool) {
        return GraphQueryFilter::from_args(&proposal.args)
            .is_ok_and(|filter| filter.within_scope(scope));
    }
    if !is_scoped(&proposal.tool) {
        return true;
    }
    match proposal.tool {
        Tool::SiemSearch | Tool::SiemGetAlert | Tool::CloudAuditEvents => {
            scoped_event(scope, proposal)
        }
        Tool::ThreatIntelInternal => proposal
            .args
            .get("source")
            .is_some_and(|source| scope.allows_source(source)),
        Tool::CloudIdentity => proposal
            .args
            .get("source")
            .zip(proposal.args.get("account"))
            .is_some_and(|(source, account)| scope.allows_account(source, account)),
        Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections => {
            scoped_edr(scope, proposal)
        }
        _ => false,
    }
}

fn scoped_event(scope: &CaseScope, proposal: &ProposedCall) -> bool {
    if proposal.tool == Tool::CloudAuditEvents
        && let Some(project) = proposal.args.get("project")
    {
        return proposal
            .args
            .get("source")
            .zip(proposal.args.get("from"))
            .zip(proposal.args.get("to"))
            .is_some_and(|((source, from), to)| scope.contains_project(source, project, from, to));
    }
    proposal
        .args
        .get("source")
        .zip(proposal.args.get("account"))
        .zip(proposal.args.get("from"))
        .zip(proposal.args.get("to"))
        .is_some_and(|(((source, account), from), to)| {
            scope.contains(source, Some(account), None, from, to)
        })
}

fn scoped_edr(scope: &CaseScope, proposal: &ProposedCall) -> bool {
    proposal
        .args
        .get("source")
        .zip(proposal.args.get("host"))
        .is_some_and(|(source, host)| {
            if proposal.tool == Tool::EdrDetections {
                proposal
                    .args
                    .get("from")
                    .zip(proposal.args.get("to"))
                    .is_some_and(|(from, to)| scope.contains(source, None, Some(host), from, to))
            } else {
                scope.allows_host(source, host)
            }
        })
}
