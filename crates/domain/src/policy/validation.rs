use crate::{
    BTreeMap, GraphQueryFilter, ProposedCall, SiemQuery, Tool, valid_object_scope,
    valid_scope_target, valid_scope_time,
};

pub(super) fn valid_tool_arguments(proposal: &ProposedCall) -> bool {
    match proposal.tool {
        Tool::EvidenceSearch
        | Tool::EvidenceRead
        | Tool::GraphSummary
        | Tool::EntityLookup
        | Tool::Neighbors
        | Tool::EntityTimeline
        | Tool::GraphPath
        | Tool::TextSearch
        | Tool::RawRecords
        | Tool::CaseAddFinding => valid_local(proposal),
        Tool::SiemSearch => valid_siem_search(proposal),
        Tool::SiemGetAlert | Tool::CloudAuditEvents => valid_event(proposal),
        Tool::ThreatIntelInternal | Tool::CloudIdentity => valid_identity_and_intel(proposal),
        Tool::EdrHostInfo
        | Tool::EdrProcessTree
        | Tool::EdrDetections
        | Tool::ThreatIntelExternal => valid_edr_and_external_intel(proposal),
        Tool::ObjectList | Tool::ObjectRead => valid_object_request(proposal),
    }
}

fn valid_object_request(proposal: &ProposedCall) -> bool {
    let allowed: &[&str] = if proposal.tool == Tool::ObjectList {
        &[
            "source",
            "scheme",
            "container",
            "prefix",
            "from",
            "to",
            "limit",
        ]
    } else {
        &[
            "source",
            "scheme",
            "container",
            "key",
            "from",
            "to",
            "version",
            "etag",
            "max_bytes",
            "copy_original",
        ]
    };
    if !valid_args(&proposal.args, allowed) {
        return false;
    }
    let args = &proposal.args;
    if !valid_object_target(args, proposal.tool == Tool::ObjectList) {
        return false;
    }
    if proposal.tool == Tool::ObjectList {
        args.get("limit").is_some_and(|value| {
            value
                .parse::<usize>()
                .is_ok_and(|limit| (1..=1_000).contains(&limit))
        })
    } else {
        (args.contains_key("version") || args.contains_key("etag"))
            && args
                .get("copy_original")
                .is_none_or(|value| matches!(value.as_str(), "true" | "false"))
            && args.get("version").is_none_or(|value| {
                !value.is_empty() && value.len() <= 256 && !value.contains(['\n', '\r', '\0'])
            })
            && args.get("etag").is_none_or(|value| {
                !value.is_empty() && value.len() <= 256 && !value.contains(['\n', '\r', '\0'])
            })
            && args.get("max_bytes").is_some_and(|value| {
                value
                    .parse::<u64>()
                    .is_ok_and(|bytes| (1..=1_073_741_824).contains(&bytes))
            })
    }
}

fn valid_object_target(args: &BTreeMap<String, String>, listing: bool) -> bool {
    let Some((source, scheme, container, from, to)) = args
        .get("source")
        .zip(args.get("scheme"))
        .zip(args.get("container"))
        .zip(args.get("from"))
        .zip(args.get("to"))
        .map(|((((source, scheme), container), from), to)| (source, scheme, container, from, to))
    else {
        return false;
    };
    if !valid_scope_target(source)
        || !matches!(scheme.as_str(), "s3" | "gs" | "az")
        || !valid_scope_target(container)
        || container.contains(':')
        || !valid_scope_time(from)
        || !valid_scope_time(to)
        || crate::UtcTimestamp::parse(from)
            .ok()
            .zip(crate::UtcTimestamp::parse(to).ok())
            .is_none_or(|(a, b)| a > b)
    {
        return false;
    }
    let path_key = if listing { "prefix" } else { "key" };
    let Some(path) = args.get(path_key) else {
        return false;
    };
    valid_object_scope(&format!("{scheme}://{container}/{path}")) && (listing || !path.is_empty())
}

fn valid_local(proposal: &ProposedCall) -> bool {
    match proposal.tool {
        Tool::EvidenceSearch => {
            valid_args(&proposal.args, &["query", "limit"])
                && proposal
                    .args
                    .get("query")
                    .is_some_and(|q| !q.is_empty() && q.len() <= 256)
                && valid_limit(proposal.args.get("limit"))
        }
        Tool::EvidenceRead => {
            valid_args(&proposal.args, &["hash", "limit"])
                && proposal
                    .args
                    .get("hash")
                    .is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
                && valid_limit(proposal.args.get("limit"))
        }
        Tool::GraphSummary => proposal.args.is_empty(),
        Tool::EntityLookup => valid_entity_args(&proposal.args, false),
        Tool::Neighbors | Tool::EntityTimeline => valid_entity_args(&proposal.args, true),
        Tool::GraphPath => {
            valid_args(
                &proposal.args,
                &[
                    "from_kind",
                    "from_value",
                    "to_kind",
                    "to_value",
                    "from",
                    "to",
                    "account",
                    "project",
                    "region",
                ],
            ) && proposal
                .args
                .get("from_kind")
                .zip(proposal.args.get("from_value"))
                .is_some_and(|(kind, value)| valid_entity(kind, value))
                && proposal
                    .args
                    .get("to_kind")
                    .zip(proposal.args.get("to_value"))
                    .is_some_and(|(kind, value)| valid_entity(kind, value))
                && GraphQueryFilter::from_args(&proposal.args).is_ok()
        }
        Tool::TextSearch => {
            valid_args(
                &proposal.args,
                &[
                    "query", "limit", "from", "to", "account", "project", "region",
                ],
            ) && proposal
                .args
                .get("query")
                .is_some_and(|query| !query.trim().is_empty() && query.len() <= 128)
                && valid_limit(proposal.args.get("limit"))
                && GraphQueryFilter::from_args(&proposal.args).is_ok()
        }
        Tool::RawRecords => {
            valid_args(&proposal.args, &["hash", "index"])
                && proposal.args.get("hash").is_some_and(|hash| {
                    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
                })
                && proposal
                    .args
                    .get("index")
                    .is_some_and(|index| index.parse::<usize>().is_ok_and(|index| index < 100_000))
        }
        Tool::CaseAddFinding => valid_finding(&proposal.args),
        _ => false,
    }
}

fn valid_finding(args: &BTreeMap<String, String>) -> bool {
    valid_args(
        args,
        &[
            "kind",
            "value",
            "evidence_hash",
            "ioc_type",
            "first_seen",
            "last_seen",
            "verdict",
            "supporting_evidence",
            "refuting_evidence",
            "technique_id",
            "at",
            "source",
            "record_index",
        ],
    ) && args.get("kind").is_some_and(|kind| {
        matches!(
            kind.as_str(),
            "ioc" | "hypothesis" | "technique" | "timeline" | "impact" | "recommendation"
        )
    }) && args.get("value").is_some_and(|value| {
        !value.trim().is_empty() && value.len() <= 2_000 && !value.contains('\0')
    }) && args
        .get("evidence_hash")
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_event(proposal: &ProposedCall) -> bool {
    match proposal.tool {
        Tool::SiemGetAlert | Tool::CloudAuditEvents => {
            let query_key = if proposal.tool == Tool::SiemGetAlert {
                "alert_id"
            } else {
                "event_name"
            };
            let allowed = if proposal.tool == Tool::CloudAuditEvents {
                vec!["source", "account", "project", "from", "to", query_key]
            } else {
                vec!["source", "account", "from", "to", query_key]
            };
            let target_valid = if proposal.tool == Tool::CloudAuditEvents {
                match (proposal.args.get("account"), proposal.args.get("project")) {
                    (Some(account), None) => valid_scope_target(account),
                    (None, Some(project)) => valid_scope_target(project),
                    _ => false,
                }
            } else {
                proposal
                    .args
                    .get("account")
                    .is_some_and(|value| valid_scope_target(value))
            };
            valid_args(&proposal.args, &allowed)
                && target_valid
                && proposal
                    .args
                    .get("source")
                    .is_some_and(|v| valid_scope_target(v))
                && proposal
                    .args
                    .get("from")
                    .is_some_and(|v| valid_scope_time(v))
                && proposal.args.get("to").is_some_and(|v| valid_scope_time(v))
                && proposal.args.get(query_key).is_some_and(|v| {
                    !v.is_empty()
                        && v.len() <= 128
                        && !v.contains('\0')
                        && v.bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:@/".contains(&byte))
                })
        }
        _ => false,
    }
}

fn valid_siem_search(proposal: &ProposedCall) -> bool {
    valid_args(
        &proposal.args,
        &[
            "source",
            "account",
            "from",
            "to",
            "field",
            "operator",
            "value",
            "aggregation",
            "group_by",
            "limit",
        ],
    ) && proposal
        .args
        .get("source")
        .is_some_and(|value| valid_scope_target(value))
        && proposal
            .args
            .get("account")
            .is_some_and(|value| valid_scope_target(value))
        && proposal
            .args
            .get("from")
            .is_some_and(|value| valid_scope_time(value))
        && proposal
            .args
            .get("to")
            .is_some_and(|value| valid_scope_time(value))
        && SiemQuery::parse(&proposal.args).is_some()
}

fn valid_identity_and_intel(proposal: &ProposedCall) -> bool {
    match proposal.tool {
        Tool::ThreatIntelInternal => {
            valid_args(&proposal.args, &["source", "ioc"])
                && proposal
                    .args
                    .get("source")
                    .is_some_and(|v| valid_scope_target(v))
                && proposal.args.get("ioc").is_some_and(|v| {
                    !v.is_empty()
                        && v.len() <= 253
                        && v.bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                })
        }
        Tool::CloudIdentity => {
            valid_args(&proposal.args, &["source", "account", "kind", "name"])
                && proposal
                    .args
                    .get("source")
                    .is_some_and(|value| valid_scope_target(value))
                && proposal
                    .args
                    .get("account")
                    .is_some_and(|value| valid_scope_target(value))
                && proposal
                    .args
                    .get("kind")
                    .is_some_and(|value| matches!(value.as_str(), "role" | "user"))
                && proposal.args.get("name").is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"_+=,.@-".contains(&byte))
                })
        }
        _ => false,
    }
}

fn valid_edr_and_external_intel(proposal: &ProposedCall) -> bool {
    match proposal.tool {
        Tool::EdrHostInfo | Tool::EdrProcessTree | Tool::EdrDetections => {
            let fields: &[&str] = match proposal.tool {
                Tool::EdrHostInfo => &["source", "host"],
                Tool::EdrProcessTree => &["source", "host", "process_id"],
                Tool::EdrDetections => &["source", "host", "from", "to"],
                _ => &[],
            };
            valid_args(&proposal.args, fields)
                && proposal
                    .args
                    .get("source")
                    .is_some_and(|value| valid_scope_target(value))
                && proposal
                    .args
                    .get("host")
                    .is_some_and(|value| valid_scope_target(value))
                && (proposal.tool != Tool::EdrProcessTree
                    || proposal.args.get("process_id").is_some_and(|value| {
                        !value.is_empty()
                            && value.len() <= 128
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                    }))
                && (proposal.tool != Tool::EdrDetections
                    || proposal
                        .args
                        .get("from")
                        .zip(proposal.args.get("to"))
                        .is_some_and(|(from, to)| valid_scope_time(from) && valid_scope_time(to)))
        }
        Tool::ThreatIntelExternal => {
            valid_args(&proposal.args, &["ioc"])
                && proposal
                    .args
                    .get("ioc")
                    .is_some_and(|v| !v.is_empty() && v.len() <= 253)
        }
        _ => false,
    }
}

fn valid_args(args: &BTreeMap<String, String>, allowed: &[&str]) -> bool {
    args.keys().all(|key| allowed.contains(&key.as_str()))
}

fn valid_limit(value: Option<&String>) -> bool {
    value.is_none_or(|v| v.parse::<usize>().is_ok_and(|n| (1..=20).contains(&n)))
}

fn valid_entity_args(args: &BTreeMap<String, String>, allow_limit: bool) -> bool {
    let fields: &[&str] = if allow_limit {
        &[
            "kind", "value", "limit", "from", "to", "account", "project", "region",
        ]
    } else {
        &[
            "kind", "value", "from", "to", "account", "project", "region",
        ]
    };
    valid_args(args, fields)
        && args
            .get("kind")
            .zip(args.get("value"))
            .is_some_and(|(kind, value)| valid_entity(kind, value))
        && valid_limit(args.get("limit"))
        && GraphQueryFilter::from_args(args).is_ok()
}

pub fn valid_entity(kind: &str, value: &str) -> bool {
    matches!(
        kind,
        "ip" | "host"
            | "user"
            | "role"
            | "identity"
            | "domain"
            | "hash"
            | "account"
            | "key"
            | "principal"
            | "resource"
            | "user_agent"
            | "event_id"
    ) && !value.is_empty()
        && value.len() <= 512
}
