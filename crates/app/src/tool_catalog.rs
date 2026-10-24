//! Provider-neutral tool catalog used by every LLM adapter.

use serde_json::{Value, json};

#[derive(Clone, Debug)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub parameters: Value,
}

#[must_use]
pub fn catalog() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: "evidence_search",
            description: "Search evidence in the active case only",
            parameters: json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"}},"required":["query"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "evidence_read",
            description: "Read a bounded excerpt of an evidence item in the active case",
            parameters: json!({"type":"object","properties":{"hash":{"type":"string"},"limit":{"type":"integer"}},"required":["hash"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "graph_summary",
            description: "Summarize indexed entities from local evidence",
            parameters: json!({"type":"object","properties":{},"additionalProperties":false}),
        },
        ToolSpec {
            name: "entity_lookup",
            description: "Find one entity in the active case and return bounded source record references",
            parameters: json!({"type":"object","properties":{"kind":{"type":"string","enum":["ip","host","user","role","identity","domain","hash","account","key"]},"value":{"type":"string"}},"required":["kind","value"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "neighbors",
            description: "Find entities co-observed in the same source records; co-observation does not prove a causal relationship",
            parameters: json!({"type":"object","properties":{"kind":{"type":"string","enum":["ip","host","user","role","identity","domain","hash","account","key"]},"value":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":20}},"required":["kind","value"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "entity_timeline",
            description: "Recent source records containing one entity in the active case",
            parameters: json!({"type":"object","properties":{"kind":{"type":"string","enum":["ip","host","user","role","identity","domain","hash","account","key"]},"value":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":20}},"required":["kind","value"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "path",
            description: "Find up to three co-observation hops between two entities; this does not prove causality",
            parameters: json!({"type":"object","properties":{"from_kind":{"type":"string","enum":["ip","host","user","role","identity","domain","hash","account","key"]},"from_value":{"type":"string"},"to_kind":{"type":"string","enum":["ip","host","user","role","identity","domain","hash","account","key"]},"to_value":{"type":"string"}},"required":["from_kind","from_value","to_kind","to_value"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "text_search",
            description: "Search all indexed JSON record fields in this case using a literal substring",
            parameters: json!({"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":20}},"required":["query"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "raw_records",
            description: "Read a bounded excerpt of one original JSON record by its hash and zero-based record index",
            parameters: json!({"type":"object","properties":{"hash":{"type":"string"},"index":{"type":"integer","minimum":0,"maximum":99999}},"required":["hash","index"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "case_add_finding",
            description: "Propose an unconfirmed case finding linked to existing evidence; only the analyst can confirm it for the report",
            parameters: json!({"type":"object","properties":{"kind":{"type":"string","enum":["ioc","hypothesis","technique","impact","recommendation"]},"value":{"type":"string"},"evidence_hash":{"type":"string","description":"SHA-256 of existing case evidence"}},"required":["kind","value","evidence_hash"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "siem_search",
            description: "Search a configured SIEM source for a single literal term in one scoped account and UTC window; Splunk uses a restricted SPL query built by its module",
            parameters: json!({"type":"object","properties":{"source":{"type":"string"},"account":{"type":"string"},"from":{"type":"string","description":"UTC YYYY-MM-DDTHH:MM:SSZ"},"to":{"type":"string","description":"UTC YYYY-MM-DDTHH:MM:SSZ"},"query":{"type":"string","description":"One literal term, no SPL operators"}},"required":["source","account","from","to","query"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "cloud_audit_events",
            description: "Read at most 20 CloudTrail management events by exact event name from a scoped AWS account and UTC window of at most 24 hours",
            parameters: json!({"type":"object","properties":{"source":{"type":"string"},"account":{"type":"string","description":"12-digit AWS account ID"},"from":{"type":"string","description":"UTC YYYY-MM-DDTHH:MM:SSZ"},"to":{"type":"string","description":"UTC YYYY-MM-DDTHH:MM:SSZ"},"event_name":{"type":"string","description":"Exact API event name, e.g. AssumeRole"}},"required":["source","account","from","to","event_name"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "cloud_identity",
            description: "Read a named IAM role or user in a scoped AWS account",
            parameters: json!({"type":"object","properties":{"source":{"type":"string"},"account":{"type":"string","description":"12-digit AWS account ID"},"kind":{"type":"string","enum":["role","user"]},"name":{"type":"string"}},"required":["source","account","kind","name"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "edr_host_info",
            description: "Read information for one host in a configured, scoped EDR source",
            parameters: json!({"type":"object","properties":{"source":{"type":"string"},"host":{"type":"string"}},"required":["source","host"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "edr_process_tree",
            description: "Read a process tree rooted at one process on a scoped EDR host",
            parameters: json!({"type":"object","properties":{"source":{"type":"string"},"host":{"type":"string"},"process_id":{"type":"string"}},"required":["source","host","process_id"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "edr_detections",
            description: "Read detections for one scoped EDR host in a UTC time window",
            parameters: json!({"type":"object","properties":{"source":{"type":"string"},"host":{"type":"string"},"from":{"type":"string","description":"UTC YYYY-MM-DDTHH:MM:SSZ"},"to":{"type":"string","description":"UTC YYYY-MM-DDTHH:MM:SSZ"}},"required":["source","host","from","to"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "ti_lookup_internal",
            description: "Look up an IOC in a configured internal threat intelligence source such as MISP; source must be within the case scope",
            parameters: json!({"type":"object","properties":{"source":{"type":"string"},"ioc":{"type":"string"}},"required":["source","ioc"],"additionalProperties":false}),
        },
        ToolSpec {
            name: "ti_lookup_external",
            description: "Look up a public IOC with external threat intelligence. This always pauses for analyst approval; querying can disclose the IOC to the provider.",
            parameters: json!({"type":"object","properties":{"ioc":{"type":"string","description":"Public IPv4, domain, or file hash"}},"required":["ioc"],"additionalProperties":false}),
        },
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_domain::Tool;
    use std::collections::BTreeSet;

    #[test]
    fn provider_neutral_catalog_matches_policy_tools() {
        let specs = catalog();
        let mut names = BTreeSet::new();
        for spec in &specs {
            assert!(names.insert(spec.name));
            assert_eq!(Tool::parse(spec.name).unwrap().as_str(), spec.name);
            assert_eq!(spec.parameters["type"], "object");
            assert_eq!(spec.parameters["additionalProperties"], false);
            if let Some(required) = spec.parameters["required"].as_array() {
                for name in required {
                    assert!(
                        spec.parameters["properties"]
                            .get(name.as_str().unwrap())
                            .is_some()
                    );
                }
            }
        }
        assert_eq!(specs.len(), 18);
    }
}
