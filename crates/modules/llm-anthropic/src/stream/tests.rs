use super::*;
use std::fmt::Write as _;

#[test]
fn native_tool_stream_is_assembled_before_policy_receives_it() {
    let wire = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":14,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":0}}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"evidence_search\",\"input\":{}}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"query\\\":\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"AssumeRole\\\"}\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":7}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
    );
    let (answer, usage) = parse(wire.as_bytes()).unwrap();
    assert_eq!(answer.calls.len(), 1);
    assert_eq!(answer.calls[0].id(), "toolu_1");
    assert_eq!(answer.calls[0].proposal().tool, Tool::EvidenceSearch);
    assert_eq!(
        answer.calls[0]
            .proposal()
            .args
            .get("query")
            .map(String::as_str),
        Some("AssumeRole")
    );
    assert_eq!(usage.unwrap().input_tokens, 14);
    assert_eq!(usage.unwrap().output_tokens, 7);
}

#[test]
fn rejects_truncated_or_failed_stream() {
    let prefix = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1}}}\n\n";
    assert!(parse(prefix.as_bytes()).is_err());
    let failed = format!("{prefix}event: error\ndata: {{\"type\":\"error\"}}\n\n");
    assert!(parse(failed.as_bytes()).is_err());
}

#[test]
fn cached_input_counts_toward_case_limit() {
    let usage = serde_json::json!({
        "input_tokens": 5,
        "cache_read_input_tokens": 100,
        "cache_creation_input_tokens": 20
    });
    assert_eq!(total_input(&usage, false).unwrap().0, 125);
    assert!(
        total_input(&serde_json::json!({"input_tokens": u64::MAX, "cache_read_input_tokens": 1, "cache_creation_input_tokens":0}), false)
            .is_none()
    );
}

#[test]
fn preview_emits_only_complete_text_events() {
    let mut preview = TextPreview::default();
    assert!(preview.push(b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hel").unwrap().is_empty());
    assert_eq!(preview.push(b"lo\"}}\n\n").unwrap(), ["hello"]);
}

#[test]
fn max_tokens_keeps_partial_text_without_dispatching_tools() {
    let wire = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2}}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"partial\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":{\"output_tokens\":4}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
    );
    let (answer, _) = parse(wire.as_bytes()).unwrap();
    assert!(answer.truncated);
    assert_eq!(answer.text, "partial");
    assert!(answer.calls.is_empty());
}

fn cache_wire(input: &serde_json::Value, deltas: &[serde_json::Value]) -> String {
    let mut wire = format!(
        "event: message_start\ndata: {}\n\n",
        serde_json::json!({"type":"message_start","message":{"id":"msg_1","usage":input}})
    );
    wire.push_str("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"paid reply\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n");
    for delta in deltas {
        write!(wire, "event: message_delta\ndata: {}\n\n", serde_json::json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":delta})).unwrap();
    }
    wire.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
    wire
}
#[test]
fn cache_sse_counts_disjoint_parts_once_and_preserves_lifetimes() {
    use irmind_app::CacheWriteLifetime;
    let input = serde_json::json!({"input_tokens":100,"cache_read_input_tokens":800,"cache_creation_input_tokens":100});
    let wire = cache_wire(&input, &[serde_json::json!({"output_tokens":50})]);
    let (reply, usage) = parse_profile(wire.as_bytes(), true).unwrap();
    assert_eq!(reply.text, "paid reply");
    let usage = usage.unwrap();
    assert_eq!(usage.input_tokens, 1000);
    assert_eq!(
        usage.cache.unwrap().write_lifetime(),
        CacheWriteLifetime::FiveMinutes
    );
    assert_eq!(
        parse(wire.as_bytes())
            .unwrap()
            .1
            .unwrap()
            .cache
            .unwrap()
            .write_lifetime(),
        CacheWriteLifetime::Unknown
    );
    for (five, hour, lifetime) in [
        (100, 0, CacheWriteLifetime::FiveMinutes),
        (0, 100, CacheWriteLifetime::OneHour),
        (50, 50, CacheWriteLifetime::Unknown),
    ] {
        let mut input = input.clone();
        input["cache_creation"] =
            serde_json::json!({"ephemeral_5m_input_tokens":five,"ephemeral_1h_input_tokens":hour});
        let (_, usage) = parse_profile(
            cache_wire(&input, &[serde_json::json!({"output_tokens":50})]).as_bytes(),
            true,
        )
        .unwrap();
        assert_eq!(usage.unwrap().cache.unwrap().write_lifetime(), lifetime);
    }
    let (_, usage) = parse_profile(
        cache_wire(
            &input,
            &[
                input.clone(),
                serde_json::json!({"output_tokens":1}),
                serde_json::json!({"output_tokens":50}),
            ],
        )
        .as_bytes(),
        true,
    )
    .unwrap();
    assert_eq!(usage.unwrap().input_tokens, 1000);
    assert_eq!(usage.unwrap().output_tokens, 50);
}
#[test]
fn incomplete_or_contradictory_usage_keeps_response_and_uncertain_accounting() {
    for input in [
        serde_json::json!({"input_tokens":100}),
        serde_json::json!({"input_tokens":u64::MAX,"cache_read_input_tokens":1,"cache_creation_input_tokens":0}),
    ] {
        let (reply, usage) = parse_profile(
            cache_wire(&input, &[serde_json::json!({"output_tokens":50})]).as_bytes(),
            true,
        )
        .unwrap();
        assert_eq!(reply.text, "paid reply");
        assert!(usage.is_none());
    }
    let invalid_ttl = serde_json::json!({"input_tokens":100,"cache_read_input_tokens":800,"cache_creation_input_tokens":100,"cache_creation":{"ephemeral_5m_input_tokens":1,"ephemeral_1h_input_tokens":1}});
    let (_, usage) = parse_profile(
        cache_wire(&invalid_ttl, &[serde_json::json!({"output_tokens":50})]).as_bytes(),
        true,
    )
    .unwrap();
    assert_eq!(usage.unwrap().input_tokens, 1000);
    assert!(usage.unwrap().cache.is_none());
    let input = serde_json::json!({"input_tokens":100,"cache_read_input_tokens":800,"cache_creation_input_tokens":0});
    let (reply, usage) = parse_profile(
        cache_wire(
            &input,
            &[
                serde_json::json!({"output_tokens":50}),
                serde_json::json!({"output_tokens":49}),
            ],
        )
        .as_bytes(),
        true,
    )
    .unwrap();
    assert_eq!(reply.text, "paid reply");
    assert!(usage.is_none());
}

#[test]
fn contradictory_cache_updates_keep_known_inclusive_totals_unpriced() {
    let start = serde_json::json!({"input_tokens":100,"cache_read_input_tokens":800,"cache_creation_input_tokens":100});
    let next = serde_json::json!({"input_tokens":200,"cache_read_input_tokens":700,"cache_creation_input_tokens":100,"output_tokens":50});
    let final_snapshot = serde_json::json!({"input_tokens":50,"cache_read_input_tokens":850,"cache_creation_input_tokens":100,"output_tokens":50});
    let (reply, usage) =
        parse_profile(cache_wire(&start, &[next, final_snapshot]).as_bytes(), true).unwrap();
    assert_eq!(reply.text, "paid reply");
    let usage = usage.unwrap();
    assert_eq!(usage.input_tokens, 1000);
    assert_eq!(usage.output_tokens, 50);
    assert!(usage.cache.is_none());
}
