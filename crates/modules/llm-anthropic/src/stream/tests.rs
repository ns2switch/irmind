use super::*;

#[test]
fn native_tool_stream_is_assembled_before_policy_receives_it() {
    let wire = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":14}}}\n\n",
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
    assert_eq!(usage.input_tokens, 14);
    assert_eq!(usage.output_tokens, 7);
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
    assert_eq!(total_input(&usage).unwrap(), Some(125));
    assert!(
        total_input(&serde_json::json!({"input_tokens": u64::MAX, "cache_read_input_tokens": 1}))
            .is_err()
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
