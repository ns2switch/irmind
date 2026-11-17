use super::*;
use irmind_domain::AuditEventKind;

struct OutputModel {
    text: String,
    replies: Mutex<usize>,
    truncated_first: bool,
    truncate_followups: bool,
    fail_followup: bool,
    usage: ModelUsage,
}
#[async_trait]
impl LlmPort for OutputModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let mut count = self.replies.lock().unwrap();
        let first = *count == 0;
        *count += 1;
        if !first && self.fail_followup {
            return Err(AppError::Model("synthetic continuation failure".into()));
        }
        if !first && self.truncated_first {
            assert!(request.tools.is_empty());
            assert!(request.messages.iter().any(|m| m.role == irmind_app::MessageRole::Assistant && m.content == self.text));
            assert!(
                request
                    .messages
                    .iter()
                    .filter(|m| m.role == irmind_app::MessageRole::System)
                    .all(|m| !m.content.contains("Synthetic"))
            );
        }
        let text = if first {
            self.text.clone()
        } else {
            " and the final part.".into()
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                raw: text.clone(),
                text,
                calls: vec![],
                truncated: (first && self.truncated_first) || (!first && self.truncate_followups),
            },
            Some(self.usage),
        ))
    }
}
fn output_model(text: String, truncated: bool, output_tokens: u64) -> OutputModel {
    OutputModel {
        text,
        replies: Mutex::new(0),
        truncated_first: truncated,
        truncate_followups: false,
        fail_followup: false,
        usage: ModelUsage {
            cache: None,
            input_tokens: 20,
            output_tokens,
        },
    }
}

#[test]
fn a_128000_token_reported_answer_is_retained_signed_and_exported_in_full() {
    let (root, store, engine, id) = engine_fixture();
    // 128,000 synthetic word tokens, 640,000 UTF-8 bytes, provider-reported usage.
    // No claim is made about a real provider tokenizer.
    let text = "word ".repeat(128_000);
    let model = output_model(text.clone(), false, 128_000);
    let reply = engine
        .investigate(&id, "Explain the synthetic observations.", &model)
        .unwrap();
    assert_eq!(reply, text);
    let entries = store.entries(&id).unwrap();
    assert_eq!(
        entries
            .iter()
            .find(|e| e.kind == AuditEventKind::FinalAnswer)
            .unwrap()
            .payload,
        text
    );
    assert_eq!(engine.case_budget(&id).unwrap().usage.model_tokens, 128_020);
    for entry in &entries {
        assert!(serde_json::to_vec(entry).unwrap().len() <= 1024 * 1024);
    }
    engine.verify(&id).unwrap();
    engine.seal(&id).unwrap();
    let path = root.path().join("complete-answer.irmind");
    let key = irmind_app::export_case_with_originals(
        &engine,
        store.as_ref(),
        &id,
        &path,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    irmind_app::verify_export_details(&crate::LocalExportVerifier, &path, Some(&key)).unwrap();
    let exported = std::fs::read(path).unwrap();
    assert!(
        exported
            .windows(text.len())
            .any(|window| window == text.as_bytes())
    );
}

#[test]
fn an_admitted_response_can_overdraw_but_the_next_request_does_not_start() {
    let (_root, store, engine, id) = engine_fixture();
    engine
        .change_case_budget(
            &id,
            irmind_app::CaseBudgetLimits {
                model_tokens: 100,
                tool_calls: 1000,
                cloud_bytes: 536_870_912_000,
            },
            false,
        )
        .unwrap();
    let model = output_model("The entire paid answer is retained.".into(), false, 200);
    let reply = engine
        .investigate(&id, "Explain the case.", &model)
        .unwrap();
    assert!(reply.starts_with(&model.text));
    assert!(reply.contains("/budget"));
    assert_eq!(engine.case_budget(&id).unwrap().usage.model_tokens, 220);
    let before = store
        .entries(&id)
        .unwrap()
        .iter()
        .filter(|e| e.kind == AuditEventKind::ModelRequest)
        .count();
    let next = engine.investigate(&id, "Explain again.", &model).unwrap();
    assert!(next.contains("/budget"));
    assert_eq!(*model.replies.lock().unwrap(), 1);
    let after = store
        .entries(&id)
        .unwrap()
        .iter()
        .filter(|e| e.kind == AuditEventKind::ModelRequest)
        .count();
    assert_eq!(before, after);
    engine.verify(&id).unwrap();
}

#[test]
fn native_length_stop_continues_once_as_one_signed_final_answer() {
    let (_root, store, engine, id) = engine_fixture();
    let model = output_model("The first part".into(), true, 10);
    let reply = engine
        .investigate(&id, "Explain the case.", &model)
        .unwrap();
    assert!(reply.starts_with("The first part and the final part."));
    assert!(reply.contains("model reached its maximum output"));
    assert_eq!(*model.replies.lock().unwrap(), 2);
    let entries = store.entries(&id).unwrap();
    for kind in [
        AuditEventKind::ModelRequest,
        AuditEventKind::ModelReply,
        AuditEventKind::ModelUsage,
    ] {
        assert_eq!(entries.iter().filter(|e| e.kind == kind).count(), 2);
    }
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::FinalAnswer)
            .count(),
        1
    );
    assert_eq!(engine.case_budget(&id).unwrap().usage.model_tokens, 60);
    engine.verify(&id).unwrap();
}

#[test]
fn escaped_text_that_exceeds_a_frame_is_explicitly_marked_and_still_exports() {
    let (root, store, engine, id) = engine_fixture();
    let model = output_model("\"".repeat(700_000), false, 128_000);
    let reply = engine
        .investigate(&id, "Explain the case.", &model)
        .unwrap();
    assert!(
        reply.ends_with("[Truncated by IRMind's security limit; this response is incomplete.]")
    );
    for entry in store.entries(&id).unwrap() {
        assert!(serde_json::to_vec(&entry).unwrap().len() <= 1024 * 1024);
    }
    engine.verify(&id).unwrap();
    engine.seal(&id).unwrap();
    let path = root.path().join("security-prefix.irmind");
    let key = irmind_app::export_case_with_originals(
        &engine,
        store.as_ref(),
        &id,
        &path,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    irmind_app::verify_export_details(&crate::LocalExportVerifier, &path, Some(&key)).unwrap();
}

#[test]
fn a_second_provider_stop_does_not_create_a_retry_loop() {
    let (_root, _store, engine, id) = engine_fixture();
    let mut model = output_model("First part".into(), true, 10);
    model.truncate_followups = true;
    let reply = engine
        .investigate(&id, "Explain the case.", &model)
        .unwrap();
    assert_eq!(*model.replies.lock().unwrap(), 2);
    assert!(reply.contains("First part and the final part."));
    assert!(reply.contains("model reached its maximum output"));
    assert!(!reply.contains("Use /continue"));
}

#[test]
fn a_security_prefix_and_streaming_preview_do_not_expose_an_open_private_key() {
    let (_root, _store, engine, id) = engine_fixture();
    let mut text = "safe ".repeat(190_000);
    text.push_str("-----BEGIN PRIVATE KEY-----\n");
    text.push_str(&"synthetic private material\n".repeat(6_000));
    let preview =
        irmind_app::screen_model_preview(engine.guard.as_ref(), &text[..990_000]).unwrap();
    assert!(!preview.text.contains("synthetic private material"));
    text.push_str("-----END PRIVATE KEY-----");
    let model = output_model(text, false, 128_000);
    let reply = engine
        .investigate(&id, "Explain the case.", &model)
        .unwrap();
    assert!(!reply.contains("synthetic private material"));
    assert!(reply.contains("Truncated by IRMind's security limit"));
    engine.verify(&id).unwrap();
}

#[test]
fn a_failed_automatic_continuation_retains_the_received_prefix_and_known_charge() {
    let (_root, store, engine, id) = engine_fixture();
    let mut model = output_model("Received and paid prefix".into(), true, 10);
    model.fail_followup = true;
    assert!(
        engine
            .investigate(&id, "Explain the case.", &model)
            .is_err()
    );
    let entries = store.entries(&id).unwrap();
    let answer = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::FinalAnswer)
        .unwrap();
    assert!(answer.payload.starts_with("Received and paid prefix"));
    assert!(answer.payload.contains("did not complete"));
    assert_eq!(engine.case_budget(&id).unwrap().usage.model_tokens, 30);
    assert!(
        !engine
            .case_budget(&id)
            .unwrap()
            .usage
            .provider_usage_available
    );
    engine.verify(&id).unwrap();
}
