use super::*;
use serde_json::json;
use std::fmt::Write as _;

fn wire(frames: &[Value]) -> String {
    let mut wire = String::new();
    for frame in frames {
        write!(wire, "data: {frame}\n\n").unwrap();
    }
    wire.push_str("data: [DONE]\n\n");
    wire
}

#[test]
fn documented_compatible_endings_and_empty_followups_keep_one_usage_snapshot() {
    let answer = json!({"choices":[{"index":0,"delta":{"content":"synthetic"}}]});
    let stop = json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]});
    let counts = json!({"prompt_tokens":7,"completion_tokens":2,"total_tokens":9});
    let usage_only = json!({"choices":[],"usage":counts});
    let stop_with_usage =
        json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":counts});
    // Synthetic sequences model the documented completion shapes. Additional
    // empty followups exercise compatibility without asserting that every
    // server emits them.
    let cases = [
        // https://docs.vllm.ai/en/stable/serving/openai_compatible_server/
        ("vLLM", vec![stop.clone(), usage_only.clone()]),
        // https://github.com/ollama/ollama/blob/main/openai/openai.go
        ("Ollama", vec![stop.clone(), usage_only.clone()]),
        // https://lmstudio.ai/docs/developer/api-changelog
        (
            "LM Studio",
            vec![
                stop.clone(),
                json!({"choices":[{"index":0,"delta":{"content":""},"finish_reason":null}],"usage":counts}),
            ],
        ),
        // https://github.com/ggml-org/llama.cpp/issues/15443
        ("llama.cpp", vec![stop_with_usage.clone()]),
        // https://github.com/BerriAI/litellm-docs/blob/main/docs/completion/stream.md
        (
            "LiteLLM",
            vec![
                stop.clone(),
                json!({"choices":[{"index":0,"delta":{"content":null}}]}),
                json!({"choices":[{"index":0,"delta":null}],"usage":counts}),
                usage_only.clone(),
            ],
        ),
        // https://github.com/OpenRouterTeam/docs/blob/main/api_reference/streaming.mdx
        (
            "OpenRouter",
            vec![
                stop.clone(),
                stop_with_usage,
                json!({"choices":[{"index":0}],"usage":counts}),
            ],
        ),
    ];
    for (provider, endings) in cases {
        let mut frames = vec![answer.clone()];
        frames.extend(endings);
        frames.push(usage_only.clone());
        let wire = wire(&frames);
        let (response, usage) = parse(wire.as_bytes()).unwrap();
        assert_eq!(response.text, "synthetic", "{provider}");
        assert!(!response.truncated, "{provider}");
        assert!(response.calls.is_empty(), "{provider}");
        let usage = usage.unwrap();
        assert_eq!(
            (usage.input_tokens, usage.output_tokens),
            (7, 2),
            "{provider}"
        );
    }
}

#[test]
fn rejects_effective_output_and_conflicting_reasons_after_finish() {
    let stop = json!({"choices":[{"index":0,"delta":{"content":"before"},"finish_reason":"stop"}]});
    for choice in [
        json!({"index":0,"delta":{"content":"late text"}}),
        json!({"index":0,"delta":{"content":"late text","reasoning_content":"metadata"}}),
        json!({"index":0,"delta":{"tool_calls":[{"index":0}]}}),
        json!({"index":0,"delta":{"tool_calls":[]}}),
        json!({"index":0,"delta":{"function_call":{"name":"late"}}}),
        json!({"index":0,"delta":{"reasoning_content":{"content":"not a reasoning string"}}}),
        json!({"index":0,"delta":{"content":false}}),
        json!({"index":0,"delta":[]}),
        json!({"index":0,"delta":{},"message":{"content":"late text"}}),
        json!({"index":0,"delta":{},"finish_reason":"length"}),
        json!({"index":0,"delta":{},"finish_reason":0}),
    ] {
        let frame = json!({"choices":[choice]});
        let wire = wire(&[stop.clone(), frame]);
        assert!(matches!(
            parse(wire.as_bytes()),
            Err(AppError::Fixed(FixedAppError::AdapterModel(
                AdapterModelError::ProviderOutputAfterFinish
            )))
        ));
        assert_eq!(
            TextPreview::default().push(wire.as_bytes()).unwrap(),
            ["before"]
        );
    }
}

#[test]
fn content_filter_reports_the_provider_stop_and_omits_its_delta() {
    for choice in [
        json!({"index":0,"delta":{"content":"filtered"},"finish_reason":"content_filter"}),
        json!({"index":0,"delta":null,"finish_reason":"content_filter"}),
        json!({"index":0,"finish_reason":"content_filter"}),
    ] {
        let wire = wire(&[json!({"choices":[choice]})]);
        let error = parse(wire.as_bytes()).err().unwrap();
        assert!(matches!(
            error,
            AppError::Fixed(FixedAppError::AdapterModel(
                AdapterModelError::ProviderContentFiltered
            ))
        ));
        assert!(error.to_string().contains("content filter"));
        assert!(
            TextPreview::default()
                .push(wire.as_bytes())
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn glm_reasoning_and_assistant_role_are_metadata_before_and_after_finish() {
    // https://docs.z.ai/guides/capabilities/thinking
    // The late frames exercise compatible gateways while retaining the
    // documented separation between reasoning, answer text, and token usage.
    let usage = json!({"prompt_tokens":7,"completion_tokens":19,"total_tokens":26,
        "completion_tokens_details":{"reasoning_tokens":16}});
    let sse = wire(&[
        json!({"choices":[{"index":0,"delta":{"role":"assistant"}}]}),
        json!({"choices":[{"index":0,"delta":{"reasoning_content":"synthetic prior reasoning"}}]}),
        json!({"choices":[{"index":0,"delta":{"content":"visible answer"}}]}),
        json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        json!({"choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"synthetic late reasoning"},"finish_reason":"stop"}]}),
        json!({"choices":[{"index":0,"delta":{"role":"assistant"}}]}),
        json!({"choices":[],"usage":usage}),
        json!({"choices":[],"usage":usage}),
    ]);
    let (answer, counts) = parse(sse.as_bytes()).unwrap();
    assert_eq!(answer.text, "visible answer");
    assert!(answer.calls.is_empty());
    assert!(!answer.raw.contains("reasoning_content"));
    assert!(!answer.raw.contains("synthetic prior reasoning"));
    assert!(!answer.raw.contains("synthetic late reasoning"));
    assert_eq!(
        TextPreview::default().push(sse.as_bytes()).unwrap(),
        ["visible answer"]
    );
    let counts = counts.unwrap();
    assert_eq!((counts.input_tokens, counts.output_tokens), (7, 19));
}
