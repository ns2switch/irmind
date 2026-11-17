//! Native provider usage snapshots never accumulate the same bill twice.
use super::{ModelUsage, Value};
#[derive(Clone, Copy, Default)]
pub(crate) enum UsageProfile {
    #[default]
    Compatible,
    OpenAi,
    DeepSeek,
}

#[derive(Default)]
pub(super) struct UsageSnapshots {
    value: Option<ModelUsage>,
    profile: UsageProfile,
    uncertain: bool,
    message_id: Option<String>,
}
impl UsageSnapshots {
    pub(super) fn new(profile: UsageProfile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }
    pub(super) fn push(&mut self, chunk: &Value) {
        if let Some(id) = chunk.get("id").and_then(Value::as_str) {
            if self.message_id.as_deref().is_some_and(|prior| prior != id) {
                self.uncertain = true;
            }
            self.message_id = Some(id.to_owned());
        }
        if let Some(value) = chunk.get("usage").filter(|value| !value.is_null()) {
            let next = normalize_usage(value, self.profile);
            if let (Some(previous), Some(next)) = (self.value, next) {
                if next.input_tokens < previous.input_tokens
                    || next.output_tokens < previous.output_tokens
                {
                    self.uncertain = true;
                }
                if let (Some(a), Some(b)) = (previous.cache, next.cache)
                    && (b.read_input_tokens() < a.read_input_tokens()
                        || b.write_input_tokens() < a.write_input_tokens())
                {
                    self.uncertain = true;
                }
            }
            if next.is_none() {
                self.uncertain = true;
            }
            self.value = next;
        }
    }
    pub(super) fn finish(self) -> Option<ModelUsage> {
        if self.uncertain { None } else { self.value }
    }
}
fn normalize_usage(value: &Value, profile: UsageProfile) -> Option<ModelUsage> {
    use irmind_app::{CacheUsage, CacheWriteLifetime};
    let input_tokens = value.get("prompt_tokens")?.as_u64()?;
    let output_tokens = value.get("completion_tokens")?.as_u64()?;
    input_tokens.checked_add(output_tokens)?;
    let detail = value.pointer("/prompt_tokens_details/cached_tokens");
    let read = match profile {
        UsageProfile::Compatible => None,
        UsageProfile::OpenAi => detail.and_then(Value::as_u64),
        UsageProfile::DeepSeek => {
            let hit = value.get("prompt_cache_hit_tokens");
            match (hit, detail) {
                (Some(a), Some(b)) if a.as_u64() != b.as_u64() => None,
                (Some(a), _) | (_, Some(a)) => a.as_u64(),
                _ => None,
            }
        }
    };
    let cache = read.and_then(|read| {
        if let UsageProfile::DeepSeek = profile
            && let Some(miss) = value.get("prompt_cache_miss_tokens")
            && miss.as_u64().and_then(|n| n.checked_add(read)) != Some(input_tokens)
        {
            return None;
        }
        let cache = CacheUsage::new(read, 0, CacheWriteLifetime::NotApplicable).ok()?;
        cache.ordinary_input_tokens(input_tokens).ok()?;
        Some(cache)
    });
    Some(ModelUsage {
        input_tokens,
        output_tokens,
        cache,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod cache_tests {
    use super::*;
    use crate::stream::parse_profile;
    use std::fmt::Write as _;
    fn wire(reports: &[Value]) -> String {
        let mut wire = "data: {\"id\":\"request-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"paid answer\"},\"finish_reason\":\"stop\"}]}\n\n".to_owned();
        for usage in reports {
            write!(
                wire,
                "data: {}\n\n",
                serde_json::json!({"id":"request-1","choices":[],"usage":usage})
            )
            .unwrap();
        }
        wire.push_str("data: [DONE]\n\n");
        wire
    }
    #[test]
    fn actual_sse_normalizes_native_profiles_and_leaves_compatibles_unknown() {
        for (profile, usage, read) in [
            (
                UsageProfile::OpenAi,
                serde_json::json!({"prompt_tokens":1000,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":800}}),
                800,
            ),
            (
                UsageProfile::DeepSeek,
                serde_json::json!({"prompt_tokens":1000,"completion_tokens":50,"prompt_cache_hit_tokens":900,"prompt_cache_miss_tokens":100}),
                900,
            ),
        ] {
            let wire = wire(&[usage.clone(), usage]);
            let (response, usage) = parse_profile(wire.as_bytes(), profile).unwrap();
            assert_eq!(response.text, "paid answer");
            let usage = usage.unwrap();
            assert_eq!(usage.input_tokens, 1000);
            assert_eq!(usage.cache.unwrap().read_input_tokens(), read);
            assert!(
                parse_profile(wire.as_bytes(), UsageProfile::Compatible)
                    .unwrap()
                    .1
                    .unwrap()
                    .cache
                    .is_none()
            );
        }
    }
    #[test]
    fn contradictory_cache_retains_paid_reply_and_inclusive_input() {
        for value in [
            serde_json::json!({"prompt_tokens":1000,"completion_tokens":50,"prompt_cache_hit_tokens":900,"prompt_cache_miss_tokens":101}),
            serde_json::json!({"prompt_tokens":1000,"completion_tokens":50,"prompt_cache_hit_tokens":900,"prompt_tokens_details":{"cached_tokens":800}}),
            serde_json::json!({"prompt_tokens":1000,"completion_tokens":50,"prompt_cache_hit_tokens":1001}),
        ] {
            let (response, usage) =
                parse_profile(wire(&[value]).as_bytes(), UsageProfile::DeepSeek).unwrap();
            assert_eq!(response.text, "paid answer");
            let usage = usage.unwrap();
            assert_eq!(usage.input_tokens, 1000);
            assert!(usage.cache.is_none());
        }
    }
    #[test]
    fn cumulative_snapshots_are_not_billed_twice_or_allowed_to_decrease() {
        let value = |input, output, read| serde_json::json!({"prompt_tokens":input,"completion_tokens":output,"prompt_tokens_details":{"cached_tokens":read}});
        let (_, usage) = parse_profile(
            wire(&[value(1000, 1, 800), value(1000, 50, 800)]).as_bytes(),
            UsageProfile::OpenAi,
        )
        .unwrap();
        assert_eq!(usage.unwrap().output_tokens, 50);
        let (response, usage) = parse_profile(
            wire(&[value(1000, 50, 800), value(1000, 1, 800)]).as_bytes(),
            UsageProfile::OpenAi,
        )
        .unwrap();
        assert_eq!(response.text, "paid answer");
        assert!(usage.is_none());
        let wire = wire(&[value(1000, 50, 800)]);
        let mismatched = wire.replacen("request-1", "other", 1);
        assert!(
            parse_profile(mismatched.as_bytes(), UsageProfile::OpenAi)
                .unwrap()
                .1
                .is_none()
        );
    }
}
