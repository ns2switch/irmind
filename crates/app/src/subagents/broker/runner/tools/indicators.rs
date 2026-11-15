//! Only scalars read from a verified assigned original can seed an external lookup.
use super::{AppError, Engine, TaskSession};
use crate::subagents::SubagentSourceRef;
use irmind_domain::{IocType, IocValue, SourceRecordV1, SourceValue, Tainted};

pub(in crate::subagents::broker::runner) struct ObservedIndicator {
    pub source: SubagentSourceRef,
    pub excerpt: String,
}
#[derive(serde::Serialize)]
struct Excerpt<'a> {
    observed_original_value: &'a str,
    record: u64,
}
pub(super) fn observe(
    engine: &Engine<'_>,
    state: &mut TaskSession,
    record: &Tainted<SourceRecordV1>,
    sources: &[SubagentSourceRef],
) -> Result<(), AppError> {
    let [source] = sources else {
        return Ok(());
    };
    let mut values = Vec::new();
    record.inspect(|record| {
        let mut stack = vec![record.fields()];
        while let Some(value) = stack.pop() {
            match value {
                SourceValue::Object(fields) => stack.extend(fields.values().rev()),
                SourceValue::Array(items) => stack.extend(items.iter().rev()),
                SourceValue::Text(text)
                    if values.len() < 65
                        && text.len() <= 253
                        && [IocType::Ip, IocType::Domain, IocType::Hash]
                            .iter()
                            .any(|kind| IocValue::parse(*kind, text).is_ok()) =>
                {
                    values.push(text.clone());
                }
                _ => {}
            }
        }
    });
    for value in values {
        if state.observed.contains_key(&value) {
            continue;
        }
        if state.observed.len() >= 64 {
            state.partial = true;
            state.coverage.insert("The observed-indicator summary was bounded; read the original evidence for additional indicators.".into());
            break;
        }
        let text = serde_json::to_string(&Excerpt {
            observed_original_value: &value,
            record: source.index,
        })
        .map_err(|_| super::invalid())?;
        let excerpt = engine.guard.screen(&text)?.text;
        state.observed.insert(
            value,
            ObservedIndicator {
                source: *source,
                excerpt,
            },
        );
    }
    Ok(())
}
