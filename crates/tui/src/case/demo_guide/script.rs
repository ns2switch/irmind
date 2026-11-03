use super::DemoEvent;
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

#[derive(Clone)]
pub(super) enum Action {
    Command(String),
    Wait(u64),
}

pub(super) struct Step {
    pub title: String,
    pub narration: String,
    pub actions: Vec<Action>,
    pub requires: Vec<DemoEvent>,
}

pub(super) fn load() -> Result<Vec<Step>> {
    let data: Value =
        serde_json::from_str(include_str!("../../../assets/demo-presentation.en.json"))?;
    ensure!(data["version"] == 1, "unsupported demo script version");
    let steps = data["steps"].as_array().ok_or_else(invalid)?;
    ensure!(steps.len() == 10, "demo script requires ten steps");
    steps.iter().map(step).collect()
}

fn step(value: &Value) -> Result<Step> {
    let title = text(&value["title"], 80)?;
    let sentences = value["narration"].as_array().ok_or_else(invalid)?;
    ensure!(
        (2..=4).contains(&sentences.len()),
        "demo needs 2–4 sentences"
    );
    let narration = sentences
        .iter()
        .map(|value| text(value, 600))
        .collect::<Result<Vec<_>>>()?
        .join("\n\n");
    let actions = value["actions"].as_array().ok_or_else(invalid)?;
    ensure!(actions.len() <= 12, "too many demo actions");
    let actions = actions.iter().map(action).collect::<Result<_>>()?;
    let requires = value["requires"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(event)
        .collect::<Result<_>>()?;
    Ok(Step {
        title,
        narration,
        actions,
        requires,
    })
}

fn action(value: &Value) -> Result<Action> {
    if let Some(wait) = value.get("wait_ms").and_then(Value::as_u64) {
        ensure!(wait <= 10_000, "demo delay exceeds bound");
        return Ok(Action::Wait(wait));
    }
    Ok(Action::Command(text(value, 512)?))
}

fn event(value: &Value) -> Result<DemoEvent> {
    Ok(match value.as_str().ok_or_else(invalid)? {
        "scope" => DemoEvent::ScopeViewed,
        "ingest" => DemoEvent::EvidenceIngested,
        "timeline" => DemoEvent::TimelineViewed,
        "search" => DemoEvent::TermSearched,
        "neighbors" => DemoEvent::NeighborsViewed,
        "question" => DemoEvent::QuestionAnswered,
        "approval" => DemoEvent::ApprovalResolved,
        "finding" => DemoEvent::FindingResolved,
        "check" => DemoEvent::Checked,
        "verify" => DemoEvent::CustodyVerified,
        "seal" => DemoEvent::Sealed,
        "export" => DemoEvent::Exported,
        "verify-export" => DemoEvent::ExportVerified,
        _ => return Err(invalid()),
    })
}

fn text(value: &Value, limit: usize) -> Result<String> {
    let text = value.as_str().ok_or_else(invalid)?;
    ensure!(
        !text.is_empty() && text.len() <= limit,
        "invalid demo text length"
    );
    Ok(text.into())
}
fn invalid() -> anyhow::Error {
    anyhow!("invalid bundled demo presentation")
}
