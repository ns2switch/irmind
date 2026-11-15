use irmind_app::subagents::{EngineEvent, EngineEventKind, SubagentDigest, SubagentResources};
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Panel {
    pub(super) visible: bool,
    pub(super) selected: usize,
    pub(super) detail: bool,
    rows: BTreeMap<SubagentDigest, Row>,
    notice: String,
}
struct Row {
    kind: String,
    objective: String,
    activity: String,
    summary: String,
    usage: Option<SubagentResources>,
    reported_tokens: u64,
    cost_microusd: Option<u64>,
}
impl Panel {
    pub(super) fn accept(&mut self, event: &EngineEvent) {
        let Some(task) = event.task_id else {
            self.notice.clone_from(&event.payload);
            return;
        };
        let row = self.rows.entry(task).or_insert_with(|| Row {
            kind: event.task_type.clone().unwrap_or_else(|| "Subagent".into()),
            objective: event.objective.clone().unwrap_or_default(),
            activity: "Prepared".into(),
            summary: String::new(),
            usage: None,
            reported_tokens: 0,
            cost_microusd: Some(0),
        });
        if event.model_reply {
            row.report(event.model_usage, event.estimated_cost_microusd);
        }
        match event.kind {
            EngineEventKind::Round | EngineEventKind::ToolProposal | EngineEventKind::Approval => {
                row.activity = event
                    .payload
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(160)
                    .collect();
            }
            EngineEventKind::Message | EngineEventKind::ToolResult => {
                row.summary.clone_from(&event.payload);
            }
            EngineEventKind::Status => {
                row.activity = event
                    .payload
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(160)
                    .collect();
                row.usage = event.usage;
            }
            _ => {}
        }
    }
    pub(super) fn text(&self) -> String {
        let mut lines = vec!["Subagents".into(), self.notice.clone(), String::new()];
        if self.rows.is_empty() {
            lines.push("No delegated tasks in this case yet.".into());
        }
        for (index, (task, row)) in self.rows.iter().enumerate() {
            let id = digest(*task);
            lines.push(format!(
                "{} {} · {} · {}",
                if index == self.selected { "›" } else { " " },
                label(&row.kind),
                &id[..8],
                row.activity
            ));
            lines.push(format!("  {}", row.objective));
            if let Some(usage) = row.usage {
                lines.push(format!(
                    "  {} tokens charged/reserved · {} calls · {} rounds · {} cloud bytes · {}",
                    usage.tokens,
                    usage.calls,
                    usage.rounds,
                    usage.cloud_bytes,
                    row.cost(usage.tokens)
                ));
            }
            if self.detail && index == self.selected {
                lines.push(format!("  Task: {id}"));
                lines.push(row.summary.clone());
            }
        }
        lines.push(String::new());
        lines.push("↑/↓ choose · Enter details · Esc close · /subagents cancel <task>".into());
        lines.join("\n")
    }
    pub(super) fn move_by(&mut self, delta: isize) {
        self.selected = self
            .selected
            .saturating_add_signed(delta)
            .min(self.rows.len().saturating_sub(1));
    }
    pub(super) fn resolve_task(&self, value: &str) -> Option<SubagentDigest> {
        if value.len() < 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut matches = self
            .rows
            .keys()
            .filter(|task| digest(**task).starts_with(value));
        let task = matches.next().copied()?;
        matches.next().is_none().then_some(task)
    }
}
impl Row {
    fn report(&mut self, usage: Option<irmind_app::ModelUsage>, cost: Option<u64>) {
        let tokens = usage.and_then(|usage| usage.input_tokens.checked_add(usage.output_tokens));
        if let Some(tokens) = tokens.and_then(|tokens| self.reported_tokens.checked_add(tokens)) {
            self.reported_tokens = tokens;
        } else {
            self.cost_microusd = None;
        }
        self.cost_microusd = self
            .cost_microusd
            .and_then(|total| cost.and_then(|cost| total.checked_add(cost)));
    }
    fn cost(&self, charged: u64) -> String {
        if charged == self.reported_tokens
            && let Some(cost) = self.cost_microusd
        {
            format!(
                "estimated cost at current prices ${}.{:06}",
                cost / 1_000_000,
                cost % 1_000_000
            )
        } else {
            "cost not available".into()
        }
    }
}
pub(super) fn digest(value: SubagentDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    value
        .as_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
            text
        })
}
pub(super) fn label(id: &str) -> &str {
    match id {
        "triage" => "Triage",
        "cloud" => "Cloud",
        "endpoint" => "Endpoint",
        "network" => "Network",
        "kubernetes" => "Kubernetes",
        "threat-intelligence" => "Threat intelligence",
        _ => "Subagent",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::case::{CaseFrame, draw_case};
    use ratatui::{Terminal, backend::TestBackend};
    fn fixture() -> Panel {
        let mut panel = Panel {
            notice: "Plan: two source-restricted synthetic tasks".into(),
            detail: true,
            ..Panel::default()
        };
        panel.rows.insert(
            SubagentDigest::from_bytes([1; 32]),
            Row {
                kind: "endpoint".into(),
                objective: "Review synthetic Windows authentication failures".into(),
                activity: "Partial: sampled evidence; no conclusion of absence".into(),
                summary: "Verified synthetic source only.".into(),
                usage: Some(SubagentResources {
                    tokens: 1200,
                    calls: 3,
                    rounds: 2,
                    cloud_bytes: 0,
                }),
                reported_tokens: 0,
                cost_microusd: None,
            },
        );
        panel.rows.insert(
            SubagentDigest::from_bytes([2; 32]),
            Row {
                kind: "cloud".into(),
                objective: "Review synthetic AWS access".into(),
                activity: "Round 2 · scripted".into(),
                summary: "Synthetic cloud source.".into(),
                usage: None,
                reported_tokens: 0,
                cost_microusd: None,
            },
        );
        panel
    }
    #[test]
    fn subagent_panel_at_eighty_columns_shows_activity_budgets_and_details() {
        let mut panel = fixture();
        let overlay = panel.text();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        draw_case(
            &mut terminal,
            &CaseFrame {
                title: "Synthetic investigation",
                guide: None,
                guide_scroll: 0,
                messages: "",
                visible_lines: None,
                input: "",
                input_focused: false,
                panel: "",
                overlay: Some(&overlay),
                menu: None,
                tab: 0,
                sidebar_visible: false,
                sidebar_scroll: 0,
                overlay_scroll: 0,
                new_content: false,
                model: "scripted",
                tokens: Some(1200),
                cost: "",
                pending: 0,
                detections: 0,
                status: "delegated investigation",
            },
        )
        .unwrap();
        let buffer = terminal.backend().buffer();
        let screen = (0..24)
            .map(|y| {
                (0..80)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            screen.contains("Endpoint")
                && screen.contains("Cloud")
                && screen.contains("1200 tokens")
        );
        insta::assert_snapshot!("subagents_80x24", screen);
        assert_eq!(
            panel.resolve_task("01010101"),
            Some(SubagentDigest::from_bytes([1; 32]))
        );
        assert_eq!(panel.resolve_task("01"), None);
        assert_eq!(panel.resolve_task("/../../"), None);
        panel.move_by(1);
        assert_eq!(panel.selected, 1);
        panel.move_by(1000);
        assert_eq!(panel.selected, 1);
    }
    #[test]
    fn cost_never_treats_missing_provider_usage_as_free() {
        let mut row = Row {
            kind: "triage".into(),
            objective: String::new(),
            activity: String::new(),
            summary: String::new(),
            usage: None,
            reported_tokens: 0,
            cost_microusd: Some(0),
        };
        row.report(
            Some(irmind_app::ModelUsage {
                input_tokens: 2,
                output_tokens: 1,
            }),
            Some(10),
        );
        assert!(row.cost(3).contains("$0.000010"));
        assert_eq!(row.cost(100), "cost not available");
        row.report(None, None);
        row.report(
            Some(irmind_app::ModelUsage {
                input_tokens: 1,
                output_tokens: 1,
            }),
            Some(0),
        );
        assert_eq!(row.cost(5), "cost not available");
    }
}
