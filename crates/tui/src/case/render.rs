mod cards;
mod menu;
mod panels;
use super::conversation::{Card, CardKind};
use super::runtime::CaseRuntime;
use super::{CaseFrame, Result, draw_case, escape_display, summarize_usage};
use cards::audit_card;
use irmind_app::AuditEventKind;
use menu::menu_text;
pub(crate) use panels::{approval_panel, entity_panel};
use panels::{overlay_text, panel_text};

impl CaseRuntime<'_, '_, '_> {
    fn refresh_usage(&mut self) -> Result<()> {
        let last_seq = self.state.entries.last().map_or(0, |entry| entry.seq);
        if last_seq == self.state.usage_cache_seq {
            return Ok(());
        }
        let usage = summarize_usage(&self.state.entries)?;
        self.state.usage_cache_tokens = usage.input_tokens.saturating_add(usage.output_tokens);
        self.state.usage_cache_cost = usage.estimated_cost_microusd.map_or_else(
            || "cost n/a".to_owned(),
            |micro| {
                format!(
                    "cost ${}.{:04}",
                    micro / 1_000_000,
                    (micro % 1_000_000) / 100
                )
            },
        );
        self.state.usage_cache_seq = last_seq;
        self.state.turn_detection_count = self
            .state
            .entries
            .iter()
            .rev()
            .take_while(|entry| entry.kind != AuditEventKind::Prompt)
            .filter(|entry| entry.kind == AuditEventKind::InjectionDetected)
            .count();
        Ok(())
    }

    fn status_text(&self) -> Result<String> {
        let mut status = self.active.as_ref().map_or_else(
            || "idle".into(),
            |(_, _, label)| {
                format!(
                    "{label}: {}s",
                    self.state
                        .running_since
                        .map_or(0, |since| since.elapsed().as_secs())
                )
            },
        );
        if self.overrides_active {
            status = format!("OVR {status}");
        }
        if self.engine.case_scope_exceeds_policy(&self.state.case)? {
            status = format!("SCOPE LIMITED {status}");
        }
        Ok(status)
    }

    fn sync_conversation(&mut self) -> Result<()> {
        for entry in self.state.entries.iter().skip(self.state.audit_cursor) {
            if matches!(
                entry.kind,
                AuditEventKind::Prompt | AuditEventKind::ModelReply
            ) && self
                .state
                .live_reply_cutoff_seq
                .is_some_and(|seq| entry.seq > seq)
            {
                continue;
            }
            if let Some(card) = audit_card(entry, &self.state, self.engine)? {
                self.state.conversation.push(card);
            }
        }
        self.state.audit_cursor = self.state.entries.len();
        if self.active.is_none() {
            self.state.live_reply_cutoff_seq = None;
        }
        if let Some(reply) = self.state.pending_final_reply.take() {
            self.state
                .conversation
                .push(Card::new(CardKind::Model, "IRMind", reply, true));
        }
        for message in std::mem::take(&mut self.state.messages) {
            let visible = self.engine.guard.screen(&message)?.text;
            self.state
                .conversation
                .push(Card::new(CardKind::Notice, "Activity", visible, false));
        }
        for (title, result) in std::mem::take(&mut self.state.graph_results) {
            let visible = self.engine.guard.screen(&result)?.text;
            self.state
                .conversation
                .push(Card::new(CardKind::ToolResult, title, visible, false));
        }
        Ok(())
    }

    pub(super) fn render(&mut self) -> Result<()> {
        self.sync_conversation()?;
        self.refresh_usage()?;
        let panel = if self.state.sidebar_visible {
            panel_text(&self.state)
        } else {
            String::new()
        };
        let title = self.engine.guard.screen(&self.state.case.title)?.text;
        let shown_input = self.engine.guard.screen(&self.state.input)?.text;
        let shown_panel = if self.state.tab == 4 {
            escape_display(&panel)
        } else {
            self.engine.guard.screen(&panel)?.text
        };
        let overlay = overlay_text(&self.state, self.engine)?;
        let menu = menu_text(&self.state, self.modules)
            .map(|content| {
                self.engine
                    .guard
                    .screen(&content)
                    .map(|visible| visible.text)
            })
            .transpose()?;
        let size = self.terminal.size()?;
        let chat_area =
            super::view::conversation_area(size.into(), &shown_input, self.state.sidebar_visible);
        self.state.conversation.set_viewport(
            usize::from(chat_area.width.saturating_sub(2)),
            usize::from(chat_area.height.saturating_sub(2)),
        );
        let visible_lines = self.state.conversation.visible_lines();
        let status = self.status_text()?;
        let model_name = self
            .engine
            .guard
            .screen(
                &self
                    .model
                    .map_or_else(|| "no model".into(), irmind_app::LlmPort::descriptor),
            )?
            .text;
        draw_case(
            self.terminal,
            &CaseFrame {
                id: self.id,
                title: &title,
                messages: "",
                visible_lines: Some(&visible_lines),
                input: &shown_input,
                input_focused: self.state.focus == super::state::Focus::Composer,
                panel: &shown_panel,
                overlay: overlay.as_deref(),
                menu: menu.as_deref(),
                tab: self.state.tab,
                sidebar_visible: self.state.sidebar_visible,
                sidebar_scroll: u16::try_from(self.state.sidebar_scroll).unwrap_or(u16::MAX),
                overlay_scroll: u16::try_from(self.state.overlay_scroll).unwrap_or(u16::MAX),
                new_content: self.state.conversation.has_new_content(),
                model: &model_name,
                tokens: self.state.usage_cache_tokens,
                cost: &self.state.usage_cache_cost,
                pending: self.state.approvals.len(),
                detections: self.state.turn_detection_count,
                status: &status,
            },
        )?;
        Ok(())
    }
}
