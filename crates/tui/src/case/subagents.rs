mod feed;
mod panel;
mod review;
use super::conversation::{Card, CardKind, Conversation};
use crossterm::event::KeyCode;
use irmind_app::subagents::{AnalystPlanMailbox, EngineEventKind};
use irmind_app::{CancellationToken, CaseId, Engine};
use std::thread::Scope;

pub(super) struct SubagentUi<'scope, 'env> {
    feed: Option<feed::EventFeed<'scope>>,
    mailbox: Option<&'env AnalystPlanMailbox>,
    review: Option<review::Review>,
    panel: panel::Panel,
    event_failure: bool,
}
impl<'scope, 'env> SubagentUi<'scope, 'env> {
    pub(super) fn new(
        scope: &'scope Scope<'scope, 'env>,
        engine: &Engine<'_>,
        case: &CaseId,
        shutdown: &CancellationToken,
        mailbox: Option<&'env AnalystPlanMailbox>,
    ) -> Self {
        Self {
            feed: feed::EventFeed::start(scope, engine, case, shutdown),
            mailbox,
            review: None,
            panel: panel::Panel::default(),
            event_failure: false,
        }
    }
    pub(super) fn tick(
        &mut self,
        engine: &Engine<'_>,
        case: &CaseId,
        conversation: &mut Conversation,
    ) -> anyhow::Result<()> {
        if self
            .review
            .as_ref()
            .is_some_and(|review| !review.request.is_active())
        {
            self.review = None;
        }
        if self.review.is_none()
            && let Some(mailbox) = self.mailbox
            && let Some(request) = mailbox.take_review(case)?
        {
            self.review = Some(review::Review::new(request));
        }
        let Some(feed) = &self.feed else {
            return Ok(());
        };
        for _ in 0..16 {
            let batch = match feed.receiver.try_recv() {
                Ok(batch) => batch,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if !self.event_failure {
                        conversation.push(Card::new(CardKind::Notice, "Subagents", "The subagent activity feed stopped. Stop the turn and run /verify before continuing.", false));
                        self.event_failure = true;
                    }
                    break;
                }
            };
            let batch = match batch {
                Ok(batch) => batch,
                Err(error) => {
                    self.event_failure = true;
                    let error = engine.guard.screen(&error)?.text;
                    conversation.push(Card::new(CardKind::Notice, "Subagents", format!("Subagent activity could not be verified: {error}. Stop the turn and run /verify."), false));
                    break;
                }
            };
            for event in batch.events {
                self.panel.accept(&event);
                let kind = match event.kind {
                    EngineEventKind::PlanPreview | EngineEventKind::ConsentRequired => {
                        CardKind::Notice
                    }
                    EngineEventKind::Message => CardKind::Model,
                    EngineEventKind::ToolProposal => CardKind::Proposal,
                    EngineEventKind::ToolResult => CardKind::ToolResult,
                    EngineEventKind::Status => CardKind::Notice,
                    _ => continue,
                };
                let name = event.task_type.as_deref().map_or("Subagents", panel::label);
                conversation.push(Card::new(kind, name, event.payload, true));
            }
        }
        Ok(())
    }
    pub(super) fn overlay(&self) -> Option<String> {
        self.review
            .as_ref()
            .map(review::Review::text)
            .or_else(|| self.panel.visible.then(|| self.panel.text()))
    }
    pub(super) fn rendered(&mut self) {
        if let Some(review) = &mut self.review {
            review.displayed = true;
        }
    }
    pub(super) fn automatic_start(&mut self) -> anyhow::Result<()> {
        if self.review.as_ref().is_some_and(|review| {
            review.displayed && !review.request.preview().confirmation_required()
        }) {
            let review = self
                .review
                .take()
                .ok_or_else(|| anyhow::anyhow!("Plan review expired"))?;
            review.request.automatic_start()?;
        }
        Ok(())
    }
    pub(super) fn key(
        &mut self,
        code: KeyCode,
        scroll: &mut usize,
        input_empty: bool,
    ) -> anyhow::Result<bool> {
        if (self.review.is_some() || self.panel.visible)
            && matches!(code, KeyCode::PageUp | KeyCode::PageDown)
        {
            *scroll = scroll.saturating_add_signed(if code == KeyCode::PageUp { -10 } else { 10 });
            return Ok(true);
        }
        if let Some(review) = &mut self.review {
            if let Some(start) = review.key(code) {
                let review = self
                    .review
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("Plan review expired"))?;
                if start {
                    review.request.start()?;
                } else {
                    review.request.cancel()?;
                }
            }
            return Ok(true);
        }
        if self.panel.visible && input_empty {
            match code {
                KeyCode::Esc => self.panel.visible = false,
                KeyCode::Up => self.panel.move_by(-1),
                KeyCode::Down => self.panel.move_by(1),
                KeyCode::Enter => self.panel.detail = !self.panel.detail,
                _ => return Ok(false),
            }
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn paste(&mut self, value: &str) -> bool {
        if let Some(review) = &mut self.review {
            review.paste(value);
            true
        } else {
            false
        }
    }
    pub(super) fn command(
        &mut self,
        prompt: &str,
        engine: &Engine<'_>,
        case: &CaseId,
        messages: &mut Vec<String>,
    ) -> bool {
        if prompt == "/subagents" {
            self.panel.visible = true;
            return true;
        }
        let Some(value) = prompt.strip_prefix("/subagents ") else {
            return false;
        };
        let Some(value) = value.strip_prefix("cancel ") else {
            messages.push("Use /subagents or /subagents cancel <task>.".into());
            return true;
        };
        let Some(task) = self.panel.resolve_task(value.trim()) else {
            messages.push(
                "Choose a unique task identifier shown in /subagents (at least 8 characters)."
                    .into(),
            );
            return true;
        };
        messages.push(match engine.cancel_live_subagent_task(case, task) {
            Ok(true) => {
                "Cancellation requested; completed work and incurred usage will be retained.".into()
            }
            Ok(false) => "This task is no longer active; its signed result is retained.".into(),
            Err(error) => format!("Task cancellation could not be requested: {error}"),
        });
        true
    }
}
