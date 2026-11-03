use anyhow::Result;
use std::fmt::Write as _;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
mod playback;
mod script;
pub(super) enum Effect {
    None,
    Bind(String),
    Type(String),
    Submit(String),
    Finished,
    Next,
    Error(&'static str),
}
use script::Step;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum DemoEvent {
    ScopeViewed,
    EvidenceIngested,
    TimelineViewed,
    TermSearched,
    NeighborsViewed,
    QuestionAnswered,
    ApprovalResolved,
    FindingResolved,
    Checked,
    CustodyVerified,
    Sealed,
    Exported,
    ExportVerified,
}

pub(super) struct DemoGuide {
    step: usize,
    hidden: bool,
    seen: BTreeSet<DemoEvent>,
    parser: Option<(String, u8)>,
    note: String,
    steps: Vec<Step>,
    playback: playback::Playback,
    progress: [usize; 10],
    pub final_option: usize,
    pub show_real_case_help: bool,
}

impl DemoGuide {
    pub(super) fn new() -> Result<Self> {
        Self::with_speed(1)
    }
    pub(super) fn with_speed(speed: u8) -> Result<Self> {
        Ok(Self {
            step: 0,
            hidden: false,
            seen: BTreeSet::new(),
            parser: None,
            note: String::new(),
            steps: script::load()?,
            playback: playback::Playback::new(speed),
            progress: [0; 10],
            final_option: 0,
            show_real_case_help: false,
        })
    }
    pub(super) fn step(&self) -> usize {
        self.step
    }
    pub(super) fn hidden(&self) -> bool {
        self.hidden
    }
    pub(super) fn active(&self) -> bool {
        !self.hidden
    }
    pub(super) fn record(&mut self, event: DemoEvent) {
        self.seen.insert(event);
    }
    pub(super) fn record_ingest(&mut self, parser: &str, confidence: u8) {
        self.parser = Some((parser.into(), confidence));
        self.record(DemoEvent::EvidenceIngested);
    }
    pub(super) fn completed(&self) -> bool {
        self.progress[self.step] >= self.steps[self.step].actions.len()
            && self.steps[self.step]
                .requires
                .iter()
                .all(|event| self.seen.contains(event))
    }
    pub(super) fn next(&mut self) {
        if self.completed() && self.step < 9 {
            self.step += 1;
            self.playback.reset();
            self.note.clear();
        } else if !self.completed() {
            self.playback.request_advance();
        }
    }
    pub(super) fn back(&mut self) {
        if !self.playback.in_flight() {
            self.step = self.step.saturating_sub(1);
            self.playback.reset();
            self.playback.pause();
            self.note.clear();
        }
    }
    pub(super) fn skip(&mut self) {
        self.next();
    }
    pub(super) fn hide(&mut self) {
        self.hidden = true;
        self.playback.pause();
    }
    pub(super) fn show(&mut self) {
        self.hidden = false;
        self.playback.reset();
    }
    pub(super) fn hint(&mut self) {
        self.show();
    }
    pub(super) fn pause_or_resume(&mut self) {
        self.playback.toggle();
    }
    pub(super) fn fail(&mut self, text: &str) {
        if !self.playback.in_flight() && !self.completed() {
            self.progress[self.step] = self.progress[self.step].saturating_sub(1);
        }
        self.note = format!("Presentation stopped: {text}. Enter retries; Esc exits.");
        self.playback.fail();
    }
    pub(super) fn enter(&mut self) {
        self.note.clear();
        if self.playback.failed() {
            self.playback.retry();
        } else {
            self.next();
        }
    }
    pub(super) fn tick(&mut self, now: Instant, busy: bool, visible: bool) -> Effect {
        if self.hidden {
            return Effect::None;
        }
        let completed = self.completed();
        self.playback.tick(playback::Tick {
            now,
            visibility: if !visible {
                playback::Visibility::Hidden
            } else if busy {
                playback::Visibility::Busy
            } else {
                playback::Visibility::Ready
            },
            completion: if self.step == 9 {
                playback::Completion::Final
            } else if completed {
                playback::Completion::Complete
            } else {
                playback::Completion::Pending
            },
            action: self.steps[self.step]
                .actions
                .get(self.progress[self.step])
                .cloned(),
            reading_time: self.reading_time(),
        })
    }
    pub(super) fn start_typing(&mut self, command: String) {
        self.playback.start_typing(command);
    }
    pub(super) fn command_sent(&mut self) {
        self.playback.command_sent();
    }
    pub(super) fn action_finished(&mut self) {
        self.progress[self.step] += 1;
        self.playback.action_finished();
    }
    pub(super) fn scaled(&self, millis: u64) -> Duration {
        self.playback.scaled(millis)
    }
    fn reading_time(&self) -> Duration {
        let words = self.steps[self.step].narration.split_whitespace().count() as u64;
        self.scaled((words * 1_000 / 3).max(6_000))
    }
    pub(super) fn panel(&self, _approval: Option<&str>, _finding: Option<&str>) -> Option<String> {
        if self.hidden {
            return None;
        }
        let current = &self.steps[self.step];
        let mut text = format!(
            "Step {} of 10 · {}\n\n{}",
            self.step + 1,
            current.title,
            current.narration
        );
        if self.step == 2
            && let Some((parser, confidence)) = &self.parser
        {
            let _ = write!(
                text,
                "\nEvidence ready: {parser} · {confidence}% confidence"
            );
        }
        if self.step == 9 {
            if self.show_real_case_help {
                text.push_str(
                    "\nExit demo, run irmind, then /new, /ingest and /settings. Enter returns.",
                );
            } else {
                for (index, choice) in [
                    "Explore this demo case (sealed, read-only)",
                    "Start your own case",
                    "Exit",
                ]
                .iter()
                .enumerate()
                {
                    let _ = write!(
                        text,
                        "\n{} {}. {choice}",
                        if index == self.final_option {
                            "›"
                        } else {
                            " "
                        },
                        index + 1
                    );
                }
            }
        }
        if !self.note.is_empty() {
            text.push('\n');
            text.push_str(&self.note);
        }
        text.push_str(if self.playback.automatic() {
            "\nAuto playing"
        } else {
            "\nPaused"
        });
        text.push_str(" · Enter next · Backspace previous · Space pause/play · Esc exit");
        Some(text)
    }
}

#[cfg(test)]
mod tests;
