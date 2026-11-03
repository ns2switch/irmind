use super::{Effect, script::Action};
use std::time::{Duration, Instant};

enum Phase {
    Ready,
    Typing { command: String, chars: usize },
    Typed(String),
    Waiting,
    Delay,
    Reading,
    Failed,
}
pub(super) struct Tick {
    pub now: Instant,
    pub visibility: Visibility,
    pub completion: Completion,
    pub action: Option<Action>,
    pub reading_time: Duration,
}
pub(super) enum Visibility {
    Hidden,
    Busy,
    Ready,
}
pub(super) enum Completion {
    Pending,
    Complete,
    Final,
}

pub(super) struct Playback {
    automatic: bool,
    advance: bool,
    speed: u8,
    phase: Phase,
    deadline: Instant,
}
impl Playback {
    pub(super) fn new(speed: u8) -> Self {
        Self {
            automatic: true,
            advance: false,
            speed: speed.clamp(1, 50),
            phase: Phase::Ready,
            deadline: Instant::now(),
        }
    }
    pub(super) fn reset(&mut self) {
        self.phase = Phase::Ready;
        self.deadline = Instant::now();
        self.advance = false;
    }
    pub(super) fn pause(&mut self) {
        self.automatic = false;
    }
    pub(super) fn automatic(&self) -> bool {
        self.automatic
    }
    pub(super) fn toggle(&mut self) {
        self.automatic = !self.automatic;
        self.deadline = Instant::now();
    }
    pub(super) fn request_advance(&mut self) {
        self.advance = true;
    }
    pub(super) fn in_flight(&self) -> bool {
        matches!(
            self.phase,
            Phase::Waiting | Phase::Typing { .. } | Phase::Typed(_)
        )
    }
    pub(super) fn failed(&self) -> bool {
        matches!(self.phase, Phase::Failed)
    }
    pub(super) fn fail(&mut self) {
        self.phase = Phase::Failed;
        self.pause();
    }
    pub(super) fn retry(&mut self) {
        self.reset();
        self.advance = true;
    }
    pub(super) fn scaled(&self, millis: u64) -> Duration {
        Duration::from_millis((millis / u64::from(self.speed)).max(1))
    }
    pub(super) fn start_typing(&mut self, command: String) {
        self.phase = Phase::Typing { command, chars: 0 };
        self.deadline = Instant::now();
    }
    pub(super) fn command_sent(&mut self) {
        self.phase = Phase::Waiting;
    }
    pub(super) fn action_finished(&mut self) {
        self.phase = Phase::Ready;
    }
    pub(super) fn tick(&mut self, tick: Tick) -> Effect {
        let Tick {
            now,
            visibility,
            completion,
            action,
            reading_time,
        } = tick;
        if matches!(visibility, Visibility::Hidden) {
            self.deadline = now + reading_time;
            return Effect::None;
        }
        if matches!(visibility, Visibility::Busy)
            || matches!(completion, Completion::Final)
            || self.failed()
        {
            return Effect::None;
        }
        if matches!(self.phase, Phase::Waiting) {
            return Effect::Finished;
        }
        if !(self.automatic || self.advance) {
            return Effect::None;
        }
        if now < self.deadline {
            return Effect::None;
        }
        match &mut self.phase {
            Phase::Ready => match action {
                Some(Action::Command(command)) => Effect::Bind(command),
                Some(Action::Wait(millis)) => {
                    self.phase = Phase::Delay;
                    self.deadline = now + self.scaled(millis);
                    Effect::None
                }
                None if matches!(completion, Completion::Complete) => {
                    self.phase = Phase::Reading;
                    self.deadline = now
                        + if self.advance {
                            Duration::ZERO
                        } else {
                            reading_time
                        };
                    Effect::None
                }
                None => {
                    self.fail();
                    Effect::Error("the expected completion was not observed")
                }
            },
            Phase::Typing { command, chars } => {
                *chars = chars.saturating_add(usize::from(self.speed).saturating_mul(3));
                let prefix = command.chars().take(*chars).collect::<String>();
                if prefix.len() == command.len() {
                    self.phase = Phase::Typed(command.clone());
                }
                self.deadline = now + self.scaled(100);
                Effect::Type(prefix)
            }
            Phase::Typed(command) => Effect::Submit(command.clone()),
            Phase::Delay => Effect::Finished,
            Phase::Reading => Effect::Next,
            Phase::Waiting | Phase::Failed => Effect::None,
        }
    }
}
