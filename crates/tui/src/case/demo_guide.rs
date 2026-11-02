use std::collections::BTreeSet;

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
}

impl DemoGuide {
    pub(super) fn new() -> Self {
        Self {
            step: 0,
            hidden: false,
            seen: BTreeSet::new(),
            parser: None,
            note: String::new(),
        }
    }

    pub(super) fn step(&self) -> usize {
        self.step
    }

    #[cfg(test)]
    pub(super) fn hidden(&self) -> bool {
        self.hidden
    }

    pub(super) fn record(&mut self, event: DemoEvent) {
        self.seen.insert(event);
        if self.completed() && self.step < 9 {
            self.note = "Step complete. Use /demo next when ready.".into();
        }
    }

    pub(super) fn record_ingest(&mut self, parser: &str, confidence: u8) {
        self.parser = Some((parser.to_owned(), confidence));
        self.record(DemoEvent::EvidenceIngested);
    }

    pub(super) fn next(&mut self) {
        if self.step == 9 {
            self.note = "The tutorial is complete. Use /demo exit to leave.".into();
        } else if self.completed() {
            self.step += 1;
            self.hidden = false;
            self.note.clear();
        } else {
            self.note = "Complete this step, or use /demo skip to move on.".into();
        }
    }

    pub(super) fn back(&mut self) {
        self.step = self.step.saturating_sub(1);
        self.hidden = false;
        self.note.clear();
    }

    pub(super) fn skip(&mut self) {
        if self.step < 9 {
            self.step += 1;
        }
        self.hidden = false;
        self.note = "Step skipped. You can return with /demo back.".into();
    }

    pub(super) fn hide(&mut self) {
        self.hidden = true;
    }

    pub(super) fn show(&mut self) {
        self.hidden = false;
    }

    pub(super) fn hint(&mut self) {
        self.note = match self.step {
            0 => "No setup is needed. This session uses only bundled synthetic data.",
            1 => "The signed case scope is visible with /scope.",
            2 => "Wait for the ingest result; it names the parser and confidence.",
            3 => "Run the commands shown in the guide, one at a time.",
            4 => "Ask about the synthetic IAM events in your own words.",
            5 => "Open /approvals to inspect the exact arguments before deciding.",
            6 => "Use /findings to see the proposed hypothesis and its evidence.",
            7 => "Only confirmed findings count toward the local check.",
            8 => "Verify before sealing, then export and check the package with the analyst key.",
            _ => "Use /new and /settings outside this temporary demo.",
        }
        .into();
        self.hidden = false;
    }

    fn completed(&self) -> bool {
        let has = |event| self.seen.contains(&event);
        match self.step {
            1 => has(DemoEvent::ScopeViewed),
            2 => has(DemoEvent::EvidenceIngested),
            3 => {
                has(DemoEvent::TimelineViewed)
                    && has(DemoEvent::TermSearched)
                    && has(DemoEvent::NeighborsViewed)
            }
            4 => has(DemoEvent::QuestionAnswered),
            5 => has(DemoEvent::ApprovalResolved),
            6 => has(DemoEvent::FindingResolved),
            7 => has(DemoEvent::Checked),
            8 => {
                has(DemoEvent::CustodyVerified)
                    && has(DemoEvent::Sealed)
                    && has(DemoEvent::Exported)
                    && has(DemoEvent::ExportVerified)
            }
            _ => true,
        }
    }

    fn instruction(&self, approval: Option<&str>, finding: Option<&str>) -> String {
        match self.step {
            0 => "/demo next — begin the guided tour".into(),
            1 => "/scope — inspect the signed case boundary".into(),
            2 => self.parser.as_ref().map_or_else(
                || "Wait for ingest, then /demo next".into(),
                |(parser, confidence)| format!("{parser} · {confidence}% confidence · /demo next"),
            ),
            3 if !self.seen.contains(&DemoEvent::TimelineViewed) => "/timeline".into(),
            3 if !self.seen.contains(&DemoEvent::TermSearched) => "/search 203.0.113.77".into(),
            3 => "/neighbors ip 203.0.113.77".into(),
            4 => "What happened in this synthetic AWS IAM episode?".into(),
            5 => approval.map_or_else(
                || "/approvals — inspect the pending request".into(),
                |id| format!("/approve {id} — or /deny <id> <reason>"),
            ),
            6 => finding.map_or_else(
                || "/findings — inspect the proposed hypothesis".into(),
                |id| format!("/confirm {id} or /dismiss {id} <reason>"),
            ),
            7 => "/demo check".into(),
            8 if !self.seen.contains(&DemoEvent::CustodyVerified) => "/verify".into(),
            8 if !self.seen.contains(&DemoEvent::Sealed) => "/seal".into(),
            8 if !self.seen.contains(&DemoEvent::Exported) => "/export".into(),
            8 => "/verify-export — check the package with the expected key".into(),
            _ => "/demo exit — then try /new and /settings".into(),
        }
    }

    pub(super) fn panel(&self, approval: Option<&str>, finding: Option<&str>) -> Option<String> {
        if self.hidden {
            return None;
        }
        let (title, reason) = match self.step {
            0 => (
                "Welcome",
                "IRMind signs each action. This demo stays local and is deleted on exit.",
            ),
            1 => (
                "The case",
                "The case is a signed record with a fixed scope.",
            ),
            2 => (
                "Evidence",
                "The signed manifest links the original to a parser; it is not copied by default.",
            ),
            3 => (
                "Explore",
                "Local graph queries help you inspect evidence without a model.",
            ),
            4 => (
                "Ask the agent",
                "The model may propose tools, but policy decides what runs.",
            ),
            5 => (
                "Approval",
                "External enrichment waits for your signed decision.",
            ),
            6 => (
                "Findings",
                "Reports count only findings you confirm with evidence.",
            ),
            7 => (
                "Demo check",
                "Expected answers are read locally only for this comparison.",
            ),
            8 => (
                "Custody",
                "Verify the chain, seal the case, export it, then verify the package.",
            ),
            _ => (
                "Next steps",
                "Create a case and configure a model when you are ready.",
            ),
        };
        let mut text = format!(
            "Demo {}/10 · {title}\nDo: {}\nWhy: {reason}",
            self.step + 1,
            self.instruction(approval, finding),
        );
        if !self.note.is_empty() {
            text.push('\n');
            text.push_str(&self.note);
        }
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use super::{DemoEvent, DemoGuide};

    #[test]
    fn unrelated_actions_never_advance_the_guide() {
        let mut guide = DemoGuide::new();
        guide.record(DemoEvent::QuestionAnswered);
        assert_eq!(guide.step(), 0);
        guide.next();
        assert_eq!(guide.step(), 1);
        guide.next();
        assert_eq!(guide.step(), 1);
        guide.record(DemoEvent::ScopeViewed);
        guide.next();
        assert_eq!(guide.step(), 2);
    }

    #[test]
    fn exploring_requires_all_three_local_queries() {
        let mut guide = DemoGuide::new();
        guide.skip();
        guide.skip();
        guide.skip();
        guide.record(DemoEvent::TimelineViewed);
        guide.record(DemoEvent::TermSearched);
        guide.next();
        assert_eq!(guide.step(), 3);
        guide.record(DemoEvent::NeighborsViewed);
        guide.next();
        assert_eq!(guide.step(), 4);
    }

    #[test]
    fn hint_and_visibility_preserve_progress() {
        let mut guide = DemoGuide::new();
        guide.hide();
        assert!(guide.panel(None, None).is_none());
        guide.hint();
        assert!(!guide.hidden());
        assert!(
            guide
                .panel(None, None)
                .is_some_and(|panel| panel.contains("Demo 1/10"))
        );
        guide.next();
        guide.back();
        assert_eq!(guide.step(), 0);
    }
}
