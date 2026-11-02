use super::CaseRuntime;
impl CaseRuntime<'_, '_, '_> {
    pub(super) fn parser_exit_requested(&self) -> bool {
        matches!(
            self.exit_to,
            super::super::CaseExit::Restart | super::super::CaseExit::Quit
        )
    }
    pub(super) fn parser_command(&mut self, prompt: &str) -> bool {
        if prompt != "/parsers" && !prompt.starts_with("/parsers ") {
            return false;
        }
        if self.io_ops.demo_mode() {
            self.state
                .messages
                .push("Leave the demo before managing custom parser definitions.".into());
            return true;
        }
        match crate::parsers::run(
            self.terminal,
            self.engine,
            self.io_ops,
            self.shutdown,
            prompt,
        ) {
            Ok(crate::parsers::ManagerExit::Restart) => {
                self.exit_to = super::super::CaseExit::Restart;
            }
            Ok(crate::parsers::ManagerExit::Quit) => self.exit_to = super::super::CaseExit::Quit,
            Ok(crate::parsers::ManagerExit::Back) => {}
            Ok(crate::parsers::ManagerExit::Palette) => self.state.palette = Some(String::new()),
            Err(error) => self
                .state
                .messages
                .push(format!("Parser manager: {error}. Use /parsers to retry.")),
        }
        true
    }
}
