use super::CaseRuntime;
impl CaseRuntime<'_, '_, '_> {
    pub(super) fn skill_command(&mut self, prompt: &str) -> Option<bool> {
        if prompt != "/skills" && !prompt.starts_with("/skills ") {
            return None;
        }
        match crate::skills::run(
            self.terminal,
            self.engine,
            self.io_ops,
            self.shutdown,
            self.io_ops.demo_mode(),
            prompt,
        ) {
            Ok(crate::skills::ManagerExit::Quit) => {
                self.exit_to = super::super::CaseExit::Quit;
                return Some(true);
            }
            Ok(crate::skills::ManagerExit::Palette) => self.state.palette = Some(String::new()),
            Ok(crate::skills::ManagerExit::Back) => {}
            Err(error) => self
                .state
                .messages
                .push(format!("Skill manager: {error}. Use /skills to retry.")),
        }
        self.state.skill_commands = self.engine.skill_command_metadata().unwrap_or_default();
        Some(false)
    }
}
