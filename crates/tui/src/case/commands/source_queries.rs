use super::CaseRuntime;

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn show_source_query_budget(&mut self) {
        let status = match self.engine.source_query_budget(self.id, self.shutdown) {
            Ok(status) if status.revision != 0 || status.organization.is_some() => status,
            Ok(_) => return,
            Err(error) => {
                self.state.messages.push(error.to_string());
                return;
            }
        };
        let allocation = status.allocation;
        if !allocation.enabled {
            self.state
                .messages
                .push("Source queries are disabled for this case.".into());
            return;
        }
        let scan_cap = allocation
            .scan_bytes
            .map_or_else(|| "unallocated".into(), |cap| cap.to_string());
        self.state.messages.push(format!(
            "Source queries\nBilled scan bytes · {} used · {} reserved · {scan_cap} allocated\nRetained rows · {} used · {} reserved · {} allocated\nRetained bytes · {} used · {} reserved · {} allocated",
            status.used.scan_bytes, status.held.scan_bytes,
            status.used.retained_rows, status.held.retained_rows, allocation.retained_rows,
            status.used.retained_bytes, status.held.retained_bytes, allocation.retained_bytes,
        ));
    }

    pub(super) fn source_query_command(&mut self, prompt: &str) -> bool {
        let Some(args) = prompt.strip_prefix("/source-query") else {
            return false;
        };
        if !args.is_empty() && !args.starts_with(' ') {
            return false;
        }
        let mut parts = args.split_whitespace();
        let (Some(action), Some(plan_id), None) = (parts.next(), parts.next(), parts.next()) else {
            self.state.messages.push(
                "Use /source-query show <plan-id> or /source-query approve <plan-id>.".into(),
            );
            return true;
        };
        if plan_id.len() != 64
            || !plan_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            self.state
                .messages
                .push("Enter the full source-query plan ID.".into());
            return true;
        }
        let engine = self.engine;
        let case = self.id.clone();
        let plan_id = plan_id.to_owned();
        match action {
            "show" => self.start_task("Show source query plan", move |cancel| {
                let plan = engine.source_query_plan_text(&case, &plan_id, &cancel)?;
                Ok(format!(
                    "{plan}\nTo confirm the exact plan, enter /source-query approve {plan_id}."
                ))
            }),
            "approve" => self.start_task("Acquire source query", move |cancel| {
                engine
                    .run_source_query_plan_blocking(
                        &case,
                        &plan_id,
                        "Analyst confirmed the exact source-query plan",
                        &cancel,
                    )
                    .map(|result| result.display_summary())
            }),
            _ => self.state.messages.push(
                "Use /source-query show <plan-id> or /source-query approve <plan-id>.".into(),
            ),
        }
        true
    }
}
