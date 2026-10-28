use super::CaseRuntime;
use irmind_app::{ProposedCall, Tool};
use std::collections::BTreeMap;

const USAGE: &str = "Usage: /siem-alert <source> <account> <alert-id> <from-UTC> <to-UTC>";

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn siem_command(&mut self, prompt: &str) -> bool {
        let Some(parsed) = parse_siem_alert(prompt) else {
            return false;
        };
        let Ok(proposal) = parsed else {
            self.state.messages.push(USAGE.into());
            return true;
        };
        let engine = self.engine;
        let id = self.id;
        self.start_task("SIEM alert", move |cancel| {
            engine.request_tool_as_analyst(id, proposal, &cancel)
        });
        true
    }
}

fn parse_siem_alert(prompt: &str) -> Option<Result<ProposedCall, &'static str>> {
    let rest = prompt.strip_prefix("/siem-alert")?;
    if !rest.is_empty() && !rest.starts_with(' ') {
        return None;
    }
    let parts = rest.split_whitespace().collect::<Vec<_>>();
    let [source, account, alert_id, from, to] = parts.as_slice() else {
        return Some(Err(USAGE));
    };
    Some(Ok(ProposedCall {
        tool: Tool::SiemGetAlert,
        args: BTreeMap::from([
            ("source".into(), (*source).into()),
            ("account".into(), (*account).into()),
            ("alert_id".into(), (*alert_id).into()),
            ("from".into(), (*from).into()),
            ("to".into(), (*to).into()),
        ]),
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::parse_siem_alert;

    #[test]
    fn alert_command_requires_exact_five_arguments() {
        assert!(parse_siem_alert("/siem-alertx").is_none());
        assert!(
            parse_siem_alert("/siem-alert source account id")
                .unwrap()
                .is_err()
        );
        let proposal = parse_siem_alert(
            "/siem-alert splunk-prod account-a alert-1 2026-10-23T12:00:00Z 2026-10-23T13:00:00Z",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            proposal.args.get("alert_id").map(String::as_str),
            Some("alert-1")
        );
    }
}
