use super::{CaseRuntime, Result};
use crate::case::demo_guide::DemoEvent;
use irmind_app::{AppError, CaseId, EvidenceGraph, GraphQueryFilter};

enum GraphAction {
    Query(String, String, GraphQueryFilter),
    Timeline(GraphQueryFilter),
    Raw(String, usize),
}

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn graph_command(&mut self, prompt: &str) -> bool {
        let (command, rest) = prompt.split_once(' ').unwrap_or((prompt, ""));
        let title = match command {
            "/timeline" => "Case timeline",
            "/entity" => "Entity lookup",
            "/neighbors" => "Graph neighbors",
            "/entity-timeline" => "Entity timeline",
            "/path" => "Graph path",
            "/search" => "Evidence search",
            "/raw" => "Source record",
            _ => return false,
        };
        let action = if command == "/timeline" {
            parse_graph_options(rest, false).map(|(_, filter)| GraphAction::Timeline(filter))
        } else if command == "/raw" {
            rest.split_once(' ')
                .and_then(|(hash, index)| {
                    index
                        .parse::<usize>()
                        .ok()
                        .map(|index| GraphAction::Raw(hash.to_owned(), index))
                })
                .ok_or_else(invalid_graph_arguments)
        } else {
            parse_graph_input(rest)
                .map(|(query, filter)| GraphAction::Query(command.to_owned(), query, filter))
        };
        match action {
            Ok(action) => {
                if self.state.demo_guide.is_some() {
                    self.state.demo_pending_event = match (command, rest.trim()) {
                        ("/timeline", "") => Some(DemoEvent::TimelineViewed),
                        ("/search", "203.0.113.77") => Some(DemoEvent::TermSearched),
                        ("/neighbors", "ip 203.0.113.77") => Some(DemoEvent::NeighborsViewed),
                        _ => None,
                    };
                }
                let graph = self.engine.graph.clone();
                let id = self.id.clone();
                let repo = self.engine.repo.clone();
                let ceiling = self.engine.policy.scope.clone();
                self.start_task(title, move |cancel| {
                    if cancel.is_cancelled() {
                        return Err(AppError::Cancelled);
                    }
                    let scope = irmind_app::CaseScope::parse(&repo.get_case(&id)?.scope)
                        .map_err(|_| invalid_graph_arguments())?;
                    validate_scope(&action, &scope, ceiling.as_ref())?;
                    let result = run_graph_action(graph.as_ref(), &id, &action)?;
                    if cancel.is_cancelled() {
                        Err(AppError::Cancelled)
                    } else {
                        Ok(result)
                    }
                });
            }
            Err(error) => self.state.messages.push(format!("Graph error: {error}")),
        }
        true
    }
}

fn run_graph_action(
    graph: &dyn EvidenceGraph,
    id: &CaseId,
    action: &GraphAction,
) -> Result<String, AppError> {
    match action {
        GraphAction::Timeline(filter) => {
            let events = graph.timeline_filtered(id, filter, 100)?;
            if events.is_empty() {
                return Ok(filter.coverage_notice().map_or_else(
                    || "No timeline events in the selected partitions".into(),
                    |notice| {
                        format!(
                            "{notice}\nNo matching classified events in the selected partitions"
                        )
                    },
                ));
            }
            let output = events
                .into_iter()
                .map(|event| {
                    format!(
                        "{} {} source={}#{}",
                        event.at, event.event, event.evidence_hash, event.record_index
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            Ok(match filter.coverage_notice() {
                Some(notice) => format!("{notice}\n{output}"),
                None => output,
            })
        }
        GraphAction::Raw(hash, index) => graph.raw_record(id, hash, *index),
        GraphAction::Query(command, query, filter) => match command.as_str() {
            "/search" => graph.text_search_filtered(id, filter, query, 10),
            "/entity" | "/neighbors" | "/entity-timeline" => {
                let (kind, value) = query.split_once(' ').ok_or_else(invalid_graph_arguments)?;
                match command.as_str() {
                    "/entity" => graph.entity_lookup_filtered(id, filter, kind, value),
                    "/neighbors" => graph.neighbors_filtered(id, filter, kind, value, 10),
                    _ => graph.entity_timeline_filtered(id, filter, kind, value, 10),
                }
            }
            "/path" => {
                let parts = query.splitn(4, ' ').collect::<Vec<_>>();
                let [from_kind, from_value, to_kind, to_value] = parts.as_slice() else {
                    return Err(invalid_graph_arguments());
                };
                graph.graph_path_filtered(id, filter, (from_kind, from_value), (to_kind, to_value))
            }
            _ => Err(invalid_graph_arguments()),
        },
    }
}

fn parse_graph_input(input: &str) -> Result<(String, GraphQueryFilter), AppError> {
    parse_graph_options(input, true)
}

fn parse_graph_options(
    input: &str,
    require_query: bool,
) -> Result<(String, GraphQueryFilter), AppError> {
    let mut args = std::collections::BTreeMap::new();
    let mut query = Vec::new();
    for token in input.split_whitespace() {
        if let Some(option) = token.strip_prefix("--") {
            let (name, value) = option.split_once('=').ok_or_else(invalid_graph_arguments)?;
            let name = name.replace('-', "_");
            if !GraphQueryFilter::ARGUMENTS.contains(&name.as_str())
                || value.is_empty()
                || args.insert(name, value.into()).is_some()
            {
                return Err(invalid_graph_arguments());
            }
        } else {
            query.push(token);
        }
    }
    if query.is_empty() == require_query {
        return Err(invalid_graph_arguments());
    }
    let filter = GraphQueryFilter::from_args(&args).map_err(|_| invalid_graph_arguments())?;
    Ok((query.join(" "), filter))
}

fn invalid_graph_arguments() -> AppError {
    AppError::Policy("invalid graph command arguments or partition filter".into())
}

fn validate_scope(
    action: &GraphAction,
    scope: &irmind_app::CaseScope,
    ceiling: Option<&irmind_app::CaseScope>,
) -> Result<(), AppError> {
    let filter = match action {
        GraphAction::Query(_, _, f) | GraphAction::Timeline(f) => f,
        GraphAction::Raw(..) => return Ok(()),
    };
    if !filter.within_scope(scope) || ceiling.is_some_and(|s| !filter.within_scope(s)) {
        return Err(invalid_graph_arguments());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn graph_command_filter_parses_without_leaking_into_search_term() {
        let (query, filter) = parse_graph_input(
            "AssumeRole --from=2026-10-28T12:00:00Z --to=2026-10-28T13:00:00Z --account=123456789012 --region=eu-west-1",
        )
        .unwrap();
        assert_eq!(query, "AssumeRole");
        assert_eq!(filter.account_or_project(), Some("123456789012"));
        assert_eq!(filter.region(), Some("eu-west-1"));
        assert!(parse_graph_input("AssumeRole --region=eu-west-1 --region=us-east-1").is_err());
        assert!(parse_graph_options("", false).is_ok());
        assert!(parse_graph_options("--region=eu-west-1", false).is_ok());
        assert!(parse_graph_options("unexpected", false).is_err());
        let (text, typed) = parse_graph_input(
            "Login --event-category=authentication --event-outcome=failure --entity-role=actor",
        )
        .unwrap();
        assert_eq!(text, "Login");
        assert_eq!(
            typed.common().outcome,
            Some(irmind_app::common_event::EventOutcome::Failure)
        );
        assert!(parse_graph_input("Login --event-outcome=maybe").is_err());
        assert!(parse_graph_input("Login --entity-role=actor --entity-role=target").is_err());
    }
}
