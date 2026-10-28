use super::{CaseRuntime, Result};

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn graph_command(&mut self, prompt: &str) -> bool {
        if let Some(rest) = prompt.strip_prefix("/entity ") {
            if let Some((kind, value)) = rest.split_once(' ') {
                self.push_graph(
                    "Entity lookup",
                    self.engine.graph.entity_lookup(self.id, kind, value),
                );
            }
        } else if let Some(rest) = prompt.strip_prefix("/neighbors ") {
            if let Some((kind, value)) = rest.split_once(' ') {
                self.push_graph(
                    "Graph neighbors",
                    self.engine.graph.neighbors(self.id, kind, value, 10),
                );
            }
        } else if let Some(rest) = prompt.strip_prefix("/entity-timeline ") {
            if let Some((kind, value)) = rest.split_once(' ') {
                self.push_graph(
                    "Entity timeline",
                    self.engine.graph.entity_timeline(self.id, kind, value, 10),
                );
            }
        } else if let Some(rest) = prompt.strip_prefix("/path ") {
            let parts = rest.splitn(4, ' ').collect::<Vec<_>>();
            if let [from_kind, from_value, to_kind, to_value] = parts.as_slice() {
                self.push_graph(
                    "Graph path",
                    self.engine.graph.graph_path(
                        self.id,
                        (from_kind, from_value),
                        (to_kind, to_value),
                    ),
                );
            }
        } else if let Some(query) = prompt.strip_prefix("/search ") {
            self.push_graph(
                "Evidence search",
                self.engine.graph.text_search(self.id, query, 10),
            );
        } else if let Some(rest) = prompt.strip_prefix("/raw ") {
            if let Some((hash, index)) = rest.split_once(' ')
                && let Ok(index) = index.parse::<usize>()
            {
                self.push_graph(
                    "Source record",
                    self.engine.graph.raw_record(self.id, hash, index),
                );
            }
        } else {
            return false;
        }
        true
    }

    fn push_graph(&mut self, title: &'static str, result: Result<String, irmind_app::AppError>) {
        match result {
            Ok(result) => self.state.result_cards.push((title, result)),
            Err(error) => self.state.messages.push(format!("Graph error: {error}")),
        }
    }
}
