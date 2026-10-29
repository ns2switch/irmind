use super::super::Confirmation;
use super::CaseRuntime;
use irmind_app::{ObjectEntry, ProposedCall, Tool};
use std::collections::BTreeMap;

const LIST_USAGE: &str =
    "Usage: /objects <source> <s3|gs|az> <bucket-or-container> <prefix> <from-UTC> <to-UTC>";

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn objects_command(&mut self, prompt: &str) -> bool {
        if let Some(rest) = prompt.strip_prefix("/objects ") {
            return self.list_objects(rest);
        }
        if let Some(rest) = prompt.strip_prefix("/object-read ") {
            return self.read_object(rest);
        }
        if prompt == "/objects" || prompt == "/object-read" {
            self.state.messages.push(
                if prompt == "/objects" {
                    LIST_USAGE
                } else {
                    "Usage: /object-read <number> [--copy-original]"
                }
                .into(),
            );
            return true;
        }
        false
    }

    fn list_objects(&mut self, input: &str) -> bool {
        let parts = input.split_whitespace().collect::<Vec<_>>();
        let [source, scheme, container, prefix, from, to] = parts.as_slice() else {
            self.state.messages.push(LIST_USAGE.into());
            return true;
        };
        let proposal = ProposedCall {
            tool: Tool::ObjectList,
            args: BTreeMap::from([
                ("source".into(), (*source).into()),
                ("scheme".into(), (*scheme).into()),
                ("container".into(), (*container).into()),
                ("prefix".into(), (*prefix).into()),
                ("from".into(), (*from).into()),
                ("to".into(), (*to).into()),
                ("limit".into(), "20".into()),
            ]),
        };
        self.state.object_listing.clear();
        self.state.object_listing_source = Some((*source).into());
        self.state.object_listing_window = Some(((*from).into(), (*to).into()));
        self.state.object_listing_after_seq =
            self.state.entries.last().map_or(0, |entry| entry.seq);
        let engine = self.engine;
        let id = self.id;
        self.start_task("Cloud objects", move |cancel| {
            engine.request_tool_as_analyst(id, proposal, &cancel)
        });
        true
    }

    fn read_object(&mut self, input: &str) -> bool {
        let (copy_original, index_text) = input
            .trim()
            .strip_suffix(" --copy-original")
            .map_or((false, input.trim()), |value| (true, value));
        let Ok(index) = index_text.parse::<usize>() else {
            self.state
                .messages
                .push("Usage: /object-read <number> [--copy-original]".into());
            return true;
        };
        let Some(item) = index
            .checked_sub(1)
            .and_then(|at| self.state.object_listing.get(at))
            .cloned()
        else {
            self.state
                .messages
                .push("Select a number from a complete /objects listing".into());
            return true;
        };
        let Some(source) = self.state.object_listing_source.clone() else {
            return true;
        };
        let Some((from, to)) = self.state.object_listing_window.clone() else {
            return true;
        };
        let command = format!(
            "/object-read {index}{}",
            if copy_original {
                " --copy-original"
            } else {
                ""
            }
        );
        if !matches!(self.state.confirmed_action.as_ref(), Some(Confirmation::ObjectRead(approved, _)) if approved == &command)
        {
            let summary = format!(
                "Read cloud object?\n{}\nEstimated transfer: {} bytes\nVersion: {}\n{}\n1. Cancel  2. Confirm (↑/↓, Enter, or number then Enter)",
                item.uri,
                item.size,
                item.version.as_deref().unwrap_or("ETag-bound"),
                if copy_original {
                    "An explicit local copy will be kept and signed."
                } else {
                    "The source and hash will be signed; the original remains in cloud storage."
                }
            );
            self.state.confirmation_option = 0;
            self.state.confirmation = Some(Confirmation::ObjectRead(command, summary));
            return true;
        }
        self.state.confirmed_action = None;
        let Some(mut proposal) = read_proposal(&source, &from, &to, &item) else {
            self.state
                .messages
                .push("The selected object has no version or ETag".into());
            return true;
        };
        if copy_original {
            proposal.args.insert("copy_original".into(), "true".into());
        }
        let engine = self.engine;
        let id = self.id;
        self.start_task("Cloud object", move |cancel| {
            engine.request_tool_as_analyst(id, proposal, &cancel)
        });
        true
    }

    pub(in crate::case) fn capture_object_listing(&mut self) -> anyhow::Result<()> {
        let entries = self.engine.audit_log.entries(self.id)?;
        let hash = entries
            .iter()
            .rev()
            .find(|entry| {
                entry.seq > self.state.object_listing_after_seq
                    && entry.kind == irmind_app::AuditEventKind::ToolResult
                    && entry.payload.ends_with("from object_list")
            })
            .and_then(|entry| entry.evidence.as_deref());
        let Some(hash) = hash else {
            anyhow::bail!("no new signed object listing");
        };
        let raw = self.engine.evidence_store.get_evidence(self.id, hash)?;
        let listing: serde_json::Value = serde_json::from_slice(&raw)?;
        let source = listing.get("source").and_then(serde_json::Value::as_str);
        if source != self.state.object_listing_source.as_deref() {
            return Ok(());
        }
        let truncated = listing
            .get("truncated")
            .and_then(serde_json::Value::as_bool)
            != Some(false);
        let objects: Vec<ObjectEntry> =
            serde_json::from_value(listing.get("objects").cloned().unwrap_or_default())?;
        let total = listing
            .get("total_bytes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let mut lines = vec![format!(
            "{} objects · estimated {} bytes{}",
            objects.len(),
            total,
            if truncated {
                " · listing truncated: narrow the prefix"
            } else {
                ""
            }
        )];
        for (index, item) in objects.iter().enumerate() {
            lines.push(format!(
                "{}. {} · {} bytes · {}",
                index + 1,
                item.key.chars().take(120).collect::<String>(),
                item.size,
                item.version.as_deref().unwrap_or("ETag-bound")
            ));
        }
        if !truncated {
            self.state.object_listing = objects;
        }
        let visible = self.engine.guard.screen(&lines.join("\n"))?.text;
        self.state.result_cards.push(("Cloud objects", visible));
        Ok(())
    }
}

fn read_proposal(source: &str, from: &str, to: &str, item: &ObjectEntry) -> Option<ProposedCall> {
    let (scheme, rest) = item.uri.split_once("://")?;
    let (container, key) = rest.split_once('/')?;
    let mut args = BTreeMap::from([
        ("source".into(), source.into()),
        ("scheme".into(), scheme.into()),
        ("container".into(), container.into()),
        ("key".into(), key.into()),
        ("from".into(), from.into()),
        ("to".into(), to.into()),
        ("max_bytes".into(), item.size.to_string()),
    ]);
    if let Some(version) = &item.version {
        args.insert("version".into(), version.clone());
    } else if let Some(etag) = item
        .provider_checksum
        .as_deref()
        .and_then(|value| value.strip_prefix("etag:"))
    {
        args.insert("etag".into(), etag.into());
    } else {
        return None;
    }
    Some(ProposedCall {
        tool: Tool::ObjectRead,
        args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn listed_object_becomes_bounded_versioned_request() {
        let entry = ObjectEntry {
            uri: "gs://audit/2026/a.json".into(),
            key: "2026/a.json".into(),
            size: 42,
            modified_unix_seconds: Some(1),
            version: Some("generation-1".into()),
            provider_checksum: None,
        };
        let proposal = read_proposal(
            "gcs",
            "2026-10-23T00:00:00Z",
            "2026-10-24T00:00:00Z",
            &entry,
        )
        .unwrap();
        assert_eq!(
            proposal.args.get("version").map(String::as_str),
            Some("generation-1")
        );
        assert_eq!(
            proposal.args.get("max_bytes").map(String::as_str),
            Some("42")
        );
    }
}
