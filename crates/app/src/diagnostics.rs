//! Allowed fields for operational tracing. Evidence, arguments, URLs, and errors never enter here.

use crate::Tool;
use std::time::Duration;

pub(crate) fn tool_started(tool: &Tool) {
    tracing::info!(target: "irmind::operations", tool = tool.as_str(), "tool started");
}

pub(crate) fn tool_finished(tool: &Tool, succeeded: bool, elapsed: Duration) {
    tracing::info!(
        target: "irmind::operations",
        tool = tool.as_str(),
        outcome = if succeeded { "ok" } else { "error" },
        elapsed_ms = elapsed.as_millis(),
        "tool finished"
    );
}

pub(crate) fn model_finished(succeeded: bool, elapsed: Duration) {
    tracing::info!(
        target: "irmind::operations",
        operation = "model_completion",
        outcome = if succeeded { "ok" } else { "error" },
        elapsed_ms = elapsed.as_millis(),
        "model request finished"
    );
}
