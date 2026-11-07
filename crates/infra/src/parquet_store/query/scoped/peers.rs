//! Decode sparse typed peers and the unchanged legacy projection together.
use super::Node;
use super::node::Peer;
use crate::parquet_store::query::text;
use crate::parquet_store::{AppError, invalid_source, storage};
use arrow::record_batch::RecordBatch;
use std::{borrow::Cow, collections::BTreeSet};

pub(super) fn read_peers(batch: &RecordBatch, row: usize) -> Result<Vec<Node>, AppError> {
    let legacy = text(batch, "co_entities", row)?;
    let typed = if batch.column_by_name("co_observations").is_some() {
        Some(text(batch, "co_observations", row)?)
    } else {
        None
    };
    decode(legacy, typed)
}

fn decode(legacy: &str, typed: Option<&str>) -> Result<Vec<Node>, AppError> {
    if legacy
        .len()
        .checked_add(typed.map_or(0, str::len))
        .is_none_or(|bytes| bytes > 64 * 1024 * 1024)
    {
        return Err(invalid_source());
    }
    let descriptors: Vec<Peer<'_>> = typed
        .map(serde_json::from_str)
        .transpose()
        .map_err(storage)?
        .unwrap_or_default();
    // Validate every descriptor before considering a legacy fallback. A complete
    // descriptor list remains readable; it is never replaced around an error.
    let mut nodes = descriptors
        .iter()
        .map(Peer::node)
        .collect::<Result<BTreeSet<_>, _>>()?;
    let represented = descriptors
        .iter()
        .filter(|peer| peer.role != 0)
        .map(|peer| (peer.kind.as_ref(), peer.value.as_ref()))
        .collect::<BTreeSet<_>>();
    let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> = serde_json::from_str(legacy).map_err(storage)?;
    for (kind, value) in pairs {
        if !represented.contains(&(kind.as_ref(), value.as_ref())) {
            nodes.insert(if typed.is_some() {
                Node::checked(&kind, &value, "legacy-unspecified", 0, 0)?
            } else {
                Node::legacy(&kind, &value)
            });
        }
    }
    Ok(nodes.into_iter().collect())
}

#[cfg(test)]
mod tests;
