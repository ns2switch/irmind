use crate::parquet_store::{AppError, invalid_source};
use irmind_app::common_event::{
    CommonField, EntityIdentityScope, EntityObservation, EntityRole, ObservedEntity,
    ObservedEntityKind, decode_identity_scope,
};
use serde::Deserialize;
use std::borrow::Cow;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(super) struct Node {
    pub(super) kind: String,
    pub(super) value: String,
    pub(super) scope: String,
}
impl Node {
    pub(super) fn checked(
        kind: &str,
        value: &str,
        scope: &str,
        role: u8,
        field: u16,
    ) -> Result<Self, AppError> {
        if kind.len() > 32 || value.is_empty() || value.len() > 512 || scope.len() > 4096 {
            return Err(invalid_source());
        }
        if role == 0 && field == 0 && scope == "legacy-unspecified" {
            return Ok(Self::legacy(kind, value));
        }
        let entity = ObservedEntity::try_new(
            ObservedEntityKind::parse(kind).map_err(|_| invalid_source())?,
            value,
            decode_identity_scope(scope)?,
        )
        .map_err(|_| invalid_source())?;
        if entity.value() != value {
            return Err(invalid_source());
        }
        EntityObservation::try_new(
            entity,
            EntityRole::from_code(u16::from(role)).map_err(|_| invalid_source())?,
            CommonField::from_code(field).map_err(|_| invalid_source())?,
        )
        .map_err(|_| invalid_source())?;
        Ok(Self {
            kind: kind.into(),
            value: value.into(),
            scope: scope.into(),
        })
    }
    pub(super) fn legacy(kind: &str, value: &str) -> Self {
        let global = matches!(kind, "ip" | "domain" | "hash")
            && ObservedEntityKind::parse(kind).ok().is_some_and(|kind| {
                ObservedEntity::try_new(kind, value, EntityIdentityScope::Global).is_ok()
            });
        Self {
            kind: kind.into(),
            value: value.into(),
            scope: if global {
                r#"{"kind":"global"}"#
            } else {
                "legacy-unspecified"
            }
            .into(),
        }
    }
    pub(super) fn matches(&self, kind: &str, value: &str) -> bool {
        self.kind == kind && self.value == value
    }
    pub(super) fn display(&self) -> String {
        format!("{} {} [scope={}]", self.kind, self.value, self.scope)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Peer<'a> {
    #[serde(borrow)]
    pub(super) kind: Cow<'a, str>,
    #[serde(borrow)]
    pub(super) value: Cow<'a, str>,
    #[serde(borrow)]
    pub(super) scope: Cow<'a, str>,
    pub(super) role: u8,
    pub(super) field: u16,
}
impl Peer<'_> {
    pub(super) fn node(&self) -> Result<Node, AppError> {
        Node::checked(&self.kind, &self.value, &self.scope, self.role, self.field)
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScopedNode(<redacted>)")
    }
}
