use super::{
    AppError, CancellationToken, CaseId, GraphQueryFilter, Instant, Node, ParquetArtifact,
    QUERY_DEADLINE, QueryStore, ScanSpec, spec,
};
use crate::parquet_store::query::time_rules;
use crate::parquet_store::scan::{Predicate, ScanFlow};
use crate::parquet_store::time_cell::TimeCell;
use crate::parquet_store::{invalid_source, storage};
use arrow::{
    array::{Array, StringArray, UInt8Array, UInt16Array},
    record_batch::RecordBatch,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[derive(Default)]
struct Group {
    count: u64,
    first: Option<TimeCell>,
    last: Option<TimeCell>,
    checked: BTreeSet<(u8, u16)>,
}
struct View<'a> {
    kind: &'a str,
    value: &'a str,
    count: u64,
    roles: [u64; 9],
    first: Option<TimeCell>,
    last: Option<TimeCell>,
    groups: BTreeMap<String, Group>,
    truncated: bool,
}
impl<'a> View<'a> {
    fn new(kind: &'a str, value: &'a str) -> Self {
        Self {
            kind,
            value,
            count: 0,
            roles: [0; 9],
            first: None,
            last: None,
            groups: BTreeMap::new(),
            truncated: false,
        }
    }
    fn visit(&mut self, batch: &RecordBatch) -> Result<ScanFlow, AppError> {
        let scopes = batch
            .column_by_name("identity_scope")
            .and_then(|v| v.as_any().downcast_ref::<StringArray>())
            .ok_or_else(invalid_source)?;
        let roles = batch
            .column_by_name("entity_role")
            .and_then(|v| v.as_any().downcast_ref::<UInt8Array>())
            .ok_or_else(invalid_source)?;
        let fields = batch
            .column_by_name("entity_field")
            .and_then(|v| v.as_any().downcast_ref::<UInt16Array>())
            .ok_or_else(invalid_source)?;
        if let Some(key) = homogeneous(batch.num_rows(), scopes, roles, fields)
            && self.retains(key.0)
        {
            self.span(batch, key)?;
            self.count += u64::try_from(batch.num_rows()).map_err(storage)?;
            self.include_group_extrema(key.0)?;
            return Ok(ScanFlow::Continue);
        }
        super::super::extrema::accumulate(
            batch,
            &mut self.count,
            &mut self.first,
            &mut self.last,
            None,
        )?;
        let mut start = 0;
        while start < batch.num_rows() {
            if scopes.is_null(start) || roles.is_null(start) || fields.is_null(start) {
                return Err(invalid_source());
            }
            let key = (scopes.value(start), roles.value(start), fields.value(start));
            let mut end = start + 1;
            while end < batch.num_rows()
                && !scopes.is_null(end)
                && !roles.is_null(end)
                && !fields.is_null(end)
                && (scopes.value(end), roles.value(end), fields.value(end)) == key
            {
                end += 1;
            }
            self.span(&batch.slice(start, end - start), key)?;
            start = end;
        }
        Ok(ScanFlow::Continue)
    }
    fn retains(&self, scope: &str) -> bool {
        self.groups.contains_key(scope)
            || self.groups.len() < 20
            || self
                .groups
                .last_key_value()
                .is_some_and(|(last, _)| scope < last.as_str())
    }
    fn include_group_extrema(&mut self, scope: &str) -> Result<(), AppError> {
        let group = self.groups.get(scope).ok_or_else(invalid_source)?;
        if let Some(first) = &group.first
            && self
                .first
                .as_ref()
                .map(|old| first.compare(old, false))
                .transpose()?
                .is_none_or(std::cmp::Ordering::is_lt)
        {
            self.first = Some(first.clone());
        }
        if let Some(last) = &group.last
            && self
                .last
                .as_ref()
                .map(|old| last.compare(old, false))
                .transpose()?
                .is_none_or(std::cmp::Ordering::is_gt)
        {
            self.last = Some(last.clone());
        }
        Ok(())
    }
    fn span(
        &mut self,
        batch: &RecordBatch,
        (scope, role, field): (&str, u8, u16),
    ) -> Result<(), AppError> {
        if role > 8 || (role == 0) != (field == 0) || field > 98 {
            return Err(invalid_source());
        }
        self.roles[usize::from(role)] += u64::try_from(batch.num_rows()).map_err(storage)?;
        if !self.groups.contains_key(scope) {
            if self.groups.len() == 20 {
                self.truncated = true;
                let last = self.groups.last_key_value().ok_or_else(invalid_source)?.0;
                if scope >= last.as_str() {
                    return Ok(());
                }
                self.groups.pop_last();
            }
            self.groups.insert(scope.into(), Group::default());
        }
        let group = self.groups.get_mut(scope).ok_or_else(invalid_source)?;
        if group.checked.insert((role, field)) {
            Node::checked(self.kind, self.value, scope, role, field)?;
        }
        super::super::extrema::accumulate(
            batch,
            &mut group.count,
            &mut group.first,
            &mut group.last,
            None,
        )
    }
    fn output(self) -> Result<String, AppError> {
        let mut output = format!(
            "{} {}: observations={}; first={}; last={}; role counts:",
            self.kind,
            self.value,
            self.count,
            self.first.map_or_else(String::new, |v| v.display()),
            self.last.map_or_else(String::new, |v| v.display())
        );
        for (code, count) in self
            .roles
            .into_iter()
            .enumerate()
            .filter(|(_, count)| *count > 0)
        {
            let role = if code == 0 {
                "unspecified"
            } else {
                irmind_app::common_event::EntityRole::from_code(
                    u16::try_from(code).map_err(storage)?,
                )
                .map_err(|_| invalid_source())?
                .as_str()
            };
            write!(output, " {role}={count}").map_err(storage)?;
        }
        for (scope, group) in self.groups {
            write!(
                output,
                "\nscope={scope}: observations={}; first={}; last={}",
                group.count,
                group.first.map_or_else(String::new, |v| v.display()),
                group.last.map_or_else(String::new, |v| v.display())
            )
            .map_err(storage)?;
        }
        if self.truncated {
            output.push_str("\nPartial scope details: first 20 identities shown; additional scopes are omitted.");
        }
        Ok(output)
    }
}
fn homogeneous<'a>(
    count: usize,
    scopes: &'a StringArray,
    roles: &UInt8Array,
    fields: &UInt16Array,
) -> Option<(&'a str, u8, u16)> {
    if count == 0 || scopes.is_null(0) || roles.is_null(0) || fields.is_null(0) {
        return None;
    }
    let key = (scopes.value(0), roles.value(0), fields.value(0));
    (1..count)
        .all(|row| {
            !scopes.is_null(row)
                && !roles.is_null(row)
                && !fields.is_null(row)
                && (scopes.value(row), roles.value(row), fields.value(row)) == key
        })
        .then_some(key)
}
impl QueryStore<'_> {
    pub(in crate::parquet_store::query) fn scoped_entity(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifact],
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let mut rules = time_rules(filter);
        rules.extend([
            Predicate::Equal("entity_kind", kind.into()),
            Predicate::Equal("entity_value", value.into()),
        ]);
        let mut view = View::new(kind, value);
        let status = self.scan_artifacts(
            ScanSpec {
                schema: "irmind-entities-v1",
                columns: &[
                    "event_time",
                    "identity_scope",
                    "entity_role",
                    "entity_field",
                ],
                predicates: &rules,
                ..spec(
                    id,
                    artifacts,
                    filter,
                    cancel,
                    Instant::now() + QUERY_DEADLINE,
                )
            },
            |batch| {
                let _aggregate = self.store.profile.as_ref().map(|profile| {
                    profile.query_timer(crate::parquet_store::profile::QueryPhase::Aggregate)
                });
                view.visit(batch)
            },
        )?;
        super::super::complete(status)?;
        view.output()
    }
}
