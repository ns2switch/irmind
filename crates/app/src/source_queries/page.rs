//! Validation of retained provider pages before signing their capture metadata.
use super::{
    CaptureColumn, CapturePageCompleteness, CapturePageMetadata, QUERY_MAX_RECORD_BYTES,
    QUERY_MAX_ROWS, SourceQueryError,
};
use crate::{AppError, CancellationToken, SourceDecoder};
use std::io::{Read, Seek};

/// A page is inspected from its complete, bounded case spool. Seek is needed
/// when a provider can send its schema after the rows.
pub trait QueryPageInput: Read + Seek {}
impl<T: Read + Seek> QueryPageInput for T {}

/// Optional alongside the executor. Implementations must interpret one page
/// under the same bounds and row rules as their versioned capture decoder.
pub trait SourceQueryPageDecoder: SourceDecoder {
    fn inspect_page(
        &self,
        input: &mut dyn QueryPageInput,
        ordinal: u64,
        prior: Option<&QueryPageSchema>,
        cancel: &CancellationToken,
    ) -> Result<InspectedQueryPage, AppError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPageSchema {
    columns: Vec<CaptureColumn>,
    /// Provider-specific nested schema, in canonical order where applicable.
    native: Vec<u8>,
}

impl QueryPageSchema {
    pub fn new(columns: Vec<CaptureColumn>, native: Vec<u8>) -> Result<Self, SourceQueryError> {
        let mut names = std::collections::BTreeSet::new();
        if columns.is_empty()
            || columns.len() > 1024
            || native.len() > QUERY_MAX_RECORD_BYTES
            || columns.iter().any(|column| {
                !super::types::text(&column.name, 256)
                    || !super::types::text(&column.native_type, 128)
                    || !names.insert(column.name.as_str())
            })
        {
            return Err(SourceQueryError::Invalid);
        }
        Ok(Self { columns, native })
    }

    pub fn columns(&self) -> &[CaptureColumn] {
        &self.columns
    }

    pub fn native(&self) -> &[u8] {
        &self.native
    }
}

pub struct InspectedQueryPage {
    pub schema: QueryPageSchema,
    pub rows: u64,
    pub rejected: u64,
    pub provider_partial: bool,
    /// Total rows when the protocol reports one.
    pub total_rows: Option<u64>,
    /// A token read from the page in its native protocol, not from query data.
    pub next_token: Option<String>,
}

#[derive(Clone, Default)]
pub(crate) struct QueryPageSequence {
    schema: Option<QueryPageSchema>,
    rows: u64,
    rejected: u64,
    partial: bool,
    expected_rows: Option<u64>,
}

impl QueryPageSequence {
    pub(crate) fn schema(&self) -> Option<&QueryPageSchema> {
        self.schema.as_ref()
    }

    pub(crate) const fn counts(&self) -> (u64, u64, bool) {
        (self.rows, self.rejected, self.partial)
    }

    pub(crate) fn accept(
        &mut self,
        page: InspectedQueryPage,
        remaining_rows: u64,
    ) -> Result<CapturePageMetadata, SourceQueryError> {
        if self
            .schema
            .as_ref()
            .is_some_and(|known| *known != page.schema)
        {
            return Err(SourceQueryError::PageSchemaChanged);
        }
        if page.rows > remaining_rows || page.rows > QUERY_MAX_ROWS || page.rejected > page.rows {
            return Err(SourceQueryError::Limit);
        }
        let rows = self
            .rows
            .checked_add(page.rows)
            .ok_or(SourceQueryError::Limit)?;
        let rejected = self
            .rejected
            .checked_add(page.rejected)
            .ok_or(SourceQueryError::Limit)?;
        let expected = self.expected_rows.or(page.total_rows);
        let partial = page.provider_partial
            || self
                .expected_rows
                .zip(page.total_rows)
                .is_some_and(|(first, current)| first != current)
            || expected.is_some_and(|expected| {
                rows > expected || (page.next_token.is_none() && rows != expected)
            });
        let columns = page.schema.columns.clone();
        self.schema.get_or_insert(page.schema);
        self.rows = rows;
        self.rejected = rejected;
        self.partial |= partial;
        self.expected_rows = expected;
        Ok(CapturePageMetadata {
            columns,
            rows: page.rows,
            completeness: if partial {
                CapturePageCompleteness::ProviderPartial
            } else {
                CapturePageCompleteness::Complete
            },
        })
    }
}
