//! Optional ordering of native frame locators before projection.
use super::{SourceFileInput, SourceInput, SourceRecordV1};
use crate::AppError;
use irmind_domain::{IndexedTime, Tainted};

/// Private scheduling metadata. The frame span is not an event byte offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactRecordLocator {
    pub time: IndexedTime,
    pub index: u64,
    pub frame_start: u64,
    pub frame_len: u32,
    pub frame_hash: [u8; 32],
    pub tuple: u32,
}

pub trait CompactSourceOrdering: Send + Sync {
    /// Emit a contiguous accepted-record index for eligible sources. False
    /// discards the entire plan and leaves all decoding to the normal path.
    fn scan(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(CompactRecordLocator) -> Result<(), AppError>,
    ) -> Result<bool, AppError>;

    fn replay<'a>(&self, input: SourceFileInput<'a>) -> Box<dyn CompactSourceReplay + 'a>;
}

pub trait CompactSourceReplay {
    fn read(&mut self, locator: CompactRecordLocator) -> Result<Tainted<SourceRecordV1>, AppError>;
}
