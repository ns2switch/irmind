//! Fixed witness diagnostics. Child-controlled output is never copied into logs.
use std::io;
#[cfg(feature = "launcher")]
use {crate::witness_protocol::ReceiptFailure, std::io::Read as _, std::sync::mpsc::SyncSender};

pub(super) const CHILD_TICKET: &str = "witness ticket or local containment check failed";
pub(super) const CHILD_BIND: &str = "witness listener bind failed";
pub(super) const CHILD_OUTBOUND: &str = "witness outbound probe was not denied";
pub(super) const CHILD_READY_WRITE: &str = "witness ready flush failed";
pub(super) const CHILD_ACK_LISTENER: &str = "witness listener check failed while waiting for ack";
pub(super) const CHILD_ACK_TIMEOUT: &str = "witness ack deadline expired";
pub(super) const CHILD_ACK_READ: &str = "witness ack read failed";
pub(super) const CHILD_FINAL_LISTENER: &str = "witness listener check failed before completion";
pub(super) const CHILD_COMPLETE_WRITE: &str = "witness completion flush failed";

pub(super) fn child_failure(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(feature = "launcher")]
const MAX_PREFIX: usize = 1024;
#[cfg(feature = "launcher")]
const MAX_DRAIN: u64 = 65_536;
#[cfg(feature = "launcher")]
const FAILURE_PREFIX: &[u8] = b"EVTX decoding or containment failed: ";

#[cfg(feature = "launcher")]
pub(super) fn drain_stderr(reader: impl io::Read, report: &SyncSender<String>) {
    let mut bounded = reader.take(MAX_DRAIN);
    let mut prefix = Vec::new();
    let read_failed = bounded
        .by_ref()
        .take(MAX_PREFIX as u64)
        .read_to_end(&mut prefix)
        .is_err();
    let _ = report.send(stderr_summary(&prefix, read_failed));
    let _ = io::copy(&mut bounded, &mut io::sink());
}

#[cfg(feature = "launcher")]
fn stderr_summary(bytes: &[u8], read_failed: bool) -> String {
    let allowed = [
        CHILD_TICKET,
        CHILD_BIND,
        CHILD_OUTBOUND,
        CHILD_READY_WRITE,
        CHILD_ACK_LISTENER,
        CHILD_ACK_TIMEOUT,
        CHILD_ACK_READ,
        CHILD_FINAL_LISTENER,
        CHILD_COMPLETE_WRITE,
        ReceiptFailure::Missing.description(),
        ReceiptFailure::TooLong.description(),
        ReceiptFailure::Framing.description(),
        ReceiptFailure::NonAscii.description(),
        ReceiptFailure::UnexpectedMessage.description(),
        ReceiptFailure::NonceEncoding.description(),
        ReceiptFailure::NonceMismatch.description(),
        "EVTX network witness could not be verified",
        "EVTX thread network witness failed",
    ];
    let mut recognized = Vec::new();
    let mut omitted = !bytes.is_empty() && !bytes.ends_with(b"\n");
    let complete = &bytes[..bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |i| i + 1)];
    for line in complete
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if recognized.len() == 4 {
            omitted = true;
            break;
        }
        if line == b"EVTX decoder failed" {
            recognized.push("EVTX decoder failed");
        } else if let Some(message) = line
            .strip_prefix(FAILURE_PREFIX)
            .and_then(|value| allowed.into_iter().find(|fixed| value == fixed.as_bytes()))
        {
            recognized.push(message);
        } else {
            omitted = true;
        }
    }
    if omitted {
        recognized.push("unrecognized stderr omitted");
    }
    if bytes.len() == MAX_PREFIX {
        recognized.push("stderr prefix limit reached");
    }
    if read_failed {
        recognized.push("stderr read failed");
    }
    if recognized.is_empty() {
        "empty".into()
    } else {
        recognized.join("; ")
    }
}

#[cfg(feature = "launcher")]
#[derive(Clone, Copy, Debug)]
pub(super) enum FrameFailure {
    Missing,
    TooLong,
    Read,
    Deadline,
    Disconnected,
}

#[cfg(feature = "launcher")]
impl std::fmt::Display for FrameFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Missing => "expected frame absent at stdout EOF",
            Self::TooLong => "stdout frame exceeds the frame limit",
            Self::Read => "stdout frame read failed",
            Self::Deadline => "expected frame absent at the read deadline",
            Self::Disconnected => "stdout reader disconnected before the expected frame",
        })
    }
}

#[cfg(feature = "launcher")]
impl std::error::Error for FrameFailure {}

#[cfg(feature = "launcher")]
impl FrameFailure {
    pub(super) fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, self)
    }
}

#[cfg(all(feature = "launcher", test))]
mod tests {
    use super::*;

    #[test]
    fn stderr_keeps_fixed_diagnostics_and_omits_arbitrary_bytes() {
        let stderr = b"EVTX decoding or containment failed: witness ack deadline expired\r\n\x1b[2J sensitive value\n";
        assert_eq!(
            stderr_summary(stderr, false),
            "witness ack deadline expired; unrecognized stderr omitted"
        );
        assert_eq!(stderr_summary(b"", false), "empty");
        assert_eq!(
            stderr_summary(&vec![b'x'; MAX_PREFIX], true),
            "unrecognized stderr omitted; stderr prefix limit reached; stderr read failed"
        );
    }
}
