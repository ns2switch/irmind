//! Bounded, non-custody messages for the Windows network witness.
use std::io;
#[cfg(windows)]
pub(crate) const TICKET: &str = "irmind-network-ticket";
#[cfg(windows)]
pub(crate) const ACK: &str = "irmind-network-ack";
pub(crate) const POLICY: &str = "irmind-windows-containment-v1";
pub(crate) const MAX_MESSAGE: usize = 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ticket {
    pub(crate) witness: bool,
    pub(crate) nonce: [u8; 32],
    pub(crate) sid: Vec<u8>,
    pub(crate) ports: [u16; 2],
}
pub(crate) fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "EVTX network witness could not be verified",
    )
}
fn fields(input: &[u8], count: usize) -> io::Result<Vec<&str>> {
    if input.len() > MAX_MESSAGE
        || !input.ends_with(b"\n")
        || !input.is_ascii()
        || input[..input.len().saturating_sub(1)].contains(&b'\n')
    {
        return Err(denied());
    }
    let text = std::str::from_utf8(input).map_err(|_| denied())?;
    let tokens = text
        .split_ascii_whitespace()
        .take(count + 1)
        .collect::<Vec<_>>();
    if tokens.len() != count {
        return Err(denied());
    }
    Ok(tokens)
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
fn unhex(text: &str) -> io::Result<Vec<u8>> {
    if text.len() > 136 || !text.len().is_multiple_of(2) {
        return Err(denied());
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            fn digit(byte: u8) -> io::Result<u8> {
                match byte {
                    b'0'..=b'9' => Ok(byte - b'0'),
                    b'a'..=b'f' => Ok(byte - b'a' + 10),
                    _ => Err(denied()),
                }
            }
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}
impl Ticket {
    #[cfg(any(feature = "launcher", test, feature = "fuzzing"))]
    pub(crate) fn encode(&self) -> String {
        format!(
            "{POLICY} {} {} {} {} {}\n",
            if self.witness { "witness" } else { "decode" },
            hex(&self.nonce),
            hex(&self.sid),
            self.ports[0],
            self.ports[1]
        )
    }
    pub(crate) fn parse(input: &[u8]) -> io::Result<Self> {
        let tokens = fields(input, 6)?;
        let witness = match tokens[1] {
            "witness" => true,
            "decode" => false,
            _ => return Err(denied()),
        };
        let nonce = unhex(tokens[2])?.try_into().map_err(|_| denied())?;
        let sid = unhex(tokens[3])?;
        if tokens[0] != POLICY
            || sid.len() < 8
            || sid[0] != 1
            || sid[1] > 15
            || sid.len() != 8 + usize::from(sid[1]) * 4
        {
            return Err(denied());
        }
        let ports = ports(tokens[4], tokens[5])?;
        if witness != (ports[0] != 0 && ports[1] != 0) || (!witness && ports != [0, 0]) {
            return Err(denied());
        }
        Ok(Self {
            witness,
            nonce,
            sid,
            ports,
        })
    }
}
fn ports(first: &str, second: &str) -> io::Result<[u16; 2]> {
    Ok([
        first.parse().map_err(|_| denied())?,
        second.parse().map_err(|_| denied())?,
    ])
}
pub(crate) fn ready(nonce: &[u8; 32], ports: [u16; 2]) -> String {
    format!(
        "irmind-network-ready-v1 {} {} {}\n",
        hex(nonce),
        ports[0],
        ports[1]
    )
}
#[cfg(any(feature = "launcher", test, feature = "fuzzing"))]
pub(crate) fn parse_ready(input: &[u8], nonce: &[u8; 32]) -> io::Result<[u16; 2]> {
    let tokens = fields(input, 4)?;
    let ports = ports(tokens[2], tokens[3])?;
    if tokens[0] != "irmind-network-ready-v1" || unhex(tokens[1])? != nonce || ports.contains(&0) {
        return Err(denied());
    }
    Ok(ports)
}
pub(crate) fn receipt(nonce: &[u8; 32], complete: bool) -> String {
    format!(
        "irmind-network-{}-v1 {}\n",
        if complete { "complete" } else { "ack" },
        hex(nonce)
    )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiptFailure {
    Missing,
    TooLong,
    Framing,
    NonAscii,
    UnexpectedMessage,
    NonceEncoding,
    NonceMismatch,
}

impl ReceiptFailure {
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Missing => "receipt missing",
            Self::TooLong => "receipt exceeds the frame limit",
            Self::Framing => "receipt must end with a single newline",
            Self::NonAscii => "receipt contains non-ASCII bytes",
            Self::UnexpectedMessage => "unexpected receipt type or protocol version",
            Self::NonceEncoding => "invalid receipt nonce encoding",
            Self::NonceMismatch => "receipt nonce mismatch",
        }
    }
}

impl std::fmt::Display for ReceiptFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.description())
    }
}

impl std::error::Error for ReceiptFailure {}

pub(crate) fn check_receipt(input: &[u8], nonce: &[u8; 32], complete: bool) -> io::Result<()> {
    let canonical = receipt(nonce, complete);
    if input == canonical.as_bytes() {
        return Ok(());
    }
    let failure = receipt_failure(input, complete);
    Err(io::Error::new(io::ErrorKind::PermissionDenied, failure))
}

fn receipt_failure(input: &[u8], complete: bool) -> ReceiptFailure {
    if input.is_empty() {
        return ReceiptFailure::Missing;
    }
    if input.len() > MAX_MESSAGE {
        return ReceiptFailure::TooLong;
    }
    if !input.is_ascii() {
        return ReceiptFailure::NonAscii;
    }
    let Some(line) = input.strip_suffix(b"\n") else {
        return ReceiptFailure::Framing;
    };
    if line.contains(&b'\n') {
        return ReceiptFailure::Framing;
    }
    let header: &[u8] = if complete {
        b"irmind-network-complete-v1 "
    } else {
        b"irmind-network-ack-v1 "
    };
    let Some(nonce) = line.strip_prefix(header) else {
        return ReceiptFailure::UnexpectedMessage;
    };
    if nonce.len() != 64 || !nonce.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return ReceiptFailure::NonceEncoding;
    }
    ReceiptFailure::NonceMismatch
}
#[cfg(test)]
pub(crate) fn test_nonce() -> [u8; 32] {
    use std::hash::{BuildHasher as _, RandomState};

    // The operating-system RNG remains the only source of production nonces.
    // This fixture needs opaque bytes for comparisons and no additional crate.
    let state = RandomState::new();
    std::array::from_fn(|index| state.hash_one(index).to_le_bytes()[0])
}

#[cfg(test)]
pub(crate) fn mismatched_nonce(mut nonce: [u8; 32]) -> [u8; 32] {
    nonce[0] ^= 1;
    nonce
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn messages_bind_nonce_version_mode_and_strict_bounds() {
        let nonce = test_nonce();
        let wrong_nonce = mismatched_nonce(nonce);
        let ticket = Ticket {
            witness: true,
            nonce,
            sid: vec![1, 0, 0, 0, 0, 0, 0, 5],
            ports: [1234, 2345],
        };
        assert_eq!(Ticket::parse(ticket.encode().as_bytes()).unwrap(), ticket);
        assert!(Ticket::parse(&vec![b'a'; 1025]).is_err());
        assert!(Ticket::parse(ticket.encode().replace("witness", "decode").as_bytes()).is_err());
        assert!(Ticket::parse(ticket.encode().replace(POLICY, "unknown").as_bytes()).is_err());
        assert!(parse_ready(ready(&nonce, [1234, 2345]).as_bytes(), &wrong_nonce).is_err());
        assert!(parse_ready(ready(&nonce, [0, 1]).as_bytes(), &nonce).is_err());
        assert!(check_receipt(receipt(&nonce, false).as_bytes(), &nonce, true).is_err());
        assert!(check_receipt(receipt(&nonce, true).as_bytes(), &wrong_nonce, true).is_err());
    }
    #[test]
    fn receipt_rejections_are_specific_and_keep_exact_byte_admission() {
        let nonce = test_nonce();
        let complete = receipt(&nonce, true);
        let wrong_kind = receipt(&nonce, false);
        let wrong_nonce = receipt(&mismatched_nonce(nonce), true);
        let oversized = vec![b'x'; MAX_MESSAGE + 1];
        for (bytes, expected) in [
            (b"".as_slice(), ReceiptFailure::Missing),
            (&oversized, ReceiptFailure::TooLong),
            (complete.trim_end().as_bytes(), ReceiptFailure::Framing),
            (b"\xff\n", ReceiptFailure::NonAscii),
            (wrong_kind.as_bytes(), ReceiptFailure::UnexpectedMessage),
            (
                b"irmind-network-complete-v1 INVALID\n",
                ReceiptFailure::NonceEncoding,
            ),
            (wrong_nonce.as_bytes(), ReceiptFailure::NonceMismatch),
        ] {
            let error = check_receipt(bytes, &nonce, true).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<ReceiptFailure>()),
                Some(&expected)
            );
        }
        check_receipt(complete.as_bytes(), &nonce, true).unwrap();
    }
}
