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
pub(crate) fn check_receipt(input: &[u8], nonce: &[u8; 32], complete: bool) -> io::Result<()> {
    if input != receipt(nonce, complete).as_bytes() {
        return Err(denied());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn messages_bind_nonce_version_mode_and_strict_bounds() {
        let ticket = Ticket {
            witness: true,
            nonce: [7; 32],
            sid: vec![1, 0, 0, 0, 0, 0, 0, 5],
            ports: [1234, 2345],
        };
        assert_eq!(Ticket::parse(ticket.encode().as_bytes()).unwrap(), ticket);
        assert!(Ticket::parse(&vec![b'a'; 1025]).is_err());
        assert!(Ticket::parse(ticket.encode().replace("witness", "decode").as_bytes()).is_err());
        assert!(Ticket::parse(ticket.encode().replace(POLICY, "unknown").as_bytes()).is_err());
        assert!(parse_ready(ready(&[1; 32], [1234, 2345]).as_bytes(), &[2; 32]).is_err());
        assert!(parse_ready(ready(&[1; 32], [0, 1]).as_bytes(), &[1; 32]).is_err());
        assert!(check_receipt(receipt(&[1; 32], false).as_bytes(), &[1; 32], true).is_err());
        assert!(check_receipt(receipt(&[1; 32], true).as_bytes(), &[2; 32], true).is_err());
    }
}
