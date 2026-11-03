use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

pub(super) fn hex(bytes: &str, limit: usize) -> Option<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > limit || !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| {
                char::from(byte)
                    .to_digit(16)
                    .and_then(|value| u8::try_from(value).ok())
            };
            Some(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}
pub(super) fn text(value: &str, quoted: bool) -> Cow<'_, str> {
    if !quoted
        && let Some(bytes) = hex(value, 8192)
        && let Ok(decoded) = String::from_utf8(bytes)
    {
        return Cow::Owned(decoded);
    }
    Cow::Borrowed(value)
}
pub(super) fn socket(value: &str) -> Option<(String, String)> {
    let bytes = hex(value, 256)?;
    let family: [u8; 2] = bytes.get(..2)?.try_into().ok()?;
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?).to_string();
    let ip = match family {
        [2, 0] | [0, 2] => Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(4..8)?).ok()?).to_string(),
        [10, 0] | [0, 10] => {
            Ipv6Addr::from(<[u8; 16]>::try_from(bytes.get(8..24)?).ok()?).to_string()
        }
        _ => return None,
    };
    Some((ip, port))
}
