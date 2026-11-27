use serde_json::Value;
use std::io;

pub(crate) const MAX_DEPTH: usize = 16;
pub(crate) const MAX_NODES: usize = 4096;

pub(crate) fn encode(value: &mut Value) -> io::Result<Vec<u8>> {
    let mut nodes = 0;
    sort(value, 1, &mut nodes)?;
    serde_json::to_vec(value).map_err(|_| invalid())
}

fn sort(value: &mut Value, depth: usize, nodes: &mut usize) -> io::Result<()> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(invalid());
    }
    match value {
        Value::Array(array) => {
            for item in array {
                sort(item, depth + 1, nodes)?;
            }
        }
        Value::Object(object) => {
            object.sort_keys();
            for item in object.values_mut() {
                sort(item, depth + 1, nodes)?;
            }
        }
        Value::Number(number) if number.as_u64().is_none() => return Err(invalid()),
        _ => (),
    }
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid bounded canonical JSON")
}
