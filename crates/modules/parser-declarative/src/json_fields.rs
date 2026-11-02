use crate::{AppError, config::Limits, error};
use serde::Deserializer as _;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub(crate) fn extract(
    text: &str,
    wanted: &BTreeSet<&str>,
    limits: &Limits,
) -> Result<BTreeMap<String, String>, AppError> {
    if text.len() > limits.record_bytes {
        return Err(error("JSON record exceeds size limit"));
    }
    let raw: &RawValue = serde_json::from_str(text).map_err(|_| error("invalid JSON record"))?;
    let mut state = State {
        wanted,
        limits,
        fields: 0,
        values: BTreeMap::new(),
    };
    walk(raw, "", 0, &mut state)?;
    Ok(state.values)
}

struct State<'a> {
    wanted: &'a BTreeSet<&'a str>,
    limits: &'a Limits,
    fields: usize,
    values: BTreeMap<String, String>,
}

impl State<'_> {
    fn field(&mut self) -> Result<(), AppError> {
        self.fields += 1;
        if self.fields > self.limits.fields {
            return Err(error("JSON field limit exceeded"));
        }
        Ok(())
    }
}

fn walk(raw: &RawValue, path: &str, depth: usize, state: &mut State<'_>) -> Result<(), AppError> {
    if depth > state.limits.depth {
        return Err(error("JSON depth limit exceeded"));
    }
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'{') => {
            let mut parser = serde_json::Deserializer::from_str(text);
            parser
                .deserialize_map(MapVisitor { state, path, depth })
                .map_err(|_| error("invalid JSON object or parser limit"))?;
        }
        Some(b'[') => {
            let mut parser = serde_json::Deserializer::from_str(text);
            parser
                .deserialize_seq(ArrayVisitor { state, path, depth })
                .map_err(|_| error("invalid JSON array or parser limit"))?;
        }
        _ if state.wanted.contains(path) && text != "null" => {
            let value = if text.starts_with('"') {
                serde_json::from_str::<String>(text).map_err(|_| error("invalid JSON string"))?
            } else {
                text.to_owned()
            };
            if value.len() > 4096 {
                return Err(error("mapped JSON scalar exceeds 4096 bytes"));
            }
            state.values.insert(path.to_owned(), value);
        }
        _ => {}
    }
    Ok(())
}

struct MapVisitor<'a, 'b> {
    state: &'a mut State<'b>,
    path: &'a str,
    depth: usize,
}
impl<'de> Visitor<'de> for MapVisitor<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded JSON object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.state.field().map_err(serde::de::Error::custom)?;
            if key.len() > 256 || !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("oversized or duplicate JSON key"));
            }
            let path = format!(
                "{}/{}",
                self.path,
                key.replace('~', "~0").replace('/', "~1")
            );
            map.next_value_seed(Node {
                state: self.state,
                path: &path,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

struct ArrayVisitor<'a, 'b> {
    state: &'a mut State<'b>,
    path: &'a str,
    depth: usize,
}
impl<'de> Visitor<'de> for ArrayVisitor<'_, '_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded JSON array")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut array: A) -> Result<(), A::Error> {
        let mut index = 0;
        while let Some(raw) = array.next_element::<&RawValue>()? {
            self.state.field().map_err(serde::de::Error::custom)?;
            let path = format!("{}/{index}", self.path);
            walk(raw, &path, self.depth + 1, self.state).map_err(serde::de::Error::custom)?;
            index += 1;
        }
        Ok(())
    }
}

struct Node<'a, 'b> {
    state: &'a mut State<'b>,
    path: &'a str,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Node<'_, '_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        let raw = <&RawValue as serde::Deserialize>::deserialize(deserializer)?;
        walk(raw, self.path, self.depth, self.state).map_err(serde::de::Error::custom)
    }
}
