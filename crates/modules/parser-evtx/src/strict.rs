use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct Seed<'a> {
    left: &'a mut usize,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > 64 || *self.left == 0 {
            return Err(de::Error::custom("EVTX JSON complexity limit"));
        }
        *self.left -= 1;
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded EVTX JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if key.len() > 512 || out.contains_key(&key) {
                return Err(de::Error::custom("invalid or duplicate EVTX key"));
            }
            let value = input.next_value_seed(Seed {
                left: self.left,
                depth: self.depth + 1,
            })?;
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(value) = input.next_element_seed(Seed {
            left: self.left,
            depth: self.depth + 1,
        })? {
            out.push(value);
        }
        Ok(Value::Array(out))
    }
}
pub(super) fn decode(bytes: &[u8]) -> Result<Value, irmind_app::AppError> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(super::bad("EVTX frame exceeds 4 MiB"));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed {
        left: &mut 16384,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| super::bad("invalid, duplicate or excessively nested EVTX JSON"))?;
    decoder
        .end()
        .map_err(|_| super::bad("trailing EVTX JSON bytes"))?;
    Ok(value)
}
