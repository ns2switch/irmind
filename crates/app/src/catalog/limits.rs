use super::{CatalogError, MAX_CATALOG_INDEX_BYTES};
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};

pub(super) fn check(bytes: &[u8]) -> Result<(), CatalogError> {
    if bytes.is_empty() || bytes.len() > MAX_CATALOG_INDEX_BYTES {
        return Err(CatalogError::InvalidData);
    }
    let mut remaining = 100_000usize;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    Seed {
        depth: 0,
        remaining: &mut remaining,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| CatalogError::InvalidData)?;
    deserializer.end().map_err(|_| CatalogError::InvalidData)
}
struct Seed<'a> {
    depth: u8,
    remaining: &'a mut usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.depth > 8 {
            return Err(D::Error::custom("catalog depth limit"));
        }
        *self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| D::Error::custom("catalog value limit"))?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded catalog JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values
            .next_element_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        while values
            .next_key_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?
            .is_some()
        {
            values.next_value_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
        }
        Ok(())
    }
}
