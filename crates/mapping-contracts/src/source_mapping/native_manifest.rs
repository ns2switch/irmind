//! Strict validation of the committed native mapping inputs. This reads metadata
//! only and never loads or runs the matching binary.
use super::MappingError;

const MAGIC: &[u8] = b"irmind-native-mapping-build-v2\0";
const TARGETS: u8 = 0b0001_1111;
const SIZE_LIMIT: usize = 64 * 1024;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Unit<'a> {
    name: &'a str,
    version: &'a str,
    kind: u8,
    source: &'a str,
    content: &'a [u8],
    context: u8,
    features: Vec<&'a str>,
    effective: &'a [u8],
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], MappingError> {
        let (field, rest) = self.0.split_at_checked(length).ok_or_else(invalid)?;
        self.0 = rest;
        Ok(field)
    }
    fn byte(&mut self, ceiling: u8) -> Result<u8, MappingError> {
        let [value] = self.take(1)? else {
            return Err(invalid());
        };
        (*value <= ceiling).then_some(*value).ok_or_else(invalid)
    }
    fn count(&mut self, ceiling: usize) -> Result<usize, MappingError> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| invalid())?);
        let n = usize::try_from(n).map_err(|_| invalid())?;
        (n <= ceiling).then_some(n).ok_or_else(invalid)
    }
    fn hash(&mut self) -> Result<&'a [u8], MappingError> {
        self.take(32)
    }
    fn text(&mut self) -> Result<&'a str, MappingError> {
        let length = self.count(512)?;
        let value = std::str::from_utf8(self.take(length)?).map_err(|_| invalid())?;
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(invalid());
        }
        Ok(value)
    }
    fn mask(&mut self, applicable: u8) -> Result<u8, MappingError> {
        let n = self.byte(TARGETS)?;
        if n == 0 || n & !applicable != 0 {
            return Err(invalid());
        }
        Ok(n)
    }
    fn unit(&mut self) -> Result<Unit<'a>, MappingError> {
        let name = self.text()?;
        let version = self.text()?;
        let kind = self.byte(2)?;
        let source = self.text()?;
        let content_digest = self.hash()?;
        let context = self.byte(2)?;
        let features = (0..self.count(128)?)
            .map(|_| self.text())
            .collect::<Result<Vec<_>, _>>()?;
        let effective = self.hash()?;
        if !features.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(invalid());
        }
        check_source(kind, source, content_digest)?;
        Ok(Unit {
            name,
            version,
            kind,
            source,
            content: content_digest,
            context,
            features,
            effective,
        })
    }
}

fn portable_path(path: &str) -> bool {
    !path.contains(['\\', ':']) && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn check_source(kind: u8, source: &str, content: &[u8]) -> Result<(), MappingError> {
    if kind == 0 {
        return (portable_path(source) && content == [0; 32])
            .then_some(())
            .ok_or_else(invalid);
    }
    if !source.starts_with("https://") || source.contains(['@', '?']) {
        return Err(invalid());
    }
    if kind == 1 {
        return (!source.contains('#')).then_some(()).ok_or_else(invalid);
    }
    let (_, revision) = source.split_once('#').ok_or_else(invalid)?;
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || crate::sha256(revision.as_bytes()) != content
    {
        return Err(invalid());
    }
    Ok(())
}

fn strictly_after<T: Ord + Copy>(previous: &mut Option<T>, current: T) -> Result<(), MappingError> {
    if previous.is_some_and(|last| last >= current) {
        return Err(invalid());
    }
    *previous = Some(current);
    Ok(())
}

fn read_graph(
    reader: &mut Reader<'_>,
    masks: &[u8],
) -> Result<Vec<Vec<(usize, u8)>>, MappingError> {
    let mut graph = vec![Vec::new(); masks.len()];
    let maximum_index = masks.len().checked_sub(1).ok_or_else(invalid)?;
    let mut previous = None;
    for _ in 0..reader.count(1024)? {
        let parent = reader.count(maximum_index)?;
        let child = reader.count(maximum_index)?;
        let kind = reader.byte(1)?;
        let alias = reader.text()?;
        strictly_after(&mut previous, (parent, child, kind, alias))?;
        let mask = reader.mask(masks[parent] & masks[child])?;
        graph[parent].push((child, mask));
    }
    let mut previous_encoding = None;
    let mut previous_input = None;
    let mut previous_mask = 0;
    for _ in 0..reader.count(1024)? {
        let owner = reader.count(maximum_index)?;
        let kind = reader.byte(1)?;
        let path = reader.text()?;
        let hash = reader.hash()?;
        strictly_after(&mut previous_encoding, (owner, kind, path, hash))?;
        let mask = reader.mask(masks[owner])?;
        if !portable_path(path)
            || (previous_input == Some((owner, kind, path)) && previous_mask & mask != 0)
        {
            return Err(invalid());
        }
        previous_mask = if previous_input == Some((owner, kind, path)) {
            previous_mask | mask
        } else {
            mask
        };
        previous_input = Some((owner, kind, path));
    }
    Ok(graph)
}

fn prove_reachability(
    root: usize,
    graph: &[Vec<(usize, u8)>],
    masks: &[u8],
) -> Result<(), MappingError> {
    for bit in [1, 2, 4, 8, 16] {
        let mut seen = vec![false; masks.len()];
        let mut pending = vec![root];
        while let Some(unit) = pending.pop() {
            if !seen[unit] {
                seen[unit] = true;
                pending.extend(
                    graph[unit]
                        .iter()
                        .filter(|(_, mask)| mask & bit != 0)
                        .map(|(target, _)| *target),
                );
            }
        }
        if seen
            .iter()
            .zip(masks)
            .any(|(visited, mask)| *visited != (mask & bit != 0))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn validate(bytes: &[u8]) -> Result<(), MappingError> {
    let Some(body) = bytes.strip_prefix(MAGIC) else {
        // Existing synthetic, declarative, and development descriptors have
        // their original commitments. This parser recognizes the V2 domain.
        return Ok(());
    };
    if bytes.len() > SIZE_LIMIT {
        return Err(invalid());
    }
    let mut reader = Reader(body);
    reader.text()?;
    reader.hash()?;
    let root = reader.count(255)?;
    let count = reader.count(256)?;
    let mut previous = None;
    let mut masks = Vec::with_capacity(count);
    for index in 0..count {
        let unit = reader.unit()?;
        if index == root && unit.context != 0 {
            return Err(invalid());
        }
        if previous.as_ref().is_some_and(|last| last >= &unit) {
            return Err(invalid());
        }
        previous = Some(unit);
        masks.push(reader.mask(TARGETS)?);
    }
    if masks.get(root) != Some(&TARGETS) {
        return Err(invalid());
    }
    let graph = read_graph(&mut reader, &masks)?;
    if !reader.0.is_empty() {
        return Err(invalid());
    }
    prove_reachability(root, &graph, &masks)
}

const fn invalid() -> MappingError {
    MappingError::InvalidManifest
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_independent_golden_and_rejects_trailing_or_truncated_data() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/development/vectors/native-mapping-manifest-v2.json"
        ))
        .unwrap();
        let mut encoded = hex::decode(fixture["canonical_hex"].as_str().unwrap()).unwrap();
        assert_eq!(crate::hex(&crate::sha256(&encoded)), fixture["sha256"]);
        validate(&encoded).unwrap();
        assert!(validate(&encoded[..encoded.len() - 1]).is_err());
        encoded.push(0);
        assert!(validate(&encoded).is_err());
    }
}
