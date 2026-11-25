//! Bounded in-memory reading of a hash-pinned, single-volume ZIP32 release.
use super::{LocalSigmaPack, MAX_PACK_BYTES, check_cancel};
use irmind_app::{AppError, CancellationToken, sha256, v10_proofs::SigmaPackManifestV1};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
};
use zip::{CompressionMethod, ZipArchive};

const MAX_ENTRIES: usize = 8192;
const MAX_ENTRY_BYTES: u64 = 1024 * 1024;
const MAX_RATIO: u64 = 128;
const FOOTER: usize = 22;
const CENTRAL_HEADER: usize = 46;
const LOCAL_HEADER: usize = 30;

pub fn inspect_sigmahq_archive(
    input: &[u8],
    expected_sha256: [u8; 32],
    selection: &SigmaPackManifestV1,
    cancel: &CancellationToken,
) -> Result<LocalSigmaPack, AppError> {
    check_cancel(cancel)?;
    if input.len() as u64 > MAX_PACK_BYTES || sha256(input) != expected_sha256 {
        return Err(invalid("archive size or SHA-256"));
    }
    selection.encode().map_err(|_| invalid("rule selection"))?;
    let expected = selection
        .0
        .iter()
        .enumerate()
        .map(|(index, item)| (item.path.as_str(), (index, item)))
        .collect::<BTreeMap<_, _>>();
    let count = validate_zip32_directory(input, cancel)?;
    let mut archive =
        ZipArchive::new(Cursor::new(input)).map_err(|_| invalid("ZIP32 directory"))?;
    if archive.len() != count || archive.has_duplicate_names() || !archive.comment().is_empty() {
        return Err(invalid("duplicate names or invalid directory"));
    }
    archive
        .validate_header_consistency()
        .map_err(|_| invalid("inconsistent or overlapping ZIP headers"))?;
    let mut unique = BTreeSet::new();
    let mut found = vec![None; selection.0.len()];
    let mut remaining = MAX_PACK_BYTES;
    for index in 0..count {
        check_cancel(cancel)?;
        let entry = archive
            .by_index_raw(index)
            .map_err(|_| invalid("unsupported entry"))?;
        let name = member_name(&entry)?;
        if !unique.insert(name.to_ascii_lowercase()) {
            return Err(invalid("duplicate or case-aliased entry name"));
        }
        let selected = expected.get(name).copied();
        if entry.is_dir() {
            if entry.size() != 0
                || entry.compressed_size() != 0
                || entry.crc32() != 0
                || entry.compression() != CompressionMethod::Stored
                || selected.is_some()
            {
                return Err(invalid("directory with data"));
            }
            continue;
        }
        let expected_size = entry.size();
        validate_sizes(&entry, remaining)?;
        if selected.is_some_and(|(_, rule)| rule.size != expected_size) {
            return Err(invalid("selected rule size"));
        }
        let mut body = selected.map(|_| Vec::new());
        read_member(input, &entry, &mut body, cancel)?;
        remaining = remaining
            .checked_sub(expected_size)
            .ok_or_else(|| invalid("decoded archive size"))?;
        if let Some(((slot, rule), bytes)) = selected.zip(body) {
            super::validate_manifest_rule(rule, &bytes)
                .map_err(|_| invalid("rule selection SHA-256 or metadata"))?;
            found[slot] = Some(bytes);
        }
    }
    let rules = found
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| invalid("selected rule is missing"))?;
    Ok(LocalSigmaPack {
        manifest: selection.clone(),
        rules,
    })
}

fn member_name<'a, R: std::io::Read>(
    entry: &'a zip::read::ZipFile<'_, R>,
) -> Result<&'a str, AppError> {
    if entry.encrypted()
        || entry.is_symlink()
        || !entry.comment_raw().is_empty()
        || !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        )
        || entry
            .unix_mode()
            .is_some_and(|mode| !matches!(mode & 0o170_000, 0 | 0o040_000 | 0o100_000))
    {
        return Err(invalid("entry type, encryption or compression"));
    }
    canonical_name(entry.name_raw(), entry.is_dir())
}

fn validate_sizes<R: std::io::Read>(
    entry: &zip::read::ZipFile<'_, R>,
    remaining: u64,
) -> Result<(), AppError> {
    let compressed = entry.compressed_size();
    let limit = MAX_ENTRY_BYTES.min(remaining).min(
        compressed
            .checked_mul(MAX_RATIO)
            .ok_or_else(|| invalid("compression ratio"))?,
    );
    if entry.size() > limit
        || (entry.compression() == CompressionMethod::Stored && entry.size() != compressed)
    {
        return Err(invalid("entry size or compression ratio"));
    }
    Ok(())
}

fn read_member<R: std::io::Read>(
    input: &[u8],
    entry: &zip::read::ZipFile<'_, R>,
    body: &mut Option<Vec<u8>>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    let invalid_range = || invalid("member byte range");
    let start = entry
        .data_start()
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(invalid_range)?;
    let length = usize::try_from(entry.compressed_size()).map_err(|_| invalid_range())?;
    let end = start.checked_add(length).ok_or_else(invalid_range)?;
    let compressed = input.get(start..end).ok_or_else(invalid_range)?;
    let expected_size = entry.size();
    let mut crc = flate2::Crc::new();
    if entry.compression() == CompressionMethod::Stored {
        for block in compressed.chunks(16 * 1024) {
            check_cancel(cancel)?;
            transfer(block, &mut crc, body);
        }
    } else {
        inflate_member(compressed, expected_size, &mut crc, body, cancel)?;
    }
    if u64::from(crc.amount()) != expected_size {
        return Err(invalid("decoded entry size differs from its headers"));
    }
    if crc.sum() != entry.crc32() {
        return Err(invalid("entry CRC"));
    }
    Ok(())
}

fn inflate_member(
    mut compressed: &[u8],
    limit: u64,
    crc: &mut flate2::Crc,
    body: &mut Option<Vec<u8>>,
    cancel: &CancellationToken,
) -> Result<(), AppError> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut decoder = Decompress::new(false);
    let mut buffer = [0; 16 * 1024];
    loop {
        check_cancel(cancel)?;
        let (input_before, output_before) = (decoder.total_in(), decoder.total_out());
        let status = decoder
            .decompress(compressed, &mut buffer, FlushDecompress::None)
            .map_err(|_| invalid("invalid deflate stream"))?;
        let used = |after: u64, before| {
            after
                .checked_sub(before)
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| invalid("decoder byte count"))
        };
        let consumed = used(decoder.total_in(), input_before)?;
        let produced = used(decoder.total_out(), output_before)?;
        if decoder.total_out() > limit {
            return Err(invalid("decoded entry size or compression ratio"));
        }
        transfer(
            buffer
                .get(..produced)
                .ok_or_else(|| invalid("decoder output range"))?,
            crc,
            body,
        );
        compressed = compressed
            .get(consumed..)
            .ok_or_else(|| invalid("decoder input range"))?;
        if status == Status::StreamEnd {
            return if compressed.is_empty() {
                Ok(())
            } else {
                Err(invalid("data after the deflate stream"))
            };
        }
        if consumed == 0 && produced == 0 {
            return Err(invalid("incomplete deflate stream"));
        }
    }
}

fn transfer(bytes: &[u8], crc: &mut flate2::Crc, body: &mut Option<Vec<u8>>) {
    crc.update(bytes);
    if let Some(body) = body {
        body.extend_from_slice(bytes);
    }
}

fn validate_zip32_directory(input: &[u8], cancel: &CancellationToken) -> Result<usize, AppError> {
    let footer_start = input
        .len()
        .checked_sub(FOOTER)
        .ok_or_else(|| invalid("missing ZIP32 footer"))?;
    let footer = &input[footer_start..];
    let count = usize::from(le16(footer, 10));
    let central_start = le32(footer, 16);
    if &footer[..4] != b"PK\x05\x06"
        || footer[4..8] != [0; 4]
        || le16(footer, 8) != le16(footer, 10)
        || le16(footer, 20) != 0
        || !(1..=MAX_ENTRIES).contains(&count)
        || central_start.checked_add(le32(footer, 12)) != Some(footer_start)
    {
        return Err(invalid("multi-disk, ZIP64, bounds or footer comment"));
    }

    let mut cursor = central_start;
    let mut local_ranges = Vec::with_capacity(count);
    for _ in 0..count {
        check_cancel(cancel)?;
        let header = input
            .get(cursor..cursor + CENTRAL_HEADER)
            .ok_or_else(|| invalid("truncated central directory"))?;
        let name_len = usize::from(le16(header, 28));
        if &header[..4] != b"PK\x01\x02"
            || le16(header, 6) > 20
            || le16(header, 8) & !0x0800 != 0
            || !matches!(le16(header, 10), 0 | 8)
            || header[30..36] != [0; 6]
            || !(1..=512).contains(&name_len)
        {
            return Err(invalid("unsupported ZIP32 flags, metadata or method"));
        }
        let local_start = le32(header, 42);
        let local_end = local_start
            .checked_add(LOCAL_HEADER)
            .ok_or_else(|| invalid("local header offset"))?;
        let local = input
            .get(local_start..local_end)
            .ok_or_else(|| invalid("truncated local header"))?;
        if local_end >= central_start
            || &local[..4] != b"PK\x03\x04"
            || local[4..26] != header[6..28]
            || usize::from(le16(local, 26)) != name_len
            || le16(local, 28) != 0
        {
            return Err(invalid("inconsistent local header or extra data"));
        }
        let member_end = local_end
            .checked_add(name_len)
            .and_then(|end| end.checked_add(le32(header, 20)))
            .filter(|end| *end <= central_start)
            .ok_or_else(|| invalid("local member range"))?;
        local_ranges.push((local_start, member_end));
        cursor = cursor
            .checked_add(CENTRAL_HEADER + name_len)
            .filter(|end| *end <= footer_start)
            .ok_or_else(|| invalid("central directory range"))?;
    }
    if cursor != footer_start {
        return Err(invalid("unexpected data after ZIP directory"));
    }
    local_ranges.sort_unstable();
    let mut offset = 0;
    for (start, end) in local_ranges {
        if start != offset {
            return Err(invalid(
                "overlapping entries or unexpected data between ZIP records",
            ));
        }
        offset = end;
    }
    if offset != central_start {
        return Err(invalid("unexpected data before the ZIP directory"));
    }
    Ok(count)
}

fn canonical_name(name: &[u8], directory: bool) -> Result<&str, AppError> {
    let name = std::str::from_utf8(name).map_err(|_| invalid("entry name encoding"))?;
    let name = if directory {
        name.strip_suffix('/')
            .ok_or_else(|| invalid("directory name"))?
    } else {
        name
    };
    if !name.is_ascii()
        || name.len() > 512
        || name.contains(['\\', ':'])
        || name.bytes().any(|b| b.is_ascii_control())
        || name.split('/').count() > 16
        || name.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid("unsafe entry name"));
    }
    Ok(name)
}

fn le16(header: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([header[offset], header[offset + 1]])
}
fn le32(header: &[u8], offset: usize) -> usize {
    u32::from_le_bytes([
        header[offset],
        header[offset + 1],
        header[offset + 2],
        header[offset + 3],
    ]) as usize
}

fn invalid(reason: &str) -> AppError {
    AppError::Policy(format!("SigmaHQ ZIP rejected: {reason}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_app::{
        hex,
        v10_proofs::{SigmaPackRuleV1, SigmaRuleKeyV1},
    };
    use std::io::Write;
    use zip::{ZipWriter, write::SimpleFileOptions};

    const RULE: &[u8] = b"title: Synthetic archive rule\nlogsource: {product: aws}\ndetection: {selection: {Outcome: success}, condition: selection}\n";

    fn selection() -> SigmaPackManifestV1 {
        let digest = sha256(RULE);
        SigmaPackManifestV1(vec![SigmaPackRuleV1 {
            path: "synthetic.yml".into(),
            rule: SigmaRuleKeyV1 {
                id: format!("sha256:{}", hex(&digest)),
                sha256: digest,
            },
            version: None,
            author: None,
            size: RULE.len() as u64,
        }])
    }

    fn archive(entries: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes, method) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(*method),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn inspect(bytes: &[u8]) -> Result<LocalSigmaPack, AppError> {
        inspect_sigmahq_archive(
            bytes,
            sha256(bytes),
            &selection(),
            &CancellationToken::new(),
        )
    }

    fn stored_rule() -> (&'static str, &'static [u8], CompressionMethod) {
        ("synthetic.yml", RULE, CompressionMethod::Stored)
    }

    fn central_offset(bytes: &[u8]) -> usize {
        le32(&bytes[bytes.len() - FOOTER..], 16)
    }

    #[test]
    fn selects_only_hash_pinned_rules_after_streaming_both_methods() {
        let bytes = archive(&[
            stored_rule(),
            ("other-rule.yml", b"unselected", CompressionMethod::Deflated),
        ]);
        assert_eq!(inspect(&bytes).unwrap().rules, vec![RULE.to_vec()]);
        let cancel = CancellationToken::new();
        let mismatch = inspect_sigmahq_archive(&bytes, [0; 32], &selection(), &cancel);
        assert!(matches!(mismatch, Err(AppError::Policy(message)) if message.contains("SHA-256")));
        cancel.cancel();
        assert!(matches!(
            inspect_sigmahq_archive(&bytes, sha256(&bytes), &selection(), &cancel),
            Err(AppError::Cancelled)
        ));
        assert!(inspect(&archive(&[("other.yml", RULE, CompressionMethod::Stored)])).is_err());
    }

    #[test]
    fn rejects_dangerous_paths_aliases_and_non_regular_members() {
        for invalid_name in [
            "/bad.yml",
            "../bad.yml",
            "C:bad.yml",
            "a\\bad.yml",
            "a/./bad.yml",
            "bad\n.yml",
            "SYNTHETIC.YML",
        ] {
            let bytes = archive(&[
                stored_rule(),
                (invalid_name, b"unselected", CompressionMethod::Stored),
            ]);
            assert!(inspect(&bytes).is_err(), "{invalid_name:?}");
        }
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .add_symlink("link.yml", "synthetic.yml", SimpleFileOptions::default())
            .unwrap();
        assert!(inspect(&writer.finish().unwrap().into_inner()).is_err());
    }

    #[test]
    fn rejects_bad_crc_even_when_both_headers_agree() {
        let mut bytes = archive(&[stored_rule()]);
        let central = central_offset(&bytes);
        bytes[14] ^= 0x20;
        bytes[central + 16] ^= 0x20;
        assert!(inspect(&bytes).is_err());
        let mut unselected = archive(&[
            stored_rule(),
            ("other.yml", b"unselected", CompressionMethod::Stored),
        ]);
        let central = central_offset(&unselected) + CENTRAL_HEADER + "synthetic.yml".len();
        let offset = le32(&unselected[central..], 42);
        unselected[offset + LOCAL_HEADER + "other.yml".len()] ^= 0x20;
        assert!(inspect(&unselected).is_err());
    }

    #[test]
    fn rejects_truncation_inconsistent_headers_and_zip64() {
        let bytes = archive(&[stored_rule()]);
        for end in [0, LOCAL_HEADER, CENTRAL_HEADER, bytes.len() - 1] {
            assert!(inspect(&bytes[..end]).is_err());
        }
        let central = central_offset(&bytes);
        for offset in [6, 26, central + 20, central + 42, bytes.len() - FOOTER + 8] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0x01;
            assert!(inspect(&changed).is_err(), "offset {offset}");
        }
        let mut zip64 = bytes;
        let footer = zip64.len() - FOOTER;
        zip64[footer + 8..footer + 12].fill(0xff);
        assert!(inspect(&zip64).is_err());
    }

    #[test]
    fn rejects_directory_payloads_and_inflation_beyond_the_budget() {
        let mut gets_directory = archive(&[
            stored_rule(),
            ("unsafe", b"data", CompressionMethod::Stored),
        ]);
        let central = central_offset(&gets_directory) + CENTRAL_HEADER + "synthetic.yml".len();
        let local = le32(&gets_directory[central..], 42);
        gets_directory[central + CENTRAL_HEADER + 5] = b'/';
        gets_directory[local + LOCAL_HEADER + 5] = b'/';
        assert!(inspect(&gets_directory).is_err());
        let bomb = vec![0; 512 * 1024];
        let compressed = archive(&[
            stored_rule(),
            ("unselected", &bomb, CompressionMethod::Deflated),
        ]);
        assert!(inspect(&compressed).is_err());
    }

    #[test]
    fn rejects_unfinished_deflate_and_bytes_after_its_end() {
        use flate2::{Compression, write::DeflateEncoder};
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(RULE).unwrap();
        let mut stream = encoder.finish().unwrap();
        let mut crc = flate2::Crc::new();
        inflate_member(
            &stream,
            RULE.len() as u64,
            &mut crc,
            &mut None,
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(
            inflate_member(
                &stream[..stream.len() - 1],
                RULE.len() as u64,
                &mut flate2::Crc::new(),
                &mut None,
                &CancellationToken::new()
            )
            .is_err()
        );
        stream.push(0);
        assert!(
            inflate_member(
                &stream,
                RULE.len() as u64,
                &mut flate2::Crc::new(),
                &mut None,
                &CancellationToken::new()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_a_zip_preamble_with_consistent_directory_offsets() {
        let mut bytes = archive(&[stored_rule()]);
        let initial_directory = central_offset(&bytes);
        bytes.insert(0, b'x');
        let directory = initial_directory + 1;
        bytes[directory + 42..directory + 46].copy_from_slice(&1u32.to_le_bytes());
        let footer = bytes.len() - FOOTER;
        bytes[footer + 16..footer + 20]
            .copy_from_slice(&u32::try_from(directory).unwrap().to_le_bytes());
        assert!(inspect(&bytes).is_err());
    }

    #[test]
    fn rejects_overlapping_offsets_and_extra_metadata() {
        let mut bytes = archive(&[
            stored_rule(),
            ("anotherxx.yml", b"unselected", CompressionMethod::Stored),
        ]);
        let second = central_offset(&bytes) + CENTRAL_HEADER + "synthetic.yml".len();
        bytes[second + 42..second + 46].fill(0);
        assert!(inspect(&bytes).is_err());
        let mut bytes = archive(&[stored_rule()]);
        let central = central_offset(&bytes);
        bytes[central + 30] = 1;
        assert!(inspect(&bytes).is_err());
    }
}
