use super::*;
use arrow_array::{ArrayRef, RecordBatch, StringArray};
use irmind_app::{
    IndexedTime, encode_common_event, indexed_rfc3339, v10_proofs::SigmaFieldTableV1,
};
use irmind_domain::{
    BoundedObservations, EventContextV1, EventHeaderV1, EventOrigin, EvidenceHash,
};
use parquet::{
    arrow::ArrowWriter,
    basic::Compression,
    file::{
        properties::WriterProperties,
        reader::{ChunkReader, Length},
    },
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(not(debug_assertions))]
const GIB: u64 = 1024 * 1024 * 1024;
const INCIDENT_RECORD: u64 = 8192;
// A benign audit row has the same legacy value as the incident. The original
// fixture rule tests only that value, so both matches are expected.
const NEGATIVE_CONTROL: u64 = 8224;
#[cfg(not(debug_assertions))]
const RULES_PER_LANE: u64 = 1000;

fn event(record: u64, action: &str, code: &str) -> CommonEventV1 {
    let time: IndexedTime = indexed_rfc3339("2026-11-01T10:00:00Z", false, false).unwrap();
    CommonEventV1::try_new(
        EventOrigin::try_new(
            EvidenceHash::from_bytes([23; 32]),
            record,
            None,
            "parser-json",
            "json-source-v1",
        )
        .unwrap(),
        Some(time),
        EventHeaderV1::default()
            .with_action(action)
            .unwrap()
            .with_code(code)
            .unwrap(),
        EventContextV1::default(),
        BoundedObservations::default(),
    )
    .unwrap()
}

fn fixture_file(path: &std::path::Path, records: u64) {
    let padding = "x".repeat(4096);
    write_fixture_rows(path, records, |record| {
        let action = if record == INCIDENT_RECORD {
            "signal"
        } else {
            "background"
        };
        let code = if record % 32 == 0 {
            "audit"
        } else {
            "unrelated"
        };
        let original_name = if matches!(record, INCIDENT_RECORD | NEGATIVE_CONTROL) {
            "legacy-signal"
        } else {
            "legacy-background"
        };
        (
            encode_common_event(&event(record, action, code)).unwrap(),
            format!(r#"{{"LegacyEvent":"{original_name}","padding":"{padding}"}}"#),
        )
    });
}

pub(super) fn write_fixture_rows(
    path: &std::path::Path,
    records: u64,
    mut projected: impl FnMut(u64) -> (String, String),
) {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    let properties = WriterProperties::builder()
        .set_dictionary_enabled(false)
        .set_compression(Compression::UNCOMPRESSED)
        .set_max_row_group_row_count(Some(1024))
        .build();
    let mut writer = None;
    for begin in (0..records).step_by(1024) {
        let (common, original): (Vec<_>, Vec<_>) = (begin..(begin + 1024).min(records))
            .map(&mut projected)
            .unzip();
        let batch = RecordBatch::try_from_iter([
            (
                "common_payload",
                Arc::new(StringArray::from(common)) as ArrayRef,
            ),
            ("text", Arc::new(StringArray::from(original)) as ArrayRef),
        ])
        .unwrap();
        if writer.is_none() {
            writer = Some(
                ArrowWriter::try_new(
                    file.try_clone().unwrap(),
                    batch.schema(),
                    Some(properties.clone()),
                )
                .unwrap(),
            );
        }
        writer.as_mut().unwrap().write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

fn table(original: bool) -> super::super::field_table::ReviewedSigmaFieldTable {
    let binding = if original {
        "path = [\"LegacyEvent\"]"
    } else {
        "column = \"event.action\""
    };
    let object = SigmaFieldTableV1 {
        id: "synthetic-benchmark".into(),
        version: "1".into(),
        toml: format!(
            r#"
[[variants]]
product = "fixture"
service = "audit"
parser_id = "parser-json"
parser_version = "json-source-v1"
mapping_id = "synthetic-benchmark"
mapping_version = "v1"
dataset = "fixture-audit"
[[variants.events]]
column = "event.code"
equals = "audit"
[[variants.fields]]
name = "Activity"
{binding}
value_type = "text"
null_policy = "absent"
"#
        ),
    };
    super::super::field_table::ReviewedSigmaFieldTable::parse(&object).unwrap()
}

fn rules(original: bool, count: u64) -> Vec<(SigmaRuleKeyV1, Vec<u8>)> {
    (0..count).map(|number| {
        let (field, product) = if number >= 980 { ("unknown", "fixture") }
            else if number >= 950 { ("Activity", "unsupported") }
            else { ("Activity", "fixture") };
        let value = if number == 0 {
            if original { "legacy-signal".into() } else { "signal".into() }
        } else {
            format!("non-matching-{number}")
        };
        let id = format!("{}-{number:04}", if original { "original" } else { "common" });
        let bytes = format!("title: Synthetic fixture {id}\nlogsource: {{product: {product}, service: audit}}\ndetection: {{selection: {{{field}: {value}}}, condition: selection}}\n").into_bytes();
        (SigmaRuleKeyV1 { id, sha256: irmind_app::sha256(&bytes) }, bytes)
    }).collect()
}

struct CountedParquet {
    file: File,
    read_bytes: Arc<AtomicU64>,
}

impl Length for CountedParquet {
    fn len(&self) -> u64 {
        self.file.len()
    }
}

impl ChunkReader for CountedParquet {
    type T = CountedRead<<File as ChunkReader>::T>;

    fn get_read(&self, start: u64) -> parquet::errors::Result<Self::T> {
        Ok(CountedRead(
            self.file.get_read(start)?,
            self.read_bytes.clone(),
        ))
    }

    fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<bytes::Bytes> {
        let bytes = self.file.get_bytes(start, length)?;
        self.read_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Ok(bytes)
    }
}

struct CountedRead<R>(R, Arc<AtomicU64>);

impl<R: Read> Read for CountedRead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.0.read(bytes)?;
        self.1.fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }
}

fn lane(file: &std::path::Path, original: bool, count: u64) {
    let rules = rules(original, count);
    let table = table(original);
    let start = Instant::now();
    let programs = SigmaVariantPrograms::compile(
        &table.variants[0],
        rules.iter().map(|(key, raw)| (key.clone(), raw.as_slice())),
    )
    .unwrap();
    let compile = start.elapsed();
    let start = Instant::now();
    let cancel = CancellationToken::new();
    let mut run = programs.start(8_000_000_000);
    let mut actual = std::collections::BTreeSet::new();
    let read_bytes = Arc::new(AtomicU64::new(0));
    run.scan_authenticated(
        CountedParquet {
            file: File::open(file).unwrap(),
            read_bytes: read_bytes.clone(),
        },
        0..i64::MAX,
        start + Duration::from_mins(5),
        &cancel,
        |physical, event, rule| {
            assert_eq!(physical, event.origin().record());
            assert!(actual.insert((rule.id.clone(), physical)));
            Ok(())
        },
    )
    .unwrap();
    let seconds = start.elapsed().as_secs_f64();
    assert!(run.status() == SigmaRunStatusV1::Complete);
    let name = if original { "original" } else { "common" };
    let truth = std::collections::BTreeSet::from([(format!("{name}-0000"), INCIDENT_RECORD)]);
    let false_matches = actual
        .difference(&truth)
        .map(|(id, record)| (id.as_str(), *record))
        .collect::<Vec<_>>();
    if original {
        assert_eq!(false_matches, [("original-0000", NEGATIVE_CONTROL)]);
        println!(
            "expected_false_positive=original-0000 record={NEGATIVE_CONTROL} event.code=audit event.action=background LegacyEvent=legacy-signal"
        );
    } else {
        assert!(false_matches.is_empty());
    }
    let false_positives = false_matches.len();
    let true_positives = actual.intersection(&truth).count();
    let false_negatives = truth.difference(&actual).count();
    assert_eq!(
        (true_positives, false_positives, false_negatives),
        (1, usize::from(original), 0)
    );
    assert_eq!(
        run.rules_evaluated(),
        usize::try_from(count.min(950)).unwrap()
    );
    assert_eq!(
        programs.skipped().len(),
        usize::try_from(count.saturating_sub(950)).unwrap()
    );
    println!(
        "fields={name} rules={count} compiled={} evaluated={} skipped={} compile_s={:.3} scan_s={seconds:.3} read_bytes={} tp={true_positives} fp={false_positives} fn={false_negatives} units={}",
        programs.eligible(),
        run.rules_evaluated(),
        programs.skipped().len(),
        compile.as_secs_f64(),
        read_bytes.load(Ordering::Relaxed),
        run.used_units(),
    );
}

#[test]
fn sigma_projected_artifact_routes_count_known_false_positives() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = temp.path().join("events.parquet");
    fixture_file(&fixture, 8256);
    for original in [false, true] {
        lane(&fixture, original, 3);
    }
}

#[test]
#[cfg(not(debug_assertions))]
#[ignore = "generates a 1 GiB synthetic Parquet corpus and measures 2,000 local rules"]
fn sigma_2000_rules_on_one_gib_parquet() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = temp.path().join("events.parquet");
    fixture_file(&fixture, GIB / 4096);
    let bytes = std::fs::metadata(&fixture).unwrap().len();
    assert!(bytes >= GIB);
    println!("parquet_bytes={bytes} rows={}", GIB / 4096);
    for original in [false, true] {
        lane(&fixture, original, RULES_PER_LANE);
    }
}
