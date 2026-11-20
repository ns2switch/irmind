use super::*;

const GOLDEN: &str =
    include_str!("../../../../../docs/development/source-query-format-vectors/capture.hex");
const IDENTITIES: &str =
    include_str!("../../../../../docs/development/source-query-format-vectors/identities.json");

fn golden() -> Vec<u8> {
    hex::decode(GOLDEN.trim()).unwrap()
}

fn verify(bytes: &[u8]) -> Result<QueryCaptureSummary, CaptureError> {
    verify_query_capture(bytes, &CancellationToken::new())
}

#[test]
fn approved_capture_matches_the_hash_and_page_commitment() {
    let bytes = golden();
    let summary = verify(&bytes).unwrap();
    let identities: serde_json::Value = serde_json::from_str(IDENTITIES).unwrap();
    assert_eq!(
        summary.capture_sha256.as_str(),
        identities["capture_sha256"]
    );
    assert_eq!(
        summary.page_commitment.as_str(),
        identities["pages_commitment"]
    );
    assert_eq!(summary.plan.as_str(), identities["plan"]);
    assert_eq!(summary.bytes, bytes.len() as u64);
    assert_eq!((summary.page_count, summary.rows), (2, 2));
    assert_eq!(summary.decoder.id(), "query-athena-cloudtrail");
    assert_eq!(summary.decoder.version(), "1");
}

#[test]
fn rejects_changed_missing_and_surplus_capture_bytes() {
    let bytes = golden();
    for length in [0, QUERY_CAPTURE_MAGIC.len(), bytes.len() - 1] {
        assert_eq!(verify(&bytes[..length]), Err(CaptureError::InvalidFormat));
    }
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert_eq!(verify(&changed), Err(CaptureError::Integrity));
    changed = bytes;
    changed.push(0);
    assert_eq!(verify(&changed), Err(CaptureError::InvalidFormat));
}

fn put(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn descriptor(pages: u64) -> Descriptor {
    Descriptor {
        decoder: Decoder {
            id: "query-athena-cloudtrail".into(),
            version: "1".into(),
        },
        pages,
        plan: "00".repeat(32),
        version: 1,
    }
}

fn header(pages: u64) -> Vec<u8> {
    let mut bytes = QUERY_CAPTURE_MAGIC.to_vec();
    put(&mut bytes, &serde_json::to_vec(&descriptor(pages)).unwrap());
    bytes.extend_from_slice(&pages.to_be_bytes());
    bytes
}

fn page(ordinal: u64, rows: u64, body: &[u8]) -> Page {
    Page {
        columns: Vec::new(),
        completeness: 0,
        encoding: "identity".into(),
        ordinal,
        rows,
        sha256: crate::hex(&Sha256::digest(body)),
    }
}

fn append_page(bytes: &mut Vec<u8>, metadata: &Page, body: &[u8]) {
    put(bytes, &serde_json::to_vec(metadata).unwrap());
    put(bytes, body);
}

#[test]
fn rejects_duplicate_or_reordered_pages_and_unknown_completeness() {
    let mut bytes = header(2);
    append_page(&mut bytes, &page(0, 1, b"first"), b"first");
    append_page(&mut bytes, &page(0, 1, b"second"), b"second");
    assert_eq!(verify(&bytes), Err(CaptureError::InvalidFormat));

    let mut bytes = header(2);
    append_page(&mut bytes, &page(1, 1, b"second"), b"second");
    append_page(&mut bytes, &page(0, 1, b"first"), b"first");
    assert_eq!(verify(&bytes), Err(CaptureError::InvalidFormat));

    let mut bytes = header(1);
    let mut metadata = page(0, 1, b"first");
    metadata.completeness = 5;
    append_page(&mut bytes, &metadata, b"first");
    assert_eq!(verify(&bytes), Err(CaptureError::InvalidFormat));
}

#[test]
fn descriptor_requires_the_exact_canonical_schema() {
    let body = serde_json::to_string(&descriptor(0)).unwrap();
    for invalid in [
        format!(" {body}"),
        body.replace("\"pages\":0", "\"pages\":0,\"pages\":0"),
        body.replace("\"pages\":0", "\"pages\":0.0"),
        body.replace("\"pages\":0", "\"pages\":0,\"unknown\":true"),
        body.replace("\"pages\":0", "\"pages\":1"),
        body.replace("\"version\":1", "\"version\":2"),
        body.replace("query-athena-cloudtrail", "query-athena-\\u0063loudtrail"),
    ] {
        let mut bytes = QUERY_CAPTURE_MAGIC.to_vec();
        put(&mut bytes, invalid.as_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(verify(&bytes), Err(CaptureError::InvalidFormat));
    }
}

#[test]
fn rejects_oversized_declarations_before_consuming_the_claimed_payload() {
    let mut bytes = QUERY_CAPTURE_MAGIC.to_vec();
    bytes.extend_from_slice(&(QUERY_MAX_RECORD_BYTES as u64 + 1).to_be_bytes());
    assert_eq!(verify(&bytes), Err(CaptureError::Limit));

    assert_eq!(
        verify(&header(QUERY_MAX_PAGES + 1)),
        Err(CaptureError::Limit)
    );

    let mut bytes = header(1);
    put(&mut bytes, &serde_json::to_vec(&page(0, 1, b"")).unwrap());
    bytes.extend_from_slice(&QUERY_MAX_BYTES.to_be_bytes());
    assert_eq!(verify(&bytes), Err(CaptureError::Limit));

    let mut bytes = header(2);
    append_page(&mut bytes, &page(0, QUERY_MAX_ROWS, b"first"), b"first");
    append_page(&mut bytes, &page(1, 1, b"second"), b"second");
    assert_eq!(verify(&bytes), Err(CaptureError::Limit));
}

#[test]
fn bounds_native_column_metadata_nodes() {
    let mut metadata = page(0, 0, b"");
    metadata.columns = (0..1500)
        .map(|_| CaptureColumn {
            name: "a".into(),
            native_type: "string".into(),
        })
        .collect();
    assert!(serde_json::to_vec(&metadata).unwrap().len() < QUERY_MAX_RECORD_BYTES);
    let mut bytes = header(1);
    append_page(&mut bytes, &metadata, b"");
    assert_eq!(verify(&bytes), Err(CaptureError::InvalidFormat));
}

struct Chunked<'a> {
    input: &'a [u8],
    cancel_after_full_chunk: Option<&'a CancellationToken>,
}

impl Read for Chunked<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(bytes.len() <= MAX_CHUNK);
        if let Some(cancel) = self.cancel_after_full_chunk
            && bytes.len() == MAX_CHUNK
        {
            cancel.cancel();
        }
        let count = bytes.len().min(8192);
        self.input.read(&mut bytes[..count])
    }
}

#[test]
fn streams_large_pages_in_bounded_chunks_and_observes_cancellation() {
    let body = vec![0x80; 2 * MAX_CHUNK + 1];
    let mut bytes = header(1);
    append_page(&mut bytes, &page(0, 1, &body), &body);
    let cancel = CancellationToken::new();
    let input = Chunked {
        input: &bytes,
        cancel_after_full_chunk: None,
    };
    assert_eq!(verify_query_capture(input, &cancel), verify(&bytes));
    let input = Chunked {
        input: &bytes,
        cancel_after_full_chunk: Some(&cancel),
    };
    assert_eq!(
        verify_query_capture(input, &cancel),
        Err(CaptureError::Cancelled)
    );
}
