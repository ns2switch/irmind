use super::*;
use std::io::Cursor;
struct Broken;
impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }
}

#[test]
fn original_record_bytes_and_offsets_match_roots_arrays_and_wrapped_documents() {
    let first = r#"{"x":"\u00e9","raw":9007199254740993}"#;
    let second = r#"{"y":[true,null,"a\\b"]}"#;
    for source in [
        format!(" \n{first}\n {second}"),
        format!("[ {first},\n{second} ]"),
        format!(r#"{{"metadata":"original","Records":[{first},{second}],"after":true}}"#),
    ] {
        let cancel = CancellationToken::new();
        let mut input = Cursor::new(source.as_bytes());
        let mut frames = JsonFrames::new(&mut input, &cancel);
        for expected in [first, second] {
            let frame = frames.next_frame().unwrap().unwrap();
            assert_eq!(frame.bytes(), expected.as_bytes());
            assert_eq!(frame.offset(), source.find(expected).unwrap() as u64);
            assert!(!frame.oversized());
        }
        assert!(frames.next_frame().unwrap().is_none());
    }
}

#[test]
fn oversized_record_retains_a_bounded_prefix_and_the_next_record_is_not_consumed() {
    let source = format!(
        "{{\"message\":\"{}\"}}\n{{\"next\":true}}",
        "x".repeat(MAX_RECORD + 8192)
    );
    let cancel = CancellationToken::new();
    let mut input = Cursor::new(source.as_bytes());
    let mut frames = JsonFrames::new(&mut input, &cancel);
    let first = frames.next_frame().unwrap().unwrap();
    assert!(first.oversized());
    assert_eq!(first.bytes().len(), MAX_RECORD + 1);
    let next = frames.next_frame().unwrap().unwrap();
    assert_eq!(next.bytes(), b"{\"next\":true}");
    assert_eq!(next.offset(), source.find("{\"next\"").unwrap() as u64);
}

#[test]
fn duplicate_wrapper_metadata_and_truncated_frames_remain_errors() {
    for input in [
        r#"{"metadata":1,"metadata":2,"Records":[{"x":1}]}"#,
        r#"{"Records":[],"Records":[]}"#,
        r#"{"Records":[{"x":1}],"tail":{"x":1,"x":2}}"#,
        r#"{"unterminated":"x"#,
    ] {
        let cancel = CancellationToken::new();
        let mut input = Cursor::new(input.as_bytes());
        let mut frames = JsonFrames::new(&mut input, &cancel);
        let rejected = loop {
            match frames.next_frame() {
                Err(_) => break true,
                Ok(Some(_)) => {}
                Ok(None) => break false,
            }
        };
        assert!(rejected);
    }
}

#[test]
fn cancellation_and_io_failure_are_not_successful_empty_input() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut empty = std::io::empty();
    assert!(matches!(
        JsonFrames::new(&mut empty, &cancel).next_frame(),
        Err(AppError::Cancelled)
    ));

    assert!(
        JsonFrames::new(&mut Broken, &CancellationToken::new())
            .next_frame()
            .is_err()
    );
}
