use super::*;

#[test]
fn malformed_records_are_bounded_and_do_not_discard_valid_neighbors() {
    let input = format!("{EVENT}\nnot-json\n{EVENT}\n");
    let (report, rows) = parse(SIMPLE, &input);
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert!(report.samples.iter().all(|sample| sample.len() <= 256));
    rows[0].inspect(|record| assert_eq!(record.at, "2026-10-23T10:00:00.123456789Z"));
    assert_eq!(rows[1].provenance().evidence_hash(), &[7; 32]);
    assert_eq!(
        rows[1]
            .provenance()
            .parser_location()
            .unwrap()
            .byte_offset(),
        (EVENT.len() + 10) as u64
    );
}

#[test]
fn json_array_offsets_and_invalid_trailing_data_are_recorded() {
    let definition = SIMPLE.replace("format = \"ndjson\"", "format = \"json\"");
    let input = format!("[ {EVENT}, {EVENT} ] trailing-invalid-data");
    let (report, rows) = parse(&definition, &input);
    assert_eq!((report.accepted, report.rejected), (2, 1));
    assert_eq!(
        rows[0]
            .provenance()
            .parser_location()
            .unwrap()
            .byte_offset(),
        2
    );
    assert_eq!(
        rows[1]
            .provenance()
            .parser_location()
            .unwrap()
            .byte_offset(),
        (EVENT.len() + 4) as u64
    );
    assert!(report.samples[0].contains("trailing-invalid-data"));
    let (report, _) = parse(&definition, &format!("[{EVENT},]"));
    assert_eq!(report.rejected, 1);
    let (report, _) = parse(&definition, &format!("[{EVENT}"));
    assert_eq!(report.rejected, 1);
}

#[test]
fn oversized_lines_depth_fields_and_duplicate_keys_are_rejected() {
    let small = SIMPLE.to_owned() + "\n[limits]\nrecord_bytes = 128\n";
    let (report, _) = parse(&small, &format!("{}\n{EVENT}\n", "x".repeat(10000)));
    assert_eq!((report.accepted, report.rejected), (1, 1));
    let nested = r#"{"time":"2026-10-23T10:00:00Z","unused":{"a":{"b":1}}}"#;
    let (report, _) = parse(
        &(SIMPLE.to_owned() + "\n[limits]\ndepth = 2\n"),
        &format!("{nested}\n{EVENT}\n"),
    );
    assert_eq!((report.accepted, report.rejected), (1, 1));
    let (report, _) = parse(
        SIMPLE,
        "{\"time\":\"2026-10-23T10:00:00Z\",\"time\":\"2026-10-23T11:00:00Z\"}\n",
    );
    assert_eq!((report.accepted, report.rejected), (0, 1));
    let (report, _) = parse(
        &(SIMPLE.to_owned() + "\n[limits]\nfields = 3\n"),
        "{\"time\":\"2026-10-23T10:00:00Z\",\"unused\":[1,2,3,4]}\n",
    );
    assert_eq!(report.rejected, 1);
}

#[test]
fn csv_quoted_newlines_and_exact_negative_epoch_fractions_are_preserved() {
    let definition = include_str!("../../../../../docs/examples/parsers/access-csv.toml");
    let source = "time,host,user,source_ip,action,outcome\n2026-10-23T10:00:00Z,demo,alice,203.0.113.77,login,\"first\nsecond\"\n";
    let (report, rows) = parse(definition, source);
    assert_eq!(report.accepted, 1);
    rows[0].inspect(|record| assert!(record.text.contains("first\\nsecond")));
    let definition = SIMPLE.replace("format = \"rfc3339\"", "format = \"unix\"");
    let (report, rows) = parse(&definition, "{\"time\":\"-0.0000001\"}\n");
    assert_eq!(report.accepted, 1);
    rows[0].inspect(|record| assert_eq!(record.at, "1969-12-31T23:59:59.999999900Z"));
}

#[test]
fn cancellation_stops_before_read_and_between_records() {
    let parser = DeclarativeParser::from_toml(SIMPLE).unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        parser.parse_source(
            "events.json",
            &mut Cursor::new(EVENT),
            [0; 32],
            &cancel,
            &mut |_| Ok(())
        ),
        Err(AppError::Cancelled)
    ));
    let cancel = CancellationToken::new();
    let mut count = 0;
    let result = parser.parse_source(
        "events.json",
        &mut Cursor::new(format!("{EVENT}\n{EVENT}\n")),
        [0; 32],
        &cancel,
        &mut |_| {
            count += 1;
            cancel.cancel();
            Ok(())
        },
    );
    assert!(matches!(result, Err(AppError::Cancelled)));
    assert_eq!(count, 1);
}
