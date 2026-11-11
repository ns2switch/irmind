use super::*;

#[test]
fn offset_units_are_consistent_and_bounded_by_the_verified_source() {
    let source = SourceReferenceV1::file("logs/record.json").unwrap();
    let cancel = CancellationToken::new();
    let catalog = MappingCatalog::freeze(vec![Arc::new(Decoder)], vec![]).unwrap();
    let mut bytes = accumulator(&source, &cancel, &catalog);
    let mut output = Cursor::new(Vec::new());
    bytes
        .accept(&record_with_offset(0, Some(0)), &mut output)
        .unwrap();
    bytes
        .accept(&record_with_offset(1, Some(99)), &mut output)
        .unwrap();
    assert!(
        bytes
            .accept(&record_with_offset(2, None), &mut output)
            .is_err()
    );
    assert!(
        bytes
            .accept(&record_with_offset(2, Some(100)), &mut output)
            .is_err()
    );
    assert!(
        bytes
            .accept(&record_with_offset(2, Some(98)), &mut output)
            .is_err()
    );
    let mut unavailable = accumulator(&source, &cancel, &catalog);
    let mut output = Cursor::new(Vec::new());
    unavailable
        .accept(&record_with_offset(0, None), &mut output)
        .unwrap();
    assert!(
        unavailable
            .accept(&record_with_offset(1, Some(1)), &mut output)
            .is_err()
    );
}
