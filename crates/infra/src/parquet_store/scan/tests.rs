use super::contains_ignore_case;

#[test]
fn case_insensitive_search_matches_previous_semantics() {
    for text in [
        "",
        "a",
        "Synthetic-000001",
        "sYntHetic-000001",
        "12345",
        "abcABC",
        "Étage",
    ] {
        for needle in [
            "",
            "a",
            "A",
            "1",
            "SYNTHETIC-000001",
            "ABC",
            "bcA",
            "ÉTAGE",
            "absent",
        ] {
            let expected = text.to_lowercase().contains(&needle.to_lowercase());
            assert_eq!(
                contains_ignore_case(text, needle),
                expected,
                "text={text}, needle={needle}"
            );
        }
    }
}
