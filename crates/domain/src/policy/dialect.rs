#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplQueryClass {
    SafeLiteral,
    Forbidden,
    Unparseable,
}

/// The MVP dialect is one literal term, never arbitrary SPL. The command list is
/// defense in depth so known side-effect commands are denied before approval.
pub fn classify_spl_query(query: &str) -> SplQueryClass {
    const FORBIDDEN: &[&str] = &[
        "outputlookup",
        "outputcsv",
        "collect",
        "sendemail",
        "sendalert",
        "script",
        "run",
        "rest",
        "map",
        "delete",
        "tscollect",
        "meventcollect",
    ];
    if query
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(|token| {
            FORBIDDEN
                .iter()
                .any(|command| token.eq_ignore_ascii_case(command))
        })
    {
        return SplQueryClass::Forbidden;
    }
    if !query.is_empty()
        && query.len() <= 128
        && query
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:@/".contains(&byte))
    {
        SplQueryClass::SafeLiteral
    } else {
        SplQueryClass::Unparseable
    }
}
