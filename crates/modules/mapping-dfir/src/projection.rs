use irmind_app::{
    GraphRecord, GraphRelation,
    source_mapping::{MappingError, SourceRecordV1, SourceValue, json::render_source_fields},
};
type Alias = (&'static str, &'static [&'static str]);
const VELOCIRAPTOR: &[Alias] = &[
    ("host", &["Host", "Hostname"]),
    ("user", &["User", "Username"]),
    ("process", &["Process", "Image"]),
    ("command_line", &["CommandLine"]),
    ("ip", &["SourceIP"]),
    ("ip", &["DestinationIP"]),
    ("artifact", &["Artifact"]),
];
const HAYABUSA: &[Alias] = &[
    ("host", &["Computer"]),
    ("channel", &["Channel"]),
    ("severity", &["Level"]),
    ("rule", &["RuleTitle"]),
    ("detail", &["Details"]),
    ("finding", &["RuleTitle"]),
];
const CHAINSAW: &[Alias] = &[
    (
        "host",
        &[
            "Computer",
            "computer",
            "Event.System.Computer",
            "document.data.Event.System.Computer",
        ],
    ),
    (
        "user",
        &[
            "User",
            "user",
            "Event.EventData.SubjectUserName",
            "document.data.Event.EventData.SubjectUserName",
        ],
    ),
    (
        "process",
        &[
            "Event.EventData.NewProcessName",
            "document.data.Event.EventData.NewProcessName",
        ],
    ),
    ("rule", &["Rule", "rule", "group"]),
    (
        "event_id",
        &["Event.System.EventID", "document.data.Event.System.EventID"],
    ),
];
const PLASO: &[Alias] = &[
    ("host", &["hostname"]),
    ("user", &["user"]),
    ("file", &["filename"]),
    ("source", &["source_short"]),
];
const EZTOOLS: &[Alias] = &[
    ("host", &["Computer"]),
    ("user", &["UserName"]),
    ("process", &["ExecutableName"]),
    ("process", &["Application"]),
    ("file", &["SourceFilename"]),
    ("file", &["FullPath"]),
    ("file", &["Path"]),
    ("file", &["FileName"]),
    ("registry", &["KeyPath"]),
];
pub(super) fn project<'a>(
    parser: &str,
    source: &'a SourceRecordV1,
) -> Result<(GraphRecord, &'a str), MappingError> {
    let fields = source.fields();
    let aliases = match parser {
        "parser-velociraptor" => VELOCIRAPTOR,
        "parser-hayabusa" => HAYABUSA,
        "parser-chainsaw" => CHAINSAW,
        "parser-plaso" => PLASO,
        "parser-eztools" => EZTOOLS,
        _ => return Err(invalid()),
    };
    let host = aliases
        .iter()
        .find(|(kind, _)| *kind == "host")
        .and_then(|(_, paths)| first(fields, paths))
        .unwrap_or("");
    let mut entities = aliases
        .iter()
        .filter_map(|(kind, paths)| {
            first(fields, paths)
                .filter(|s| !s.is_empty() && s.len() <= 4096)
                .map(|v| ((*kind).into(), v.into()))
        })
        .collect::<Vec<_>>();
    entities.sort();
    entities.dedup();
    let event = event(parser, source)?;
    let relations = if parser == "parser-hayabusa" {
        first(fields, &["RuleTitle"])
            .filter(|s| !s.is_empty() && s.len() <= 4096)
            .map(|rule| GraphRelation {
                from_kind: "event".into(),
                from_value: event.clone(),
                relation: "detected_by".into(),
                to_kind: "finding".into(),
                to_value: rule.into(),
            })
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    let at = source
        .timestamp()
        .map(|t| {
            let raw = t.to_rfc3339();
            format!("{}Z", &raw[..19])
        })
        .unwrap_or_default();
    let record = GraphRecord {
        index: usize::try_from(source.origin().record()).map_err(|_| invalid())?,
        at,
        event,
        text: display_text(parser, source)?,
        entities,
        relations,
    };
    Ok((record, host))
}
fn display_text(parser: &str, source: &SourceRecordV1) -> Result<String, MappingError> {
    if parser == "parser-eztools" {
        let values = SourceValue::object(vec![
            (
                "tool".into(),
                SourceValue::Text(source_tool(source).ok_or_else(invalid)?.into()),
            ),
            ("columns".into(), source.fields().clone()),
        ])
        .map_err(|_| invalid())?;
        render_source_fields(&values).map_err(|_| invalid())
    } else {
        render_source_fields(source.fields()).map_err(|_| invalid())
    }
}
fn event(parser: &str, source: &SourceRecordV1) -> Result<String, MappingError> {
    let fields = source.fields();
    let value = match parser {
        "parser-velociraptor" => first(fields, &["EventName", "Artifact"])
            .unwrap_or("artifact_result")
            .into(),
        "parser-hayabusa" => {
            match first(fields, &["EventID"]).and_then(|v| v.parse::<u64>().ok()) {
                Some(id) => format!("windows_event_{id}"),
                None => "hayabusa_source_event".into(),
            }
        }
        "parser-chainsaw" => first(fields, &["Rule", "rule", "group"])
            .unwrap_or("chainsaw_match")
            .into(),
        "parser-plaso" => first(fields, &["data_type", "parser"])
            .ok_or_else(invalid)?
            .into(),
        "parser-eztools" => source_tool(source).ok_or_else(invalid)?.into(),
        _ => return Err(invalid()),
    };
    Ok(value)
}
fn first<'a>(fields: &'a SourceValue, paths: &[&str]) -> Option<&'a str> {
    paths.iter().find_map(|path| {
        let value = path.split('.').try_fold(fields, |v, p| v.field(p))?;
        match value {
            SourceValue::Text(t) => Some(t.as_str()),
            SourceValue::Number(n) => Some(n.as_str()),
            _ => None,
        }
    })
}
fn source_tool(source: &SourceRecordV1) -> Option<&str> {
    let tool = source
        .format()
        .discriminators()
        .get(&irmind_app::source_mapping::SourceDiscriminator::Dataset)?
        .as_str();
    [
        "PECmd",
        "PECmd timeline",
        "AmcacheParser",
        "AppCompatCacheParser",
        "MFTECmd",
        "LECmd",
        "RECmd batch",
        "SrumECmd",
        "EvtxECmd",
    ]
    .contains(&tool)
    .then_some(tool)
}
fn invalid() -> MappingError {
    MappingError::UnsupportedSourceValue
}
