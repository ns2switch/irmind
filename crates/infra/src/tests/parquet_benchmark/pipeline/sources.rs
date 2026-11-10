use super::*;
use std::io::Write as _;
pub(super) struct Input {
    pub(super) root: tempfile::TempDir,
    pub(super) name: String,
    pub(super) bytes: u64,
    pub(super) records: u64,
}
impl Input {
    pub(super) fn generate(label: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let name = if label == "evtx" {
            "events.evtx"
        } else {
            "events.ndjson"
        }
        .to_owned();
        let (bytes, records) = if label == "evtx" {
            let path = std::env::var_os("IRMIND_EVTX_SOURCE_BENCH_INPUT").unwrap();
            let bytes = fs::copy(path, root.path().join(&name)).unwrap();
            assert_eq!((bytes - 4096) % 65536, 0);
            (bytes, (bytes - 4096) / 65536 * 17)
        } else {
            let mut value = match label {
                "ocsf" => {
                    serde_json::json!({"time_dt":"2026-11-01T00:00:00.123456789Z","metadata":{"version":"1.4.0"},"class_uid":3002,"category_uid":3,"activity_id":1,"status_id":2,"device":{"hostname":"synthetic-host"},"actor":{"user":{"name":"alice","domain":"LAB"}},"src_endpoint":{"ip":"203.0.113.77"}})
                }
                "ecs" => {
                    serde_json::json!({"@timestamp":"2026-11-01T00:00:00.123456789Z","ecs":{"version":"9.5.0"},"event":{"category":["authentication"],"type":["start"],"outcome":"failure"},"host":{"name":"synthetic-host"},"user":{"name":"alice","domain":"LAB"},"source":{"ip":"203.0.113.77"}})
                }
                "cloudtrail" => serde_json::from_slice(include_bytes!(
                    "../../../../../testkit/fixtures/common/cloudtrail-console-login.jsonl"
                ))
                .unwrap(),
                "linux" => {
                    serde_json::json!({"__REALTIME_TIMESTAMP":"1793491200123456","_HOSTNAME":"synthetic-host","SYSLOG_IDENTIFIER":"sshd","_PID":"42","_UID":"1000","MESSAGE":"Failed password for alice from 203.0.113.77 port 22 ssh2"})
                }
                _ => panic!("unknown synthetic source"),
            };
            value["synthetic_padding"] = serde_json::Value::String("x".repeat(900));
            let line = format!("{value}\n");
            let target = std::env::var("IRMIND_PIPELINE_BYTES")
                .ok()
                .map_or(1 << 30, |v| v.parse::<u64>().unwrap());
            let mut out =
                std::io::BufWriter::new(fs::File::create(root.path().join(&name)).unwrap());
            let (mut bytes, mut records) = (0, 0);
            while bytes < target {
                out.write_all(line.as_bytes()).unwrap();
                bytes += line.len() as u64;
                records += 1;
            }
            out.flush().unwrap();
            (bytes, records)
        };
        Self {
            root,
            name,
            bytes,
            records,
        }
    }
}
pub(super) fn catalog(label: &str, root: &Path) -> (Arc<MappingCatalog>, Arc<mapped::Timings>) {
    let (decoder, mappers): (Arc<dyn SourceDecoder>, Vec<Arc<dyn SourceMapper>>) = match label {
        "ocsf" => (
            Arc::new(irmind_mod_parser_ocsf::OcsfSourceDecoder),
            vec![Arc::new(
                irmind_mod_mapping_ocsf::OcsfMapping::new().unwrap(),
            )],
        ),
        "ecs" => (
            Arc::new(irmind_mod_parser_ecs::EcsSourceDecoder),
            vec![Arc::new(irmind_mod_mapping_ecs::EcsMapping::new().unwrap())],
        ),
        "cloudtrail" => (
            Arc::new(irmind_mod_parser_json::JsonSourceDecoder),
            vec![Arc::new(
                irmind_mod_mapping_cloudtrail::CloudTrailMapping::new().unwrap(),
            )],
        ),
        "linux" => (
            Arc::new(irmind_mod_parser_linux::LinuxSourceDecoder),
            vec![Arc::new(
                irmind_mod_mapping_journald_compat::JournaldCompatibilityMapping::new().unwrap(),
            )],
        ),
        "evtx" => {
            let parser = evtx(root);
            assert!(
                parser.unavailable_reason().is_none(),
                "verified EVTX isolation required"
            );
            let mappers = irmind_mod_mapping_evtx::SecurityMapping::EVENT_IDS
                .iter()
                .map(|&id| {
                    Arc::new(irmind_mod_mapping_evtx::SecurityMapping::new(id).unwrap())
                        as Arc<dyn SourceMapper>
                })
                .collect();
            (Arc::new(parser), mappers)
        }
        _ => panic!("unknown synthetic source"),
    };
    mapped::catalog_with(vec![decoder], mappers)
}
fn evtx(root: &Path) -> irmind_mod_parser_evtx::EvtxParser {
    let path = std::env::var_os("IRMIND_EVTX_HELPER_TEST").unwrap();
    irmind_mod_parser_evtx::EvtxParser::new(Path::new(&path), root)
}
pub(super) fn parser(
    label: &str,
    mapped: bool,
    catalog: &MappingCatalog,
    root: &Path,
) -> Box<dyn StreamingEventParser> {
    if mapped {
        let (id, version) = match label {
            "ocsf" => ("parser-ocsf", "ocsf-source-v1"),
            "ecs" => ("parser-ecs", "ecs-source-v1"),
            "cloudtrail" => ("parser-json", "json-source-v1"),
            "linux" => ("parser-linux", "linux-source-v1"),
            "evtx" => ("parser-evtx", "evtx-source-v1"),
            _ => panic!("unknown synthetic source"),
        };
        return Box::new(catalog.decoder_selection(id, version).unwrap());
    }
    match label {
        "ocsf" => Box::new(irmind_mod_parser_ocsf::OcsfParser),
        "ecs" => Box::new(irmind_mod_parser_ecs::EcsParser),
        "cloudtrail" => Box::new(JsonParser),
        "linux" => Box::new(irmind_mod_parser_linux::LinuxParser::default()),
        "evtx" => Box::new(evtx(root)),
        _ => panic!("unknown synthetic source"),
    }
}
