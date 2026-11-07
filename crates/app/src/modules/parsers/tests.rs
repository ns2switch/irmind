use super::*;
use crate::EventParser;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod parser_choice_tests {
    use super::{DetectedParser, ParserChoice, ParserConfidence, choose_parser};

    fn candidate(id: &'static str, confidence: u8) -> DetectedParser {
        DetectedParser {
            id: id.into(),
            confidence: ParserConfidence::new(confidence).unwrap(),
        }
    }

    #[test]
    fn high_unique_candidate_is_automatic() {
        assert_eq!(
            choose_parser(vec![candidate("json", 90)]),
            ParserChoice::Auto(candidate("json", 90))
        );
    }

    #[test]
    fn ties_and_low_confidence_need_analyst() {
        assert!(matches!(
            choose_parser(vec![candidate("json", 90), candidate("ecs", 90)]),
            ParserChoice::NeedsAnalyst(_)
        ));
        assert!(matches!(
            choose_parser(vec![candidate("json", 45)]),
            ParserChoice::NeedsAnalyst(_)
        ));
    }

    #[test]
    fn no_match_is_unsupported() {
        assert_eq!(choose_parser(Vec::new()), ParserChoice::Unsupported);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod parser_router_tests {
    use super::*;
    use irmind_domain::{EvidenceHash, ParserSelectionMode};

    struct FakeParser(&'static str, &'static str);

    impl EventParser for FakeParser {
        fn version(&self) -> &'static str {
            self.1
        }
        fn parse_each(
            &self,
            _: &str,
            _: &[u8],
            _: &CancellationToken,
            _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
        ) -> Result<usize, AppError> {
            Ok(0)
        }
    }
    impl StreamingEventParser for FakeParser {
        fn source_parallelism(&self, _: &str) -> Result<crate::SourceParallelism, AppError> {
            Ok(if self.0 == "parser-json" {
                crate::SourceParallelism::Concurrent
            } else {
                crate::SourceParallelism::Serial
            })
        }

        fn partition_profile(&self, _: &GraphRecord) -> crate::PartitionProfile {
            if self.0 == "parser-json" {
                crate::PartitionProfile::CloudAccountRegion
            } else {
                crate::PartitionProfile::EndpointHost
            }
        }

        fn streaming_version(&self) -> &'static str {
            self.1
        }
        fn parser_name(&self) -> &'static str {
            self.0
        }
        fn parse_reader(
            &self,
            _: &str,
            _: &mut dyn Read,
            _: [u8; 32],
            _: &CancellationToken,
            _: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
        ) -> Result<usize, AppError> {
            Ok(0)
        }
    }
    impl LogParser for FakeParser {
        fn detect(&self, _: &str, _: &[u8]) -> Option<ParserConfidence> {
            None
        }
    }

    #[test]
    fn scheduling_uses_the_selected_source_and_unknown_sources_fail() {
        let concurrent: Arc<dyn LogParser> = Arc::new(FakeParser("parser-json", "v1"));
        let serial: Arc<dyn LogParser> = Arc::new(FakeParser("parser-endpoint", "v1"));
        let router = RebuildParser {
            sources: BTreeMap::from([("a".into(), concurrent), ("b".into(), serial)]),
        };
        assert_eq!(
            router.source_parallelism("a").unwrap(),
            crate::SourceParallelism::Concurrent
        );
        assert_eq!(
            router.source_parallelism("b").unwrap(),
            crate::SourceParallelism::Serial
        );
        assert!(router.source_parallelism("unknown").is_err());
        assert_eq!(
            crate::SourceParser::new(&router, "b")
                .source_parallelism("physical-spool")
                .unwrap(),
            crate::SourceParallelism::Serial
        );
    }

    fn entry(kind: AuditEventKind, payload: String) -> SignedEntry {
        SignedEntry {
            seq: 1,
            case_id: "00000000-0000-0000-0000-000000000001".into(),
            at: 0,
            actor: irmind_domain::Actor::Analyst,
            origin: "system".into(),
            kind,
            payload,
            evidence: None,
            prev: [0; 32],
            hash: [0; 32],
            sig: Vec::new(),
            public_key: Vec::new(),
        }
    }

    #[test]
    fn rebuild_routes_each_source_to_its_signed_parser_version() {
        let mut catalog = ParserCatalog::default();
        catalog.parsers.insert(
            "parser-json".into(),
            Arc::new(FakeParser("parser-json", "json-stream-v2")),
        );
        catalog.parsers.insert(
            "parser-syslog".into(),
            Arc::new(FakeParser("parser-syslog", "syslog-v1")),
        );
        let source = SourceManifestV1 {
            source: "system.log".into(),
            size: 1,
            modified_unix_seconds: None,
            version: None,
            provider_checksum: None,
            sha256: EvidenceHash::parse(&"a".repeat(64)).unwrap(),
            copied: false,
        };
        let selection = SourceManifestV2 {
            source,
            parser_id: "parser-syslog".into(),
            parser_version: "syslog-v1".into(),
            confidence: 95,
            selection: ParserSelectionMode::Automatic,
            timestamp_context: None,
            rejected_records: 0,
            rejected_sample: Vec::new(),
        };
        let router = catalog
            .rebuild_router(&[entry(
                AuditEventKind::SourceManifestV2,
                selection.encode().unwrap(),
            )])
            .unwrap();
        assert_eq!(
            router.version_for_source("system.log").unwrap(),
            "syslog-v1"
        );
        assert!(router.version_for_source("other.log").is_err());
    }

    #[test]
    fn profile_router_uses_only_the_signed_source_and_default_native_callback() {
        let router = RebuildParser {
            sources: BTreeMap::from([
                (
                    "cloud.json".into(),
                    Arc::new(FakeParser("parser-json", "json-stream-v2")) as Arc<dyn LogParser>,
                ),
                (
                    "audit.log".into(),
                    Arc::new(FakeParser("parser-linux", "linux-v2")) as Arc<dyn LogParser>,
                ),
            ]),
        };
        let record = GraphRecord {
            index: 0,
            at: String::new(),
            event: String::new(),
            text: "{}".into(),
            entities: Vec::new(),
            relations: Vec::new(),
        };
        assert_eq!(
            router
                .partition_profile_for_source("cloud.json", &record)
                .unwrap(),
            crate::PartitionProfile::CloudAccountRegion
        );
        assert_eq!(
            router
                .partition_profile_for_source("audit.log", &record)
                .unwrap(),
            crate::PartitionProfile::EndpointHost
        );
        assert!(
            router
                .partition_profile_for_source("unknown", &record)
                .is_err()
        );
    }

    #[test]
    fn optional_time_context_does_not_change_existing_parser_defaults_or_identity() {
        let parser = FakeParser("parser-json", "json-stream-v2");
        assert!(
            parser
                .time_context_requirement("sample.json", b"{}")
                .unwrap()
                .is_none()
        );
        let context =
            crate::ParserTimeContext::new(2026, 0, true, crate::ParserTimeBasis::Command).unwrap();
        assert!(matches!(
            parser.with_time_context(&context),
            Err(AppError::ParserTimeUnsupported)
        ));
        let mut catalog = ParserCatalog::default();
        catalog
            .parsers
            .insert("parser-json".into(), Arc::new(parser));
        let selected = catalog
            .select_source(crate::modules::ParserSelectionRequest {
                source: "sample.json",
                sample: b"{}",
                parser_override: Some("parser-json"),
                forced: true,
                time_context: Some(context),
            })
            .unwrap();
        assert_eq!(selected.selection.parser_version, "json-stream-v2");
        assert_eq!(selected.selection.timestamp_context, None);
    }
}
