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
}
