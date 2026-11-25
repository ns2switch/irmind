//! Use one byte contract for the Linux, macOS and Windows renderers.
#![allow(clippy::unwrap_used)]

use irmind_app::{
    ReportDocument, ReportDocumentFormat as Format, ReportDocumentLanguage as Language,
    ReportLimitation, ReportLocator, ReportStatement, hex, sha256,
};
use irmind_domain::{CaseId, EvidenceHash};
use std::{fmt::Write as _, fs, path::PathBuf};

#[test]
fn report_bytes_match_on_each_platform() {
    let id = CaseId::parse("00000000-0000-4000-8000-000000000006").unwrap();
    let evidence = EvidenceHash::from_bytes([1; 32]);
    let artifact = EvidenceHash::from_bytes([2; 32]);
    let receipt = EvidenceHash::from_bytes([3; 32]);
    let citations = [
        ReportLocator::Record {
            evidence: evidence.clone(),
            record: 17,
        },
        ReportLocator::Artifact { evidence, artifact },
    ];
    let statements = [ReportStatement {
        text: concat!(
            r"Análisis (literal) \ ) Tj /Action /URI /JavaScript /Launch /EmbeddedFile /Annots /Type /Annot",
            " — [link](https://fixture.invalid) mail@fixture.invalid\u{202e}\nSecond line",
        ),
        selected_by_model: true,
        citations: &citations,
    }];
    let notes = "Línea de alcance: (literal) [fixture].\n".repeat(55);
    let limitations = [
        ReportLimitation::QueryLimit { receipt: &receipt },
        ReportLimitation::PartialSigma { receipt: &receipt },
        ReportLimitation::SkillCoverage {
            skill: "triage",
            gap: "sin DNS",
        },
    ];
    let document = ReportDocument {
        case_id: &id,
        title: "Synthetic case · análisis",
        confirmed: &statements,
        analyst: Some([&notes, "Metodología", "", "Review sources"]),
        limitations: &limitations,
    };
    let destination = std::env::var_os("IRMIND_REPORT_FIXTURE_DIR").map(PathBuf::from);
    let mut hashes = String::new();
    for (locale, language) in [("en", Language::English), ("es", Language::Spanish)] {
        for (extension, format) in [("md", Format::Markdown), ("pdf", Format::Pdf)] {
            let name = format!("report-{locale}.{extension}");
            let bytes = document.render(language, format).unwrap();
            if let Some(destination) = &destination {
                fs::create_dir_all(destination).unwrap();
                fs::write(destination.join(&name), &bytes).unwrap();
            }
            writeln!(hashes, "{}  {name}", hex(&sha256(&bytes))).unwrap();
        }
    }
    assert_eq!(
        hashes,
        include_str!("fixtures/reports/SHA256SUMS").replace("\r\n", "\n")
    );
}
