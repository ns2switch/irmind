//! Render a bounded report document with shared bilingual structure and citations.
use super::{render_report_literal, render_text_pdf};
use crate::AppError;
use irmind_domain::{CaseId, EvidenceHash};
use std::fmt::Write as _;

const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportDocumentLanguage {
    English,
    Spanish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportDocumentFormat {
    Markdown,
    Pdf,
}

pub struct ReportDocument<'a> {
    pub case_id: &'a CaseId,
    pub title: &'a str,
    pub confirmed: &'a [ReportStatement<'a>],
    pub analyst: Option<[&'a str; 4]>,
    pub limitations: &'a [ReportLimitation<'a>],
}

pub struct ReportStatement<'a> {
    pub text: &'a str,
    pub selected_by_model: bool,
    pub citations: &'a [ReportLocator],
}

/// Public reference text uses validated SHA-256 values. Case and artifact
/// resolution takes place before the report document is built.
pub enum ReportLocator {
    Record {
        evidence: EvidenceHash,
        record: u64,
    },
    Artifact {
        evidence: EvidenceHash,
        artifact: EvidenceHash,
    },
}

pub enum ReportLimitation<'a> {
    UnavailableSource(&'a str),
    FolderOutcome(&'a crate::ingest_outcome::FileOutcomeNotice),
    SourceAvailabilityUnknown(&'a str),
    SkillCoverage {
        skill: &'a str,
        gap: &'a str,
    },
    DelegatedSkillCoverage {
        skill: &'a str,
        gap: &'a str,
        task_id: &'a [u8; 32],
    },
    QueryLimit {
        receipt: &'a EvidenceHash,
    },
    SigmaSourceClasses(&'a crate::v10_proofs::SigmaV3Notice),
}

impl ReportDocument<'_> {
    pub fn render(
        &self,
        language: ReportDocumentLanguage,
        format: ReportDocumentFormat,
    ) -> Result<Vec<u8>, AppError> {
        let mut out = Document {
            lines: Vec::new(),
            format,
            bytes: 0,
        };
        out.heading(1, language.text("Incident report", "Informe del incidente"))?;
        out.heading(2, &out.literal(self.title))?;
        out.line(format!(
            "{} {}",
            language.text("Case", "Caso"),
            self.case_id.as_str()
        ))?;
        out.heading(
            2,
            language.text("Confirmed findings", "Hallazgos confirmados"),
        )?;
        if self.confirmed.is_empty() {
            out.line(
                language
                    .text("No cited findings.", "Sin hallazgos con cita.")
                    .into(),
            )?;
        }
        for statement in self.confirmed {
            out.statement(statement, language)?;
        }
        if let Some(sections) = self.analyst {
            out.heading(
                2,
                language.text("Analyst-authored sections", "Secciones del analista"),
            )?;
            let titles = [
                language.text("Scope", "Alcance"),
                language.text("Methodology", "Metodología"),
                language.text("Context", "Contexto"),
                language.text("Recommendations", "Recomendaciones"),
            ];
            for (title, section) in titles.into_iter().zip(sections) {
                out.heading(3, title)?;
                for line in section.lines() {
                    out.line(out.literal(line))?;
                }
            }
        }
        out.heading(
            2,
            language.text("Limitations and coverage", "Limitaciones y cobertura"),
        )?;
        if self.limitations.is_empty() {
            out.line(
                language
                    .text(
                        "No limitations were recorded by these checks.",
                        "Estas comprobaciones no registraron limitaciones.",
                    )
                    .into(),
            )?;
        }
        for limitation in self.limitations {
            out.limitation(limitation, language)?;
        }
        out.finish()
    }
}

impl ReportDocumentLanguage {
    fn text<'a>(self, english: &'a str, spanish: &'a str) -> &'a str {
        match self {
            Self::English => english,
            Self::Spanish => spanish,
        }
    }
}

struct Document {
    lines: Vec<String>,
    format: ReportDocumentFormat,
    bytes: usize,
}

impl Document {
    fn line(&mut self, value: String) -> Result<(), AppError> {
        self.bytes = self
            .bytes
            .checked_add(value.len())
            .and_then(|len| len.checked_add(1))
            .filter(|len| *len <= MAX_REPORT_BYTES)
            .ok_or_else(|| AppError::Storage("report exceeds 64 MiB".into()))?;
        self.lines.push(value);
        Ok(())
    }

    fn literal(&self, value: &str) -> String {
        match self.format {
            ReportDocumentFormat::Markdown => render_report_literal(value),
            ReportDocumentFormat::Pdf => value.to_owned(),
        }
    }

    fn heading(&mut self, level: usize, title: &str) -> Result<(), AppError> {
        if !self.lines.is_empty() {
            self.line(String::new())?;
        }
        let title = match self.format {
            ReportDocumentFormat::Markdown => format!("{} {title}", "#".repeat(level)),
            ReportDocumentFormat::Pdf => title.to_owned(),
        };
        self.line(title)?;
        self.line(String::new())
    }

    fn statement(
        &mut self,
        statement: &ReportStatement<'_>,
        language: ReportDocumentLanguage,
    ) -> Result<(), AppError> {
        if statement.citations.is_empty() {
            return Err(AppError::Storage(
                "report finding requires a verified citation".into(),
            ));
        }
        let statement_text = self.literal(statement.text);
        let mut text = format!("- {statement_text}");
        if statement.selected_by_model {
            text.push_str(
                language.text(" (selected by the model)", " (seleccionado por el modelo)"),
            );
        }
        self.line(text)?;
        for locator in statement.citations {
            let mut reference = String::from("  - SHA-256 ");
            match locator {
                ReportLocator::Record { evidence, record } => {
                    write!(
                        reference,
                        "{} · {} {record}",
                        evidence.as_str(),
                        language.text("record", "registro")
                    )
                }
                ReportLocator::Artifact { evidence, artifact } => {
                    write!(
                        reference,
                        "{} · {} SHA-256 {}",
                        evidence.as_str(),
                        language.text("artifact", "artefacto"),
                        artifact.as_str()
                    )
                }
            }
            .map_err(|_| AppError::Storage("report citation formatting failed".into()))?;
            self.line(reference)?;
        }
        Ok(())
    }

    fn limitation(
        &mut self,
        limitation: &ReportLimitation<'_>,
        language: ReportDocumentLanguage,
    ) -> Result<(), AppError> {
        let text = match limitation {
            ReportLimitation::FolderOutcome(notice) => {
                return self.folder_outcome(language, notice);
            }
            ReportLimitation::UnavailableSource(source) => format!(
                "{} {}",
                language.text("Unavailable source", "Fuente no disponible"),
                self.literal(source),
            ),
            ReportLimitation::SourceAvailabilityUnknown(source) => format!(
                "{} {}",
                language.text("Source availability unknown", "Disponibilidad desconocida"),
                self.literal(source),
            ),
            ReportLimitation::SkillCoverage { skill, gap } => format!(
                "{} {} · {}",
                language.text("Skill coverage gap", "Hueco de cobertura de la skill"),
                self.literal(skill),
                self.literal(gap),
            ),
            ReportLimitation::DelegatedSkillCoverage {
                skill,
                gap,
                task_id,
            } => format!(
                "{} {} · {} · {}",
                language.text(
                    "Subagent skill coverage gap",
                    "Hueco de cobertura de la skill del subagente"
                ),
                crate::hex(*task_id),
                self.literal(skill),
                self.literal(gap),
            ),
            ReportLimitation::QueryLimit { receipt } => format!(
                "{} {}",
                language.text(
                    "Query reached its result limit. More rows may exist.",
                    "La consulta alcanzó su límite. Puede haber más filas."
                ),
                receipt.as_str(),
            ),
            ReportLimitation::SigmaSourceClasses(notice) => {
                return self.sigma_coverage(language, notice);
            }
        };
        self.line(format!("- {text}"))
    }

    fn folder_outcome(
        &mut self,
        language: ReportDocumentLanguage,
        notice: &crate::ingest_outcome::FileOutcomeNotice,
    ) -> Result<(), AppError> {
        let (path, reason) = notice.description();
        self.line(format!(
            "- {} {} · {} · #{} · SHA-256 {}",
            language.text("Folder ingestion", "Ingesta de carpeta"),
            self.literal(path),
            reason,
            notice.sequence,
            notice.hash.as_str()
        ))
    }

    fn sigma_coverage(
        &mut self,
        language: ReportDocumentLanguage,
        notice: &crate::v10_proofs::SigmaV3Notice,
    ) -> Result<(), AppError> {
        let counts = &notice.coverage;
        self.line(format!(
            "- {} {} · {}/{}/{} · {}/{}",
            language.text(
                "Sigma source-class plan (rules with all/some/no eligible classes, eligible/skipped pairs)",
                "Plan de Sigma por clase (reglas con todas/algunas/ninguna clase apta, pares aptos/omitidos)",
            ),
            notice.receipt.as_str(),
            counts.all_rules, counts.some_rules, counts.no_rules,
            counts.eligible_pairs, counts.skipped_pairs,
        ))?;
        if counts.skipped_pairs != 0 || counts.no_rules != 0 {
            self.line(format!(
                "- {}",
                language.text(
                    "Activity covered by skipped rules or source classes remains undetermined.",
                    "La actividad de las reglas o clases de fuente omitidas queda sin determinar.",
                )
            ))?;
        }
        for (label, missing, incompatible) in &notice.skipped_classes {
            self.line(format!(
                "- {} · {missing} {} · {incompatible} {}",
                self.literal(label),
                language.text("missing bindings", "correspondencias ausentes"),
                language.text("incompatible types", "tipos incompatibles"),
            ))?;
        }
        if notice.unavailable_rows != 0 {
            self.line(format!(
                "- {} · {} · {}",
                language.text(
                    "Rows with unavailable exact fields / rules with indeterminate rows",
                    "Filas con campos exactos no disponibles / reglas con filas indeterminadas",
                ),
                notice.unavailable_rows,
                notice.indeterminate_rules,
            ))?;
            self.line(format!("- {}", language.text(
                "Sigma cannot decide results for those rows. Unexpected values may indicate source manipulation.",
                "Sigma no puede decidir el resultado de esas filas. Los valores inesperados pueden indicar manipulación de la fuente.",
            )))?;
        }
        if notice.stopped_early {
            self.line(format!("- {}", language.text(
                "The Sigma scan stopped early. The source-class counts describe the plan.",
                "La búsqueda de Sigma se detuvo antes del final. Los recuentos por clase describen el plan.",
            )))?;
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, AppError> {
        match self.format {
            ReportDocumentFormat::Markdown => {
                let mut bytes = Vec::with_capacity(self.bytes);
                for line in self.lines {
                    bytes.extend_from_slice(line.as_bytes());
                    bytes.push(b'\n');
                }
                Ok(bytes)
            }
            ReportDocumentFormat::Pdf => render_text_pdf(self.lines.iter().map(String::as_str)),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn two_languages_have_literal_citations_and_a_separate_coverage_section() {
        let case_id = CaseId::parse("00000000-0000-4000-8000-000000000006").unwrap();
        let evidence = EvidenceHash::from_bytes([1; 32]);
        let query = EvidenceHash::from_bytes([2; 32]);
        let references = [ReportLocator::Record {
            evidence: evidence.clone(),
            record: 17,
        }];
        let statements = [ReportStatement {
            text: "[untrusted](https://demo.invalid)",
            selected_by_model: true,
            citations: &references,
        }];
        let document = ReportDocument {
            case_id: &case_id,
            title: "Synthetic",
            confirmed: &statements,
            analyst: Some(["Simple scope", "", "", "Review sources"]),
            limitations: &[ReportLimitation::QueryLimit { receipt: &query }],
        };
        for (locale, heading, location) in [
            (
                ReportDocumentLanguage::English,
                "Limitations and coverage",
                "record 17",
            ),
            (
                ReportDocumentLanguage::Spanish,
                "Limitaciones y cobertura",
                "registro 17",
            ),
        ] {
            let markdown = document
                .render(locale, ReportDocumentFormat::Markdown)
                .unwrap();
            let text = std::str::from_utf8(&markdown).unwrap();
            assert!(text.contains(heading));
            assert!(text.contains(location));
            assert!(text.contains(evidence.as_str()));
            assert!(text.contains(query.as_str()));
            assert!(!text.contains("https://"));
            let pdf = document.render(locale, ReportDocumentFormat::Pdf).unwrap();
            assert_eq!(
                pdf,
                document.render(locale, ReportDocumentFormat::Pdf).unwrap()
            );
        }
        let uncited = ReportDocument {
            confirmed: &[ReportStatement {
                text: "Uncited",
                selected_by_model: false,
                citations: &[],
            }],
            ..document
        };
        assert!(
            uncited
                .render(
                    ReportDocumentLanguage::English,
                    ReportDocumentFormat::Markdown
                )
                .is_err()
        );
    }
}
