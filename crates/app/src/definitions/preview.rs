use super::{DefinitionCompiler, Engine, MAX_DEFINITION_BYTES};
use crate::{AppError, CancellationToken};
use std::io::{Cursor, Read};

impl Engine<'_> {
    pub fn preview_parser_definition(
        &self,
        compiler: &dyn DefinitionCompiler,
        definition: &str,
        sample: &[u8],
    ) -> Result<String, AppError> {
        if definition.len() > MAX_DEFINITION_BYTES || sample.len() > 1024 * 1024 {
            return Err(AppError::Fixed(crate::FixedAppError::Definition(
                super::DefinitionError::PreviewLimit,
            )));
        }
        let parser = compiler.compile(definition)?;
        let confidence = parser
            .detect("preview.log", &sample[..sample.len().min(65536)])
            .map_or(0, crate::ParserConfidence::value);
        let cancel = CancellationToken::new();
        let mut rows = Vec::new();
        let mut reader = Cursor::new(sample).take(1024 * 1024);
        let outcome = parser.parse_reader_report(
            "preview.log",
            &mut reader,
            crate::sha256(sample),
            &cancel,
            &mut |row| {
                if rows.len() == 10 {
                    return Err(AppError::Cancelled);
                }
                row.inspect(|record| rows.push(record.text.chars().take(4096).collect::<String>()));
                Ok(())
            },
        );
        let rejected = match outcome {
            Ok(report) => report.rejected.to_string(),
            Err(AppError::Cancelled) if rows.len() == 10 => "preview stopped after ten rows".into(),
            Err(error) => return Err(error),
        };
        let identity = parser.identity();
        let mut result = format!(
            "{} · {} · {}% confidence · {} preview rows · rejected: {rejected}\n",
            identity.name,
            identity.version,
            confidence,
            rows.len()
        );
        for row in rows {
            result.push_str(&self.guard.screen(&row)?.text);
            result.push('\n');
        }
        self.guard.screen(&result).map(|value| value.text)
    }
}
