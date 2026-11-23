//! Deterministic, bounded PDF using only fixed page objects and text operands.
use super::literal::{defang, needs_visible_escape};
use crate::AppError;
use std::io::Write;

const MAX_DOCUMENT: usize = 64 * 1024 * 1024;
const WIDTH: usize = 86;
const LINES_PER_PAGE: usize = 54;

pub fn render_text_pdf<'a>(lines: impl IntoIterator<Item = &'a str>) -> Result<Vec<u8>, AppError> {
    let mut pages = Pages::default();
    for line in lines {
        pages.line(line)?;
    }
    if pages.count == 0 || pages.current_lines != 0 {
        pages.close_page()?;
    }
    pages.finish()
}

#[derive(Default)]
struct Pages {
    document: Vec<u8>,
    object_offsets: Vec<usize>,
    page_content: Vec<u8>,
    current_lines: usize,
    count: usize,
}

impl Pages {
    fn line(&mut self, value: &str) -> Result<(), AppError> {
        let mut line = Vec::with_capacity(WIDTH);
        for ch in value.chars() {
            if let Some(defanged) = defang(ch) {
                self.append_text(&mut line, defanged.as_bytes())?;
            } else if let Some(byte) = winansi(ch) {
                self.append_text(&mut line, &[byte])?;
            } else {
                let escaped = ch.escape_unicode().to_string();
                self.append_text(&mut line, escaped.as_bytes())?;
            }
        }
        self.emit_line(&line)
    }

    fn append_text(&mut self, line: &mut Vec<u8>, text: &[u8]) -> Result<(), AppError> {
        if line.len() + text.len() > WIDTH {
            self.emit_line(line)?;
            line.clear();
        }
        line.extend_from_slice(text);
        Ok(())
    }

    fn emit_line(&mut self, line: &[u8]) -> Result<(), AppError> {
        if self.current_lines == LINES_PER_PAGE {
            self.close_page()?;
        }
        self.page_content.push(b'(');
        for byte in line {
            if matches!(byte, b'(' | b')' | b'\\') {
                self.page_content.push(b'\\');
            }
            self.page_content.push(*byte);
        }
        self.page_content.extend_from_slice(b") Tj T*\n");
        self.current_lines += 1;
        Ok(())
    }

    fn close_page(&mut self) -> Result<(), AppError> {
        if self.count == 0 {
            self.document
                .extend_from_slice(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n");
        }
        let page = 4 + 2 * self.count;
        self.object(
            page,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>\n",
                page + 1
            ).as_bytes(),
        )?;
        let opening = b"BT\n/F1 10 Tf\n12 TL\n48 750 Td\n";
        let closing = b"ET\n";
        let content = std::mem::take(&mut self.page_content);
        let mut stream = format!(
            "<< /Length {} >>\nstream\n",
            opening.len() + content.len() + closing.len()
        )
        .into_bytes();
        stream.extend_from_slice(opening);
        stream.extend_from_slice(&content);
        stream.extend_from_slice(closing);
        stream.extend_from_slice(b"endstream\n");
        self.object(page + 1, &stream)?;
        self.count += 1;
        self.current_lines = 0;
        Ok(())
    }

    fn object(&mut self, id: usize, body: &[u8]) -> Result<(), AppError> {
        self.check_size(body.len() + 32)?;
        if self.object_offsets.len() <= id {
            self.object_offsets.resize(id + 1, 0);
        }
        self.object_offsets[id] = self.document.len();
        writeln!(self.document, "{id} 0 obj").map_err(storage)?;
        self.document.extend_from_slice(body);
        self.document.extend_from_slice(b"endobj\n");
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, AppError> {
        self.object(1, b"<< /Type /Catalog /Pages 2 0 R >>\n")?;
        let mut pages = format!("<< /Type /Pages /Count {} /Kids [", self.count).into_bytes();
        for page in 0..self.count {
            write!(&mut pages, "{} 0 R ", 4 + 2 * page).map_err(storage)?;
        }
        pages.extend_from_slice(b"] >>\n");
        self.object(2, &pages)?;
        self.object(
            3,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>\n",
        )?;
        let xref = self.document.len();
        let objects = self.object_offsets.len();
        self.check_size(objects * 20 + 256)?;
        write!(self.document, "xref\n0 {objects}\n0000000000 65535 f \n").map_err(storage)?;
        for offset in self.object_offsets.into_iter().skip(1) {
            writeln!(self.document, "{offset:010} 00000 n ").map_err(storage)?;
        }
        write!(
            self.document,
            "trailer\n<< /Size {objects} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
        )
        .map_err(storage)?;
        Ok(self.document)
    }

    fn check_size(&self, additional: usize) -> Result<(), AppError> {
        if additional > MAX_DOCUMENT - self.document.len() {
            return Err(AppError::Storage("report PDF exceeds 64 MiB".into()));
        }
        Ok(())
    }
}

fn winansi(ch: char) -> Option<u8> {
    match ch {
        ' '..='~' | '\u{00a0}'..='\u{00ff}' if !needs_visible_escape(ch) => Some(ch as u8),
        _ => None,
    }
}

fn storage(_: std::io::Error) -> AppError {
    AppError::Storage("report PDF rendering failed".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    #[test]
    fn pdf_bytes_and_layout_are_deterministic() {
        let data = [
            "Informe sintético",
            "(test) \\script https://test.invalid",
            "user@example.invalid \u{202e} \u{1f600}",
        ];
        let pdf = render_text_pdf(data).unwrap();
        assert_eq!(pdf, render_text_pdf(data).unwrap());
        let visible = String::from_utf8_lossy(&pdf);
        assert!(visible.contains("(\\(test\\) \\\\script https[:]//test[.]invalid)"));
        assert!(visible.contains("user[@]example[.]invalid"));
        assert!(visible.contains(r"\\u{202e} \\u{1f600}"));
        let xref = visible
            .split("startxref\n")
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(&pdf[xref..xref + 5], b"xref\n");
        for marker in ["/URI", "/Launch", "/JavaScript", "/EmbeddedFile", "/Annots"] {
            assert!(!visible.contains(marker));
        }
    }

    #[test]
    fn pdf_pages_wrap_long_lines_and_keep_every_text_operand() {
        let long = "x".repeat(WIDTH + 1);
        let data = std::iter::repeat_n("same line", LINES_PER_PAGE).chain([long.as_str()]);
        let pdf = render_text_pdf(data).unwrap();
        let visible = String::from_utf8_lossy(&pdf);
        assert!(visible.contains("/Count 2"));
        assert!(visible.contains(&format!("({}) Tj T*\n(x) Tj T*", "x".repeat(WIDTH))));
    }

    #[test]
    #[ignore = "run explicitly with Poppler installed"]
    fn pdf_is_readable_by_poppler() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("report.pdf");
        let pdf =
            render_text_pdf(["Análisis de ejecución", "(literal) https://test.invalid"]).unwrap();
        fs::write(&path, pdf).unwrap();
        let result = Command::new("pdftotext")
            .arg(path)
            .arg("-")
            .output()
            .unwrap();
        assert!(result.status.success());
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(text.contains("Análisis de ejecución"));
        assert!(text.contains("(literal) https[:]//test[.]invalid"));
    }
}
