//! Bounded screen reconstruction for the ASCII assertions in the `ConPTY` tests.
//! `ConPTY` can repaint part of a word instead of emitting a fresh text line.

#[derive(Default)]
enum Control {
    #[default]
    Text,
    Escape,
    Csi(Vec<u8>),
    Osc(bool),
}

pub(super) struct TerminalScreen {
    cells: Vec<Vec<char>>,
    row: usize,
    col: usize,
    control: Control,
    utf8: Vec<u8>,
}

impl TerminalScreen {
    pub(super) fn new(rows: usize, columns: usize) -> Self {
        Self {
            cells: vec![vec![' '; columns]; rows],
            row: 0,
            col: 0,
            control: Control::Text,
            utf8: Vec::with_capacity(4),
        }
    }

    pub(super) fn feed(&mut self, input: &[u8]) {
        for &byte in input {
            match std::mem::take(&mut self.control) {
                Control::Text => self.text_byte(byte),
                Control::Escape => {
                    self.control = match byte {
                        b'[' => Control::Csi(Vec::new()),
                        b']' => Control::Osc(false),
                        _ => Control::Text,
                    };
                }
                Control::Csi(mut parameters) => {
                    if (0x40..=0x7e).contains(&byte) {
                        self.csi(&parameters, byte);
                    } else if parameters.len() < 64 {
                        parameters.push(byte);
                        self.control = Control::Csi(parameters);
                    }
                }
                Control::Osc(escaped) => {
                    if byte != 7 && !(escaped && byte == b'\\') {
                        self.control = Control::Osc(byte == 27);
                    }
                }
            }
        }
    }

    pub(super) fn text(&self) -> String {
        self.cells
            .iter()
            .map(|line| line.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn text_byte(&mut self, byte: u8) {
        match byte {
            27 => {
                self.utf8.clear();
                self.control = Control::Escape;
            }
            b'\r' => self.col = 0,
            b'\n' => self.newline(),
            8 => self.col = self.col.saturating_sub(1),
            0..=31 | 127 => {}
            32..=126 => self.put(char::from(byte)),
            _ => {
                self.utf8.push(byte);
                if let Ok(value) = std::str::from_utf8(&self.utf8) {
                    if let Some(value) = value.chars().next() {
                        self.put(value);
                    }
                    self.utf8.clear();
                } else if self.utf8.len() == 4 {
                    self.utf8.clear();
                }
            }
        }
    }

    fn put(&mut self, value: char) {
        if self.col >= self.cells[0].len() {
            self.col = 0;
            self.newline();
        }
        self.cells[self.row][self.col] = value;
        // The English test UI uses single-cell box drawing and ASCII labels.
        // These tests do not emulate arbitrary wide/combining user input.
        self.col += 1;
    }

    fn newline(&mut self) {
        if self.row + 1 == self.cells.len() {
            self.cells.rotate_left(1);
            self.cells[self.row].fill(' ');
        } else {
            self.row += 1;
        }
    }

    fn csi(&mut self, raw: &[u8], command: u8) {
        let raw = std::str::from_utf8(raw).unwrap_or("");
        if raw.starts_with('?') {
            if raw == "?1049" && matches!(command, b'h' | b'l') {
                self.clear();
            }
            return;
        }
        let mut params = raw.split(';').map(|p| p.parse::<usize>().unwrap_or(0));
        let first = params.next().unwrap_or(0);
        let count = first.max(1);
        match command {
            b'H' | b'f' => {
                self.row = first.saturating_sub(1).min(self.cells.len() - 1);
                self.col = params.next().unwrap_or(1).saturating_sub(1);
            }
            b'A' => self.row = self.row.saturating_sub(count),
            b'B' => self.row = self.row.saturating_add(count).min(self.cells.len() - 1),
            b'C' => self.col = self.col.saturating_add(count),
            b'D' => self.col = self.col.saturating_sub(count),
            b'G' => self.col = first.saturating_sub(1),
            b'd' => self.row = first.saturating_sub(1).min(self.cells.len() - 1),
            b'J' if first == 2 || first == 3 => self.clear(),
            b'K' => self.erase_line(first),
            _ => {}
        }
        self.col = self.col.min(self.cells[0].len() - 1);
    }

    fn erase_line(&mut self, mode: usize) {
        let col = self.col.min(self.cells[0].len() - 1);
        let line = &mut self.cells[self.row];
        match mode {
            1 => line[..=col].fill(' '),
            2 => line.fill(' '),
            _ => line[col..].fill(' '),
        }
    }

    fn clear(&mut self) {
        for line in &mut self.cells {
            line.fill(' ');
        }
        self.row = 0;
        self.col = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::TerminalScreen;

    #[test]
    fn reconstructs_words_from_cursor_repaints_and_split_utf8() {
        let mut screen = TerminalScreen::new(4, 40);
        screen.feed(b"Do: /search\x1b[1;6Hneigh\x1b[1;11Hbors\x1b[K");
        assert!(screen.text().contains("Do: /neighbors"));
        screen.feed(b"\x1b[2;1H\xe2\x94");
        screen.feed(b"\x82 ready");
        assert!(screen.text().contains("\u{2502} ready"));
        screen.feed(b"\r\x1b[2KDone");
        assert!(!screen.text().contains("ready"));
    }

    #[test]
    fn ignores_titles_styles_and_cursor_queries_and_clears_old_frames() {
        let mut screen = TerminalScreen::new(4, 40);
        screen.feed(b"\x1b]0;neighbors\x07\x1b[6n\x1b[31mDo: /timeline");
        assert!(!screen.text().contains("neighbors"));
        assert!(screen.text().contains("Do: /timeline"));
        screen.feed(b"\x1b[?1049hDo: /search");
        assert!(!screen.text().contains("timeline"));
        assert!(screen.text().contains("Do: /search"));
    }
}
