#![allow(clippy::unwrap_used)]

#[path = "support/terminal_screen.rs"]
mod terminal_screen;

use terminal_screen::TerminalScreen;

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

#[test]
fn erase_sequences_remove_old_confirmation_text_without_moving_the_cursor() {
    let mut screen = TerminalScreen::new(4, 40);
    screen.feed(b"Confirmed finding\x1b[1;1H\x1b[9X");
    assert!(!screen.text().contains("Confirm"));
    screen.feed(b"New\x1b[0J");
    assert!(screen.text().starts_with("New "));
    assert!(!screen.text().contains("finding"));
    screen.feed(b"\x1b[3;5HOld\x1b[2JNow");
    assert_eq!(screen.text().lines().nth(2).unwrap().find("Now"), Some(7));
}
