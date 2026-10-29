use ratatui::style::{Color, Style};

#[derive(Clone, Copy)]
pub(crate) struct Theme {
    pub accent: Color,
    pub text: Color,
    pub muted: Color,
    pub border: Color,
    pub warning: Color,
    pub error: Color,
    pub success: Color,
    pub user_background: Color,
}

impl Theme {
    pub(crate) fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            return Self::plain();
        }
        let configured = std::env::var("IRMIND_THEME").ok();
        let terminal = std::env::var("COLORFGBG").ok();
        let light = Self::is_light(configured.as_deref(), terminal.as_deref());
        if light { Self::light() } else { Self::dark() }
    }

    fn is_light(configured: Option<&str>, terminal: Option<&str>) -> bool {
        match configured {
            Some("light") => true,
            Some("dark") => false,
            _ => terminal.is_some_and(|value| {
                value
                    .rsplit(';')
                    .next()
                    .and_then(|number| number.parse::<u8>().ok())
                    .is_some_and(|background| background >= 7 && background != 8)
            }),
        }
    }

    pub(crate) const fn plain() -> Self {
        Self {
            accent: Color::Reset,
            text: Color::Reset,
            muted: Color::Reset,
            border: Color::Reset,
            warning: Color::Reset,
            error: Color::Reset,
            success: Color::Reset,
            user_background: Color::Reset,
        }
    }

    const fn dark() -> Self {
        Self {
            accent: Color::Rgb(125, 190, 255),
            text: Color::Rgb(230, 233, 239),
            muted: Color::Rgb(145, 153, 169),
            border: Color::Rgb(95, 104, 122),
            warning: Color::Rgb(255, 190, 95),
            error: Color::Rgb(255, 120, 125),
            success: Color::Rgb(130, 215, 170),
            user_background: Color::Rgb(35, 42, 55),
        }
    }

    const fn light() -> Self {
        Self {
            accent: Color::Rgb(0, 80, 160),
            text: Color::Rgb(31, 42, 58),
            muted: Color::Rgb(82, 93, 106),
            border: Color::Rgb(115, 125, 139),
            warning: Color::Rgb(155, 80, 0),
            error: Color::Rgb(170, 30, 45),
            success: Color::Rgb(15, 110, 70),
            user_background: Color::Rgb(230, 236, 245),
        }
    }

    pub(crate) fn accent(self) -> Style {
        Style::default().fg(self.accent)
    }
    pub(crate) fn muted(self) -> Style {
        Style::default().fg(self.muted)
    }
    pub(crate) fn warning(self) -> Style {
        Style::default().fg(self.warning)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monochrome_has_no_color_tokens() {
        let theme = Theme::plain();
        assert_eq!(theme.warning, Color::Reset);
        assert_eq!(theme.user_background, Color::Reset);
    }

    #[test]
    fn configured_theme_overrides_terminal_background() {
        assert!(!Theme::is_light(Some("dark"), Some("0;15")));
        assert!(Theme::is_light(Some("light"), Some("0;0")));
        assert!(Theme::is_light(None, Some("0;15")));
    }
}
