//! Linear, bounded differences over the exact reviewed packages.
use super::super::history::Snapshot;
use crate::{AppError, CompiledSkill, Engine};
use std::{collections::BTreeSet, fmt::Write as _};
const DIFF_BYTES: usize = 16 * 1024;
impl Engine<'_> {
    pub(super) fn catalog_differences(
        &self,
        previous: Option<&Snapshot>,
        candidate: &CompiledSkill,
    ) -> Result<String, AppError> {
        let mut text = String::new();
        let Some(old) = previous else {
            return Ok("New installation.".into());
        };
        let _ = writeln!(
            text,
            "Previous package: {} · version {}",
            old.package_sha256, old.skill_version
        );
        let package = old.package()?;
        let paths = package
            .resources()
            .keys()
            .chain(candidate.package().resources().keys())
            .collect::<BTreeSet<_>>();
        let mut truncated = false;
        for path in paths {
            let before = package
                .resources()
                .get(path)
                .map_or("", |r| r.untrusted_text());
            let after = candidate
                .package()
                .resources()
                .get(path)
                .map_or("", |r| r.untrusted_text());
            if before != after {
                if text
                    .len()
                    .saturating_add(path.as_str().len().saturating_mul(2))
                    .saturating_add(10)
                    > DIFF_BYTES
                {
                    truncated = true;
                    break;
                }
                let _ = writeln!(text, "--- {}\n+++ {}", path.as_str(), path.as_str());
                if !difference_lines(&mut text, before, after) {
                    truncated = true;
                    break;
                }
            }
        }
        if truncated {
            text.push_str("\nDiff truncated; inspect the complete resource before signing.");
        }
        self.guard.screen(&text).map(|s| s.text)
    }
}
fn difference_lines(out: &mut String, old: &str, new: &str) -> bool {
    let before = old.lines().collect::<Vec<_>>();
    let after = new.lines().collect::<Vec<_>>();
    let prefix = before
        .iter()
        .zip(&after)
        .take_while(|(a, b)| a == b)
        .count();
    let suffix = before[prefix..]
        .iter()
        .rev()
        .zip(after[prefix..].iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    for (mark, lines) in [
        ("-", &before[prefix..before.len() - suffix]),
        ("+", &after[prefix..after.len() - suffix]),
    ] {
        for line in lines {
            if out.len().saturating_add(line.len()).saturating_add(2) > DIFF_BYTES {
                return false;
            }
            let _ = writeln!(out, "{mark}{line}");
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_diff_shows_only_changed_lines_and_remains_bounded_for_unicode() {
        let mut text = String::new();
        assert!(difference_lines(
            &mut text,
            "first\nold\nlast",
            "first\nnew\nlast"
        ));
        assert_eq!(text, "-old\n+new\n");
        assert!(!difference_lines(&mut text, "", &"λ".repeat(DIFF_BYTES)));
        assert!(text.len() < DIFF_BYTES);
        assert!(text.is_char_boundary(text.len()));
    }
}
