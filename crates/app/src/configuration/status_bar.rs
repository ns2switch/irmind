use crate::{AppError, FixedAppError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusSegment {
    CaseTitle,
    Severity,
    Seal,
    Model,
    Provider,
    Tokens,
    TokenBudget,
    TokenPercent,
    CacheRead,
    CacheWrite,
    ToolCalls,
    CallBudget,
    CloudBytes,
    CloudBudget,
    Cost,
    Subagents,
    Approvals,
    Detections,
    Sources,
    Keystore,
    DataDirectory,
    Version,
    Clock,
    Activity,
}
impl StatusSegment {
    pub const ALL: [Self; 24] = [
        Self::CaseTitle,
        Self::Severity,
        Self::Seal,
        Self::Model,
        Self::Provider,
        Self::Tokens,
        Self::TokenBudget,
        Self::TokenPercent,
        Self::CacheRead,
        Self::CacheWrite,
        Self::ToolCalls,
        Self::CallBudget,
        Self::CloudBytes,
        Self::CloudBudget,
        Self::Cost,
        Self::Subagents,
        Self::Approvals,
        Self::Detections,
        Self::Sources,
        Self::Keystore,
        Self::DataDirectory,
        Self::Version,
        Self::Clock,
        Self::Activity,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::CaseTitle => "Case title",
            Self::Severity => "Severity",
            Self::Seal => "Seal status",
            Self::Model => "Model",
            Self::Provider => "Provider",
            Self::Tokens => "Tokens used",
            Self::TokenBudget => "Token budget",
            Self::TokenPercent => "Token percentage",
            Self::CacheRead => "Cache tokens read",
            Self::CacheWrite => "Cache tokens written",
            Self::ToolCalls => "Tool calls",
            Self::CallBudget => "Call budget",
            Self::CloudBytes => "Cloud bytes",
            Self::CloudBudget => "Cloud byte budget",
            Self::Cost => "Estimated cost",
            Self::Subagents => "Active subagents",
            Self::Approvals => "Pending approvals",
            Self::Detections => "Detections",
            Self::Sources => "Ingested sources",
            Self::Keystore => "Keystore profile",
            Self::DataDirectory => "Data directory",
            Self::Version => "IRMind version",
            Self::Clock => "UTC clock",
            Self::Activity => "Activity",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusColor {
    Text,
    Muted,
    Accent,
    Warning,
    Error,
    Success,
}
impl StatusColor {
    pub const ALL: [Self; 6] = [
        Self::Text,
        Self::Muted,
        Self::Accent,
        Self::Warning,
        Self::Error,
        Self::Success,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Text => "Text",
            Self::Muted => "Muted",
            Self::Accent => "Accent",
            Self::Warning => "Warning",
            Self::Error => "Error",
            Self::Success => "Success",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusItem {
    pub segment: StatusSegment,
    pub priority: u8,
    pub color: StatusColor,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusBarTemplate {
    pub version: u8,
    pub separator: String,
    pub segments: Vec<StatusItem>,
}
impl Default for StatusBarTemplate {
    fn default() -> Self {
        Self::investigation()
    }
}
impl StatusBarTemplate {
    pub fn validate(&self) -> Result<(), AppError> {
        let distinct = self
            .segments
            .iter()
            .map(|s| s.segment)
            .collect::<BTreeSet<_>>();
        if self.version != 1 || self.separator.len() > 16
            || self.separator.chars().count() > 4
            || self.separator.chars().any(|ch| ch.is_control() || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}'))
            || self.segments.is_empty() || self.segments.len() > StatusSegment::ALL.len()
            || distinct.len() != self.segments.len()
            || self.segments.iter().any(|s| s.priority > 100)
        {
            return Err(AppError::Fixed(FixedAppError::PolicyInvalidPublicConfiguration));
        }
        Ok(())
    }
    fn preset(items: &[(StatusSegment, u8)]) -> Self {
        Self {
            version: 1,
            separator: " · ".into(),
            segments: items
                .iter()
                .map(|(segment, priority)| StatusItem {
                    segment: *segment,
                    priority: *priority,
                    color: if matches!(
                        segment,
                        StatusSegment::Approvals | StatusSegment::Detections
                    ) {
                        StatusColor::Warning
                    } else {
                        StatusColor::Muted
                    },
                })
                .collect(),
        }
    }
    pub fn minimal() -> Self {
        use StatusSegment::{Approvals, CaseTitle, Model};
        Self::preset(&[(CaseTitle, 90), (Model, 80), (Approvals, 100)])
    }
    pub fn investigation() -> Self {
        use StatusSegment::{
            Activity, Approvals, CaseTitle, Cost, Detections, Model, Sources, Tokens, ToolCalls,
        };
        Self::preset(&[
            (CaseTitle, 85),
            (Model, 80),
            (Tokens, 70),
            (ToolCalls, 60),
            (Sources, 40),
            (Cost, 30),
            (Approvals, 100),
            (Detections, 95),
            (Activity, 90),
        ])
    }
    pub fn costs() -> Self {
        use StatusSegment::{
            CacheRead, CacheWrite, Cost, Model, Provider, TokenBudget, TokenPercent, Tokens,
            ToolCalls,
        };
        Self::preset(&[
            (Model, 70),
            (Provider, 30),
            (Tokens, 80),
            (TokenBudget, 70),
            (TokenPercent, 85),
            (CacheRead, 40),
            (CacheWrite, 40),
            (Cost, 100),
            (ToolCalls, 60),
        ])
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn templates_have_closed_bounded_values_and_no_executable_fields() {
        for template in [
            StatusBarTemplate::minimal(),
            StatusBarTemplate::investigation(),
            StatusBarTemplate::costs(),
        ] {
            template.validate().unwrap();
            assert_eq!(
                serde_json::from_str::<StatusBarTemplate>(
                    &serde_json::to_string(&template).unwrap()
                )
                .unwrap(),
                template
            );
        }
        let mut bad = StatusBarTemplate::default();
        bad.segments.push(bad.segments[0].clone());
        assert!(bad.validate().is_err());
        bad = StatusBarTemplate::default();
        bad.separator = "\x1b[2J".into();
        assert!(bad.validate().is_err());
        bad = StatusBarTemplate::default();
        bad.segments[0].priority = 101;
        assert!(bad.validate().is_err());
        assert!(
            serde_json::from_str::<StatusBarTemplate>(
                r#"{"version":1,"separator":" ","segments":[],"command":"anything"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<StatusItem>(
                r#"{"segment":"shell","priority":0,"color":"text"}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<StatusItem>(r#"{"segment":"clock","priority":0,"color":"red"}"#)
                .is_err()
        );
    }
}
