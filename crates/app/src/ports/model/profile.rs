use crate::AppError;
use std::num::NonZeroU32;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputParameterRequirement {
    #[default]
    Optional,
    Required,
}

/// Provider capability, never a per-request application allowance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ModelOutputProfile {
    pub maximum_output_tokens: Option<NonZeroU32>,
    pub parameter_requirement: OutputParameterRequirement,
}
impl ModelOutputProfile {
    pub fn known(maximum: u32, required: bool) -> Result<Self, AppError> {
        let maximum = NonZeroU32::new(maximum)
            .ok_or_else(|| AppError::Model("model output maximum must be positive".into()))?;
        Ok(Self {
            maximum_output_tokens: Some(maximum),
            parameter_requirement: if required {
                OutputParameterRequirement::Required
            } else {
                OutputParameterRequirement::Optional
            },
        })
    }
    pub fn parameter_value(self) -> Result<Option<u32>, AppError> {
        match (self.maximum_output_tokens, self.parameter_requirement) {
            (None, OutputParameterRequirement::Required) => Err(AppError::Model(
                "The provider requires an output maximum. Set the model's native maximum in /settings model; no request was sent.".into(),
            )),
            (maximum, _) => Ok(maximum.map(NonZeroU32::get)),
        }
    }
    /// Signed analyst configuration may supply a capability absent from metadata.
    pub fn configured(
        self,
        maximum: Option<&str>,
        required: Option<&str>,
    ) -> Result<Self, AppError> {
        let configured = maximum
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<u32>()
                    .ok()
                    .and_then(NonZeroU32::new)
                    .ok_or_else(|| {
                        AppError::Model(
                            "Set a positive integer model output maximum in /settings model".into(),
                        )
                    })
            })
            .transpose()?;
        if configured
            .zip(self.maximum_output_tokens)
            .is_some_and(|(a, b)| a < b)
        {
            return Err(AppError::Model("The configured maximum is below the documented model maximum; review /settings model".into()));
        }
        let requirement = match required.filter(|s| !s.is_empty()) {
            Some("true") => OutputParameterRequirement::Required,
            Some("false") if self.parameter_requirement != OutputParameterRequirement::Required => {
                OutputParameterRequirement::Optional
            }
            None | Some("false") => self.parameter_requirement,
            _ => {
                return Err(AppError::Model(
                    "Output parameter requirement must be true or false in /settings model".into(),
                ));
            }
        };
        Ok(Self {
            maximum_output_tokens: configured.or(self.maximum_output_tokens),
            parameter_requirement: requirement,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn unknown_optional_is_omitted_and_unknown_required_names_the_setting() {
        assert_eq!(
            ModelOutputProfile::default().parameter_value().unwrap(),
            None
        );
        let required = ModelOutputProfile {
            parameter_requirement: OutputParameterRequirement::Required,
            ..ModelOutputProfile::default()
        };
        assert!(
            required
                .parameter_value()
                .unwrap_err()
                .to_string()
                .contains("/settings model")
        );
        assert!(ModelOutputProfile::known(0, false).is_err());
        assert_eq!(
            required
                .configured(Some("128000"), None)
                .unwrap()
                .parameter_value()
                .unwrap(),
            Some(128_000)
        );
        assert!(
            ModelOutputProfile::known(128_000, true)
                .unwrap()
                .configured(Some("2048"), None)
                .is_err()
        );
        for invalid in ["0", "-1", "4294967296", " 128000", "12x"] {
            assert!(required.configured(Some(invalid), None).is_err());
        }
    }
}
