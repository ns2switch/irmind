//! Disjoint provider cache counters. Inclusive input remains the budget charge.
use super::{ModelPricing, ModelUsage, UsageEvent};
use crate::AppError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheWriteLifetime {
    NotApplicable,
    FiveMinutes,
    OneHour,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "CacheWire")]
pub struct CacheUsage {
    read_input_tokens: u64,
    write_input_tokens: u64,
    write_lifetime: CacheWriteLifetime,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheWire {
    read_input_tokens: u64,
    write_input_tokens: u64,
    write_lifetime: CacheWriteLifetime,
}
fn invalid() -> AppError {
    AppError::Model("provider cache counters are inconsistent".into())
}
impl TryFrom<CacheWire> for CacheUsage {
    type Error = AppError;
    fn try_from(value: CacheWire) -> Result<Self, Self::Error> {
        Self::new(
            value.read_input_tokens,
            value.write_input_tokens,
            value.write_lifetime,
        )
    }
}
impl CacheUsage {
    pub fn new(read: u64, write: u64, lifetime: CacheWriteLifetime) -> Result<Self, AppError> {
        if read.checked_add(write).is_none()
            || (lifetime == CacheWriteLifetime::NotApplicable && write != 0)
        {
            return Err(invalid());
        }
        Ok(Self {
            read_input_tokens: read,
            write_input_tokens: write,
            write_lifetime: lifetime,
        })
    }
    pub const fn read_input_tokens(self) -> u64 {
        self.read_input_tokens
    }
    pub const fn write_input_tokens(self) -> u64 {
        self.write_input_tokens
    }
    pub const fn write_lifetime(self) -> CacheWriteLifetime {
        self.write_lifetime
    }
    pub fn ordinary_input_tokens(self, input: u64) -> Result<u64, AppError> {
        input
            .checked_sub(
                self.read_input_tokens
                    .checked_add(self.write_input_tokens)
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)
    }
    pub(crate) fn checked_add(self, other: Self) -> Result<Self, AppError> {
        let lifetime = if self.write_input_tokens == 0 {
            other.write_lifetime
        } else if other.write_input_tokens == 0 || self.write_lifetime == other.write_lifetime {
            self.write_lifetime
        } else {
            CacheWriteLifetime::Unknown
        };
        Self::new(
            self.read_input_tokens
                .checked_add(other.read_input_tokens)
                .ok_or_else(invalid)?,
            self.write_input_tokens
                .checked_add(other.write_input_tokens)
                .ok_or_else(invalid)?,
            lifetime,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ModelUsageWire {
    input_tokens: u64,
    output_tokens: u64,
    #[serde(default)]
    cache: Option<CacheUsage>,
}
impl TryFrom<ModelUsageWire> for ModelUsage {
    type Error = AppError;
    fn try_from(value: ModelUsageWire) -> Result<Self, Self::Error> {
        let usage = Self {
            input_tokens: value.input_tokens,
            output_tokens: value.output_tokens,
            cache: value.cache,
        };
        usage.validate()?;
        Ok(usage)
    }
}
impl ModelUsage {
    pub fn validate(self) -> Result<(), AppError> {
        self.input_tokens
            .checked_add(self.output_tokens)
            .ok_or_else(invalid)?;
        if let Some(cache) = self.cache {
            cache.ordinary_input_tokens(self.input_tokens)?;
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UsageEventWire {
    input_tokens: u64,
    output_tokens: u64,
    estimated_cost_microusd: Option<u64>,
    #[serde(default)]
    cache: Option<CacheUsage>,
}
impl TryFrom<UsageEventWire> for UsageEvent {
    type Error = AppError;
    fn try_from(value: UsageEventWire) -> Result<Self, Self::Error> {
        ModelUsage {
            input_tokens: value.input_tokens,
            output_tokens: value.output_tokens,
            cache: value.cache,
        }
        .validate()?;
        Ok(Self {
            input_tokens: value.input_tokens,
            output_tokens: value.output_tokens,
            estimated_cost_microusd: value.estimated_cost_microusd,
            cache: value.cache,
        })
    }
}
impl ModelPricing {
    pub fn estimate(self, usage: ModelUsage) -> Result<Option<u64>, AppError> {
        usage.validate()?;
        let Some(cache) = usage.cache else {
            return Ok(None);
        };
        let ordinary = cache.ordinary_input_tokens(usage.input_tokens)?;
        let write_rate = if cache.write_lifetime == CacheWriteLifetime::FiveMinutes {
            self.cache_write_microusd_per_million
        } else {
            None
        };
        let components = [
            (ordinary, Some(self.input_microusd_per_million)),
            (
                cache.read_input_tokens,
                self.cache_read_microusd_per_million,
            ),
            (cache.write_input_tokens, write_rate),
            (usage.output_tokens, Some(self.output_microusd_per_million)),
        ];
        let overflow = || AppError::Fixed(crate::FixedAppError::PolicyModelCostOverflow);
        let mut total = 0u128;
        for (tokens, rate) in components {
            if tokens == 0 {
                continue;
            }
            let Some(rate) = rate else {
                return Ok(None);
            };
            total = total
                .checked_add(
                    u128::from(tokens)
                        .checked_mul(u128::from(rate))
                        .ok_or_else(overflow)?,
                )
                .ok_or_else(overflow)?;
        }
        Ok(Some(
            u64::try_from(total / 1_000_000).map_err(|_| overflow())?,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn approved_cache_vectors_keep_canonical_bytes_and_prices() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../docs/development/context-cache-accounting-vectors.json"
        ))
        .unwrap();
        let pricing = ModelPricing {
            input_microusd_per_million: 1_000_000,
            output_microusd_per_million: 2_000_000,
            cache_read_microusd_per_million: Some(100_000),
            cache_write_microusd_per_million: Some(1_250_000),
        };
        for vector in vectors["vectors"].as_array().unwrap() {
            let json = vector["usage_event_json"].as_str().unwrap();
            let usage: UsageEvent = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&usage).unwrap(), json);
            assert_eq!(
                crate::hex(&crate::sha256(json.as_bytes())),
                vector["sha256"]
            );
            let model = ModelUsage {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cache: usage.cache,
            };
            assert_eq!(
                pricing.estimate(model).unwrap(),
                usage.estimated_cost_microusd
            );
            assert_eq!(
                model.input_tokens + model.output_tokens,
                vector["charged_tokens"].as_u64().unwrap()
            );
        }
    }
    #[test]
    fn impossible_counts_are_rejected_on_construction_and_deserialization() {
        assert!(CacheUsage::new(0, 1, CacheWriteLifetime::NotApplicable).is_err());
        assert!(CacheUsage::new(u64::MAX, 1, CacheWriteLifetime::Unknown).is_err());
        for json in [
            r#"{"input_tokens":10,"output_tokens":0,"cache":{"read_input_tokens":11,"write_input_tokens":0,"write_lifetime":"not-applicable"}}"#,
            r#"{"input_tokens":10,"output_tokens":0,"cache":{"read_input_tokens":0,"write_input_tokens":1,"write_lifetime":"not-applicable"}}"#,
            r#"{"input_tokens":18446744073709551615,"output_tokens":1}"#,
        ] {
            assert!(serde_json::from_str::<ModelUsage>(json).is_err());
        }
        assert_eq!(
            serde_json::to_string(&ModelUsage {
                input_tokens: 10,
                output_tokens: 2,
                cache: None
            })
            .unwrap(),
            r#"{"input_tokens":10,"output_tokens":2}"#
        );
    }
    #[test]
    fn prices_require_every_nonzero_component_and_round_only_once() {
        let cache = CacheUsage::new(1, 1, CacheWriteLifetime::FiveMinutes).unwrap();
        let usage = ModelUsage {
            input_tokens: 3,
            output_tokens: 1,
            cache: Some(cache),
        };
        let pricing = ModelPricing {
            input_microusd_per_million: 300_000,
            output_microusd_per_million: 300_000,
            cache_read_microusd_per_million: Some(300_000),
            cache_write_microusd_per_million: Some(300_000),
        };
        assert_eq!(pricing.estimate(usage).unwrap(), Some(1));
        assert_eq!(
            ModelPricing {
                cache_write_microusd_per_million: None,
                ..pricing
            }
            .estimate(usage)
            .unwrap(),
            None
        );
        assert_eq!(
            ModelPricing {
                cache_read_microusd_per_million: None,
                ..pricing
            }
            .estimate(usage)
            .unwrap(),
            None
        );
        assert_eq!(
            pricing
                .estimate(ModelUsage {
                    cache: Some(CacheUsage::new(1, 1, CacheWriteLifetime::OneHour).unwrap()),
                    ..usage
                })
                .unwrap(),
            None
        );
        assert!(
            ModelPricing {
                input_microusd_per_million: u64::MAX,
                output_microusd_per_million: u64::MAX,
                ..pricing
            }
            .estimate(ModelUsage {
                input_tokens: u64::MAX - 1,
                output_tokens: 1,
                cache: Some(CacheUsage::new(0, 0, CacheWriteLifetime::NotApplicable).unwrap())
            })
            .is_err()
        );
    }
}
