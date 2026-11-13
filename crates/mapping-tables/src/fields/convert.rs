use super::{CompiledField, Conversion};
use irmind_app::source_mapping::{MappingError, SourceValue};
use irmind_domain::{
    CommonField, CommonFieldType, CommonValue, ContentHash, EntityIdentityScope, EventText,
    EventTextList, HashAlgorithm, NetworkDirection, ObservedEntity, ObservedEntityKind,
};
impl CompiledField {
    pub(crate) fn convert(&self, value: &SourceValue) -> Result<CommonValue, MappingError> {
        let bad = || MappingError::UnsupportedSourceValue;
        let text = || value.as_text().ok_or_else(bad);
        match self.conversion {
            Conversion::Decimal => Ok(CommonValue::Unsigned(text()?.parse().map_err(|_| bad())?)),
            Conversion::Hex => Ok(CommonValue::Unsigned(
                u64::from_str_radix(text()?.strip_prefix("0x").unwrap_or(text()?), 16)
                    .map_err(|_| bad())?,
            )),
            Conversion::Domain => Ok(CommonValue::Text(
                EventText::identifier(
                    ObservedEntity::try_new(
                        ObservedEntityKind::Domain,
                        text()?,
                        EntityIdentityScope::Global,
                    )
                    .map_err(|_| bad())?
                    .value(),
                )
                .map_err(|_| bad())?,
            )),
            Conversion::Copy => copy_common_value(self.target, value),
            Conversion::KubernetesServiceAccountName => {
                let (_, name) = super::service_account_parts(text()?)?;
                Ok(CommonValue::Text(
                    EventText::identifier(name).map_err(|_| bad())?,
                ))
            }
            Conversion::Ip => Ok(CommonValue::Ip(text()?.parse().map_err(|_| bad())?)),
            Conversion::Md5 | Conversion::Sha1 | Conversion::Sha256 => {
                let algorithm = match self.conversion {
                    Conversion::Md5 => HashAlgorithm::Md5,
                    Conversion::Sha1 => HashAlgorithm::Sha1,
                    _ => HashAlgorithm::Sha256,
                };
                Ok(CommonValue::Hash(
                    ContentHash::new(algorithm, text()?).map_err(|_| bad())?,
                ))
            }
        }
    }
}

/// Copy one closed common field through the shared validated conversion rules.
pub fn copy_common_value(
    target: CommonField,
    value: &SourceValue,
) -> Result<CommonValue, MappingError> {
    let bad = || MappingError::UnsupportedSourceValue;
    let text = || value.as_text().ok_or_else(bad);
    match target.value_type() {
        CommonFieldType::Boolean => match value {
            SourceValue::Boolean(value) => Ok(CommonValue::Boolean(*value)),
            _ => Err(bad()),
        },
        CommonFieldType::Text | CommonFieldType::LongText => Ok(CommonValue::Text(
            EventText::new(text()?).map_err(|_| bad())?,
        )),
        CommonFieldType::Ip => Ok(CommonValue::Ip(text()?.parse().map_err(|_| bad())?)),
        CommonFieldType::Port
        | CommonFieldType::Pid
        | CommonFieldType::Unsigned
        | CommonFieldType::HttpStatus => {
            let SourceValue::Number(number) = value else {
                return Err(bad());
            };
            Ok(CommonValue::Unsigned(
                number.as_str().parse().map_err(|_| bad())?,
            ))
        }
        CommonFieldType::Md5 | CommonFieldType::Sha1 | CommonFieldType::Sha256 => {
            let algorithm = match target.value_type() {
                CommonFieldType::Md5 => HashAlgorithm::Md5,
                CommonFieldType::Sha1 => HashAlgorithm::Sha1,
                _ => HashAlgorithm::Sha256,
            };
            Ok(CommonValue::Hash(
                ContentHash::new(algorithm, text()?).map_err(|_| bad())?,
            ))
        }
        CommonFieldType::Direction => Ok(CommonValue::Direction(
            NetworkDirection::parse(text()?).map_err(|_| bad())?,
        )),
        CommonFieldType::TextList => {
            let SourceValue::Array(values) = value else {
                return Err(bad());
            };
            if values.len() > 16 {
                return Err(bad());
            }
            let texts = values
                .iter()
                .map(|v| EventText::new(v.as_text().ok_or_else(bad)?).map_err(|_| bad()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CommonValue::TextList(
                EventTextList::new(texts).map_err(|_| bad())?,
            ))
        }
        CommonFieldType::Time | CommonFieldType::DnsAnswers => Err(bad()),
    }
}
