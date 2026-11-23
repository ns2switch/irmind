use super::wire;
use crate::source_mapping::{
    MappingError, SelectorCondition, SelectorPredicate as P, SelectorScalar as S,
    SourceDiscriminator as D, SourceNumber, SourcePath, SourcePathSegment as Segment,
    SourceSelector,
};

impl From<&SourceSelector> for wire::Selector {
    fn from(value: &SourceSelector) -> Self {
        Self {
            parser: value.parser().into(),
            versions: value.versions().iter().cloned().collect(),
            format: value.format().cloned(),
            discriminators: value
                .discriminators()
                .iter()
                .map(|(k, v)| (k.code(), v.clone()))
                .collect(),
            conditions: value
                .conditions()
                .iter()
                .map(|c| wire::Condition {
                    path: c
                        .path
                        .segments()
                        .iter()
                        .map(|s| match s {
                            Segment::Key(k) => wire::Segment::Key(k.clone()),
                            Segment::Index(i) => wire::Segment::Index(*i),
                        })
                        .collect(),
                    predicate: (&c.predicate).into(),
                })
                .collect(),
        }
    }
}
impl From<&P> for wire::Predicate {
    fn from(value: &P) -> Self {
        match value {
            P::Missing => Self::Missing,
            P::Null => Self::Null,
            P::Present => Self::Present,
            P::Exact(v) => Self::Exact(match v {
                S::Boolean(v) => wire::Scalar::Boolean(*v),
                S::Number(v) => wire::Scalar::Number(v.as_str().into()),
                S::Text(v) => wire::Scalar::Text(v.clone()),
            }),
            P::IntegerInterval { first, last } => Self::IntegerInterval {
                first: first.to_string(),
                last: last.to_string(),
            },
        }
    }
}
impl TryFrom<wire::Selector> for SourceSelector {
    type Error = MappingError;
    fn try_from(value: wire::Selector) -> Result<Self, Self::Error> {
        let discriminators = value
            .discriminators
            .into_iter()
            .map(|(k, v)| {
                Ok((
                    match k {
                        0 => D::Dataset,
                        1 => D::Provider,
                        2 => D::Channel,
                        3 => D::RecordType,
                        _ => return Err(MappingError::InvalidManifest),
                    },
                    v,
                ))
            })
            .collect::<Result<_, MappingError>>()?;
        let conditions = value
            .conditions
            .into_iter()
            .map(|c| {
                let path = SourcePath::try_new(
                    c.path
                        .into_iter()
                        .map(|s| match s {
                            wire::Segment::Key(k) => Segment::Key(k),
                            wire::Segment::Index(i) => Segment::Index(i),
                        })
                        .collect(),
                )
                .map_err(|_| MappingError::InvalidManifest)?;
                Ok(SelectorCondition {
                    path,
                    predicate: c.predicate.try_into()?,
                })
            })
            .collect::<Result<_, MappingError>>()?;
        Self::try_new(
            &value.parser,
            value.versions.into_iter().collect(),
            value.format,
            discriminators,
            conditions,
        )
    }
}
impl TryFrom<wire::Predicate> for P {
    type Error = MappingError;
    fn try_from(value: wire::Predicate) -> Result<Self, Self::Error> {
        let invalid = || MappingError::InvalidManifest;
        Ok(match value {
            wire::Predicate::Missing => Self::Missing,
            wire::Predicate::Null => Self::Null,
            wire::Predicate::Present => Self::Present,
            wire::Predicate::Exact(v) => Self::Exact(match v {
                wire::Scalar::Boolean(v) => S::Boolean(v),
                wire::Scalar::Number(v) => {
                    S::Number(SourceNumber::try_new(&v).map_err(|_| invalid())?)
                }
                wire::Scalar::Text(v) => S::Text(v),
            }),
            wire::Predicate::IntegerInterval { first, last } => Self::IntegerInterval {
                first: first.parse().map_err(|_| invalid())?,
                last: last.parse().map_err(|_| invalid())?,
            },
        })
    }
}
