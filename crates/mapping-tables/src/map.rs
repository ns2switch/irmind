use super::TableMapping;
use irmind_app::source_mapping::{MappingDiagnostic, MappingError, MappingOutput, SourceRecordV1};
use irmind_domain::{BoundedObservations, CommonEventV1, EventContextV1};
impl TableMapping {
    pub(super) fn project(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        if !self
            .manifest
            .selectors()
            .iter()
            .any(|selector| selector.matches(source))
        {
            return Err(MappingError::UnsupportedSourceValue);
        }
        let mut selected = self.rules.iter().filter(|r| r.selector.matches(source));
        let rule = selected.next();
        let mut header = rule.map(|rule| rule.header.clone()).unwrap_or_default();
        if selected.next().is_some() {
            return Err(MappingError::InvalidDefinition);
        }
        if let Some(path) = &self.action
            && let Some(value) = path.resolve(source.fields())
        {
            header = header
                .with_action(
                    value
                        .as_text()
                        .ok_or(MappingError::UnsupportedSourceValue)?,
                )
                .map_err(|_| MappingError::UnsupportedSourceValue)?;
        }
        let mut context = EventContextV1::default();
        let mut observations = Vec::new();
        for field in self
            .fields
            .iter()
            .chain(rule.into_iter().flat_map(|r| &r.fields))
        {
            let Some(original) = field.path.resolve(source.fields()) else {
                continue;
            };
            if matches!(original, irmind_app::source_mapping::SourceValue::Null) {
                continue;
            }
            let value = field.convert(original)?;
            if let Some(observation) = &field.observation {
                observations.push(observation.project(source, field.target, &value)?);
            }
            context
                .try_insert(field.target, value)
                .map_err(|_| MappingError::UnsupportedSourceValue)?;
        }
        let common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
            context,
            BoundedObservations::try_new(observations)
                .map_err(|_| MappingError::UnsupportedSourceValue)?,
        )
        .map_err(|_| MappingError::UnsupportedSourceValue)?;
        let unmapped = MappingOutput::unclassified(source, MappingDiagnostic::Unclassified)?;
        let mut indexed = unmapped.record().indexed.clone();
        if self.project_action {
            indexed.record.event = common.event().action().unwrap_or_default().into();
        }
        MappingOutput::try_new(
            source,
            indexed,
            common,
            self.partition.project(source)?,
            vec![],
        )
    }
}
