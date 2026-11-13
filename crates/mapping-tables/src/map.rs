use super::TableMapping;
use irmind_app::source_mapping::{MappingDiagnostic, MappingError, MappingOutput, SourceRecordV1};
use irmind_domain::{BoundedObservations, CommonEventV1, EventContextV1};
impl TableMapping {
    pub(super) fn project(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        let rule = self.selected_rule(source)?;
        let header = self.header(source, rule)?;
        let (context, observations) = self.project_fields(source, rule)?;
        let common = CommonEventV1::try_new(
            source.origin().clone(),
            source.timestamp(),
            header,
            context,
            observations,
        )
        .map_err(|_| MappingError::UnsupportedSourceValue)?;
        let unmapped = MappingOutput::unclassified(source, MappingDiagnostic::Unclassified)?;
        let mut indexed = unmapped.into_record().indexed;
        indexed.record.event = common.event().action().unwrap_or_default().into();
        if source.cluster_identity().is_some() {
            indexed.record.text = irmind_app::encode_common_event(&common)
                .map_err(|_| MappingError::InvalidOutput)?;
        }
        MappingOutput::try_new(
            source,
            indexed,
            common,
            self.partition.project(source)?,
            vec![],
        )
    }
    /// Evaluate only finite classification/action rules, without serializing a projection.
    /// Native source validators use this with their own validated field representation.
    pub fn event_header(
        &self,
        source: &SourceRecordV1,
    ) -> Result<irmind_domain::EventHeaderV1, MappingError> {
        self.header(source, self.selected_rule(source)?)
    }
    fn selected_rule(
        &self,
        source: &SourceRecordV1,
    ) -> Result<Option<&super::CompiledRule>, MappingError> {
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
        if selected.next().is_some() {
            return Err(MappingError::InvalidDefinition);
        }
        Ok(rule)
    }
    fn header(
        &self,
        source: &SourceRecordV1,
        rule: Option<&super::CompiledRule>,
    ) -> Result<irmind_domain::EventHeaderV1, MappingError> {
        let mut header = rule.map(|rule| rule.header.clone()).unwrap_or_default();
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
        Ok(header)
    }
    fn project_fields(
        &self,
        source: &SourceRecordV1,
        rule: Option<&super::CompiledRule>,
    ) -> Result<(EventContextV1, BoundedObservations), MappingError> {
        let mut context = acquisition_context(source)?;
        let mut observations = Vec::new();
        for field in self
            .fields
            .iter()
            .chain(rule.into_iter().flat_map(|r| &r.fields))
        {
            if !field.applies(source) {
                continue;
            }
            let Some(original) = field.path.resolve(source.fields()) else {
                continue;
            };
            if matches!(original, irmind_app::source_mapping::SourceValue::Null)
                || field.omits(original)
            {
                continue;
            }
            let value = field.convert(original)?;
            for observation in field
                .observation
                .iter()
                .chain(&field.observations)
                .filter(|o| o.applies(source))
            {
                if observations.len() >= 32 {
                    return Err(MappingError::UnsupportedSourceValue);
                }
                observations.push(observation.project(source, field.target, &value)?);
            }
            context
                .try_insert(field.target, value)
                .map_err(|_| MappingError::UnsupportedSourceValue)?;
        }
        Ok((
            context,
            BoundedObservations::try_new(observations)
                .map_err(|_| MappingError::UnsupportedSourceValue)?,
        ))
    }
}

fn acquisition_context(source: &SourceRecordV1) -> Result<EventContextV1, MappingError> {
    let mut context = EventContextV1::default();
    if let Some(cluster) = source.cluster_identity() {
        context
            .try_insert(
                irmind_domain::CommonField::IrmindClusterIdentity,
                irmind_domain::CommonValue::Text(
                    irmind_domain::EventText::new(&cluster.qualified())
                        .map_err(|_| MappingError::InvalidOutput)?,
                ),
            )
            .map_err(|_| MappingError::InvalidOutput)?;
    }
    Ok(context)
}
