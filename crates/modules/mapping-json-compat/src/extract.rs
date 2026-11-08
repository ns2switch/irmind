use super::{classifier::classify_field, hunteval, relations, view::LegacyView};
use irmind_app::{
    GraphRelation,
    source_mapping::{MappingError, SourceValue as Value},
};
pub(super) struct Projection {
    pub(super) entities: Vec<(String, String)>,
    pub(super) relations: Vec<GraphRelation>,
}
pub(super) fn entities(value: &Value, source: &str) -> Result<Projection, MappingError> {
    let (mut entities, relations) = if hunteval::is_normalized(value) {
        let result = hunteval::extract(value, source)?;
        (result.entities, result.relations)
    } else {
        let mut entities = Vec::new();
        collect(value, &mut entities, 0);
        let relations = relations::cloudtrail_relations(value, &mut entities);
        (entities, relations)
    };
    entities.sort();
    entities.dedup();
    Ok(Projection {
        entities,
        relations,
    })
}

pub(super) fn collect(value: &Value, entities: &mut Vec<(String, String)>, depth: usize) {
    if depth > 8 || entities.len() >= 32 {
        return;
    }
    if let Value::Object(object) = value {
        for (key, child) in object {
            if let Some(text) = child.as_str() {
                if let Some(kind) = classify_field(key, text) {
                    entities.push((kind.to_owned(), text.to_owned()));
                }
            } else if child.is_object() || child.is_array() {
                collect(child, entities, depth + 1);
            }
            if entities.len() >= 32 {
                break;
            }
        }
    } else if let Value::Array(items) = value {
        for item in items.iter().take(100) {
            collect(item, entities, depth + 1);
            if entities.len() >= 32 {
                break;
            }
        }
    }
}
