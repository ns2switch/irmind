use irmind_app::source_mapping::SourceValue;

pub(super) trait LegacyView {
    fn get(&self, key: &str) -> Option<&SourceValue>;
    fn pointer(&self, path: &str) -> Option<&SourceValue>;
    fn as_str(&self) -> Option<&str>;
    fn is_object(&self) -> bool;
    fn is_array(&self) -> bool;
}
impl LegacyView for SourceValue {
    fn get(&self, key: &str) -> Option<&Self> {
        self.field(key)
    }
    fn pointer(&self, path: &str) -> Option<&Self> {
        let mut value = self;
        for key in path.strip_prefix('/')?.split('/') {
            value = value.field(key)?;
        }
        Some(value)
    }
    fn as_str(&self) -> Option<&str> {
        self.as_text()
    }
    fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
}
