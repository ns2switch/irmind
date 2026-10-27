use anyhow::Result;
use std::path::PathBuf;

pub(super) struct PathPicker {
    pub(super) current: PathBuf,
    pub(super) entries: Vec<PathBuf>,
    pub(super) selected: usize,
}

impl PathPicker {
    pub(super) fn open(path: PathBuf) -> Result<Self> {
        let mut picker = Self {
            current: path,
            entries: Vec::new(),
            selected: 0,
        };
        picker.refresh()?;
        Ok(picker)
    }

    pub(super) fn refresh(&mut self) -> Result<()> {
        let mut entries = std::fs::read_dir(&self.current)?
            .take(1000)
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        self.entries = entries;
        self.selected = 0;
        Ok(())
    }

    pub(super) fn selected_path(&self) -> PathBuf {
        self.entries
            .get(self.selected)
            .cloned()
            .unwrap_or_else(|| self.current.clone())
    }
}

/// Offers names only from directories reached without following a symlink.
pub(super) fn safe_completions(prefix: &str) -> Vec<String> {
    let path = std::path::Path::new(prefix);
    let parent = path
        .parent()
        .filter(|part| !part.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let leaf = path
        .file_name()
        .map_or_else(|| "".into(), |name| name.to_string_lossy());
    let mut cursor = PathBuf::new();
    for part in parent.components() {
        cursor.push(part.as_os_str());
        let Ok(metadata) = std::fs::symlink_metadata(&cursor) else {
            return Vec::new();
        };
        if metadata.file_type().is_symlink() {
            return Vec::new();
        }
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut candidates = entries
        .take(1000)
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with(leaf.as_ref()) {
                return None;
            }
            let metadata = std::fs::symlink_metadata(entry.path()).ok()?;
            if metadata.file_type().is_symlink() {
                return None;
            }
            Some(entry.path().to_string_lossy().into_owned())
        })
        .take(20)
        .collect::<Vec<_>>();
    candidates.sort();
    candidates
}
