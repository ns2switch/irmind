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
