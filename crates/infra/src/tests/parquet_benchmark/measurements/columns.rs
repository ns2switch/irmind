//! Unsigned benchmark accounting, never an evidence or artifact schema.
use super::*;
use parquet::file::metadata::ParquetMetaData;

#[derive(Default)]
pub(super) struct ColumnBudget {
    all: BTreeMap<String, i64>,
    coobservations: BTreeMap<String, i64>,
    coobservation_files: u64,
}

impl ColumnBudget {
    pub(super) fn observe(&mut self, artifact: &ParquetArtifact, metadata: &ParquetMetaData) {
        let coobs = artifact
            .schema_version()
            .starts_with("irmind-coobservations-");
        if coobs {
            self.coobservation_files += artifact.size();
        }
        for group in metadata.row_groups() {
            for column in group.columns() {
                let name = column.column_path().string();
                *self.all.entry(name.clone()).or_default() += column.compressed_size();
                if coobs {
                    *self.coobservations.entry(name).or_default() += column.compressed_size();
                }
            }
        }
    }

    pub(super) fn print(&self, scenario: &str) {
        for (column, bytes) in &self.all {
            println!("PARQUET_COLUMN scenario={scenario} column={column} compressed_bytes={bytes}");
        }
        for (column, bytes) in &self.coobservations {
            println!(
                "PARQUET_COOBS_COLUMN scenario={scenario} column={column} compressed_bytes={bytes}"
            );
        }
        let repeated_time = [
            "event_time",
            "submicro_nanos",
            "time_precision",
            "time_inferred",
            "source_offset",
        ]
        .iter()
        .filter_map(|name| self.coobservations.get(*name))
        .sum::<i64>();
        println!(
            "PARQUET_COOBS_BUDGET scenario={scenario} active_file_bytes={} repeated_time_column_bytes={repeated_time}",
            self.coobservation_files
        );
    }
}
