#![forbid(unsafe_code)]
//! Review a bounded data definition and print its canonical digest for pinning.
use irmind_mapping_tables::TableMapping;
use std::{error::Error, io::Read};
fn main() -> Result<(), Box<dyn Error>> {
    for path in std::env::args().skip(1).take(16) {
        let mut data = String::new();
        std::fs::File::open(&path)?
            .take(65_537)
            .read_to_string(&mut data)?;
        let manifest = TableMapping::review(&data).map_err(|_| "invalid mapping definition")?;
        println!(
            "{} {}",
            manifest.identity().id(),
            manifest.identity().implementation().as_str()
        );
    }
    Ok(())
}
