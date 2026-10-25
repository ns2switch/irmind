use irmind_domain::{Provenance, SourceKind, Tainted};

fn main() {
    let tainted = Tainted::from_external(
        "secret".to_owned(),
        Provenance::new([1; 32], Some(0), SourceKind::File),
    );
    let _raw = tainted.value().clone();
}
