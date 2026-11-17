# GUID-only winstructs build

Source: `winstructs 0.3.2`, upstream commit
`2344ba841125c93c1dae9053c2c50459f84015d5`. The published package SHA-256 and
retained file hashes are in [UPSTREAM.json](UPSTREAM.json). `guid.rs`, `err.rs`
and `LICENSE` are retained byte for byte from the verified registry archive.

The official `evtx 0.15.1` source imports only `winstructs::guid::Guid`; it does
not use the timestamp, NTFS or security modules. This build removes those unused
modules and their dependencies, including chrono. The EVTX decoder, its timestamp
implementation, containment and protocol are unchanged. GUID parsing and
serialization use the upstream implementation; short reads still fail.

This is a local source patch, not an upstream release or a fork of the EVTX crate.
