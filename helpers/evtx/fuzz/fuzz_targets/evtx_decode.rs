#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;
use std::io::{self, Cursor, Write};
struct Bounded(usize);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_sub(bytes.len()).ok_or(io::ErrorKind::OutOfMemory)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fuzz_target!(|input: &[u8]| {
    if input.len() > 131_072 { return; }
    let mut bytes=input.to_vec();
    // Keep a CRC-correct mutation route so checksums do not hide BinXML coverage.
    if bytes.last().is_some_and(|byte| byte & 1 == 0) && bytes.len() >= 4096 {
        let checksum=evtx::checksum_ieee(&bytes[..120]);
        bytes[124..128].copy_from_slice(&checksum.to_le_bytes());
        for chunk in bytes[4096..].chunks_mut(65_536) {
            if chunk.len() != 65_536 { continue; }
            let end=u32::from_le_bytes(chunk[48..52].try_into().unwrap_or([0;4])) as usize;
            if (512..=65_536).contains(&end) {
                let crc=evtx::checksum_ieee(&chunk[512..end]);
                chunk[52..56].copy_from_slice(&crc.to_le_bytes());
            }
            let crc=evtx::checksum_ieee(&[&chunk[..120],&chunk[128..512]].concat());
            chunk[124..128].copy_from_slice(&crc.to_le_bytes());
        }
    }
    let _ = irmind_evtx::decode(Cursor::new(bytes), &mut Bounded(16*1024*1024));
});
