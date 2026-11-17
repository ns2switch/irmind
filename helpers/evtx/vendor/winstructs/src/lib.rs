//! GUID-only build for the isolated EVTX reader. See UPSTREAM.md.
#![forbid(unsafe_code)]
#![deny(unused_must_use)]
pub mod err;
pub mod guid;

#[cfg(test)]
mod tests {
    use super::guid::Guid;
    #[test]
    fn guid_layout_and_short_reads_match_the_upstream_contract() -> Result<(), Box<dyn std::error::Error>> {
        let input = [0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49,
                     0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d];
        for length in 0..16 {
            assert!(Guid::from_buffer(&input[..length]).is_err());
        }
        let guid = Guid::from_buffer(&input)?;
        assert_eq!(guid.to_string(), "54849625-5478-4994-A5BA-3E3B0328C30D");
        Ok(())
    }
}
