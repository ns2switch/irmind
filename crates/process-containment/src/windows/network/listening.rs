#![cfg(windows)]
//! Check only the witness process's two loopback listeners; never log the host table.
use crate::witness_protocol::denied;
use std::{io, mem, ptr};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};
fn table(family: u32) -> io::Result<Vec<u8>> {
    let mut needed = 0;
    // SAFETY: documented null-buffer size query with valid output storage.
    let status = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &raw mut needed,
            0,
            family,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(denied());
    }
    for _ in 0..2 {
        if !(4..=1_048_576).contains(&needed) {
            return Err(denied());
        }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
        let mut capacity =
            u32::try_from(mem::size_of_val(buffer.as_slice())).map_err(|_| denied())?;
        // SAFETY: initialized pointer-aligned storage covers capacity bytes;
        // the requested family and table class determine the checked row layout.
        let status = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &raw mut capacity,
                0,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == ERROR_INSUFFICIENT_BUFFER {
            needed = capacity;
            continue;
        }
        if status != 0 || capacity as usize > mem::size_of_val(buffer.as_slice()) {
            return Err(denied());
        }
        // SAFETY: a successful query initialized at most the checked allocation;
        // copying its declared byte extent does not expose pointers or host data.
        return Ok(unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), capacity as usize)
        }
        .to_vec());
    }
    Err(denied())
}
pub(super) fn verify(pid: u32, ports: [u16; 2]) -> io::Result<()> {
    let ipv4 = table(u32::from(AF_INET))?;
    let ipv6 = table(u32::from(AF_INET6))?;
    let first =
        rows::<MIB_TCPROW_OWNER_PID>(&ipv4, mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table))?
            .into_iter()
            .any(|entry| {
                entry.dwOwningPid == pid
                    && entry.dwState == 2
                    && entry.dwLocalAddr.to_ne_bytes() == [127, 0, 0, 1]
                    && port(entry.dwLocalPort) == ports[0]
            });
    let second =
        rows::<MIB_TCP6ROW_OWNER_PID>(&ipv6, mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table))?
            .into_iter()
            .any(|entry| {
                entry.dwOwningPid == pid
                    && entry.dwState == 2
                    && entry.ucLocalAddr == std::net::Ipv6Addr::LOCALHOST.octets()
                    && port(entry.dwLocalPort) == ports[1]
            });
    if !first || !second {
        return Err(denied());
    }
    Ok(())
}
fn port(value: u32) -> u16 {
    u16::from_be(u16::try_from(value & 0xffff).unwrap_or(0))
}
fn rows<T: Copy>(bytes: &[u8], offset: usize) -> io::Result<Vec<T>> {
    let count = u32::from_ne_bytes(
        bytes
            .get(..4)
            .ok_or_else(denied)?
            .try_into()
            .map_err(|_| denied())?,
    ) as usize;
    let end = count
        .checked_mul(mem::size_of::<T>())
        .and_then(|size| size.checked_add(offset))
        .ok_or_else(denied)?;
    if end > bytes.len() {
        return Err(denied());
    }
    // SAFETY: private callers select the matching POD native row for the query's
    // family. Every copied row lies wholly inside the initialized bounded table.
    Ok(bytes[offset..end]
        .chunks_exact(mem::size_of::<T>())
        .map(|row| unsafe { ptr::read_unaligned(row.as_ptr().cast::<T>()) })
        .collect())
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn dead_and_wrong_owner_endpoints_never_count_as_live_witnesses() {
        let listeners = super::super::sockets::Listeners::bind().unwrap();
        listeners.positive_control().unwrap();
        let ports = listeners.ports().unwrap();
        // SAFETY: current process ID query takes no pointers and transfers no ownership.
        let pid = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
        verify(pid, ports).unwrap();
        assert!(verify(0, ports).is_err());
        drop(listeners);
        assert!(verify(pid, ports).is_err());
    }
}
