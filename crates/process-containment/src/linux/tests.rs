use super::*;
fn action(program: &seccompiler::BpfProgram, syscall: i64, flags: u64) -> u32 {
    let mut data = [0u8; 64];
    data[..4].copy_from_slice(&u32::try_from(syscall).unwrap().to_ne_bytes());
    let arch: u32 = if cfg!(target_arch = "x86_64") {
        0xc000_003e
    } else {
        0xc000_00b7
    };
    data[4..8].copy_from_slice(&arch.to_ne_bytes());
    data[16..24].copy_from_slice(&flags.to_ne_bytes());
    let (mut pc, mut accumulator) = (0usize, 0u32);
    while let Some(op) = program.get(pc) {
        pc += 1;
        match op.code {
            0x20 => {
                let at = usize::try_from(op.k).unwrap();
                accumulator = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap());
            }
            0x54 => accumulator &= op.k,
            0x15 | 0x25 | 0x35 | 0x45 => {
                let matches = match op.code {
                    0x15 => accumulator == op.k,
                    0x25 => accumulator > op.k,
                    0x35 => accumulator >= op.k,
                    _ => accumulator & op.k != 0,
                };
                pc += usize::from(if matches { op.jt } else { op.jf });
            }
            0x05 => pc += usize::try_from(op.k).unwrap(),
            0x06 => return op.k,
            code => panic!("unsupported BPF instruction {code}"),
        }
    }
    panic!("unterminated filter")
}
#[test]
fn compiled_filter_allows_only_same_process_thread_flag_sets() {
    let program = filter(0).unwrap();
    for optional in [
        0,
        libc::CLONE_SETTLS,
        libc::CLONE_PARENT_SETTID,
        libc::CLONE_CHILD_CLEARTID | libc::CLONE_PARENT_SETTID | libc::CLONE_SETTLS,
        libc::CLONE_CHILD_SETTID | libc::CLONE_SETTLS,
    ] {
        assert_eq!(
            action(
                &program,
                libc::SYS_clone,
                THREAD_REQUIRED | u64::try_from(optional).unwrap()
            ),
            0x7fff_0000
        );
    }
    for forbidden in [
        libc::CLONE_VFORK as u64,
        libc::CLONE_NEWNET as u64,
        libc::CLONE_NEWUSER as u64,
        libc::CLONE_NEWPID as u64,
        17,
        1 << 40,
    ] {
        assert_eq!(
            action(&program, libc::SYS_clone, THREAD_REQUIRED | forbidden),
            0x0005_0000 | libc::EPERM as u32
        );
    }
    for required in [libc::CLONE_VM, libc::CLONE_SIGHAND, libc::CLONE_THREAD] {
        assert_eq!(
            action(
                &program,
                libc::SYS_clone,
                THREAD_REQUIRED & !(u64::try_from(required).unwrap())
            ),
            0x0005_0000 | libc::EPERM as u32
        );
    }
    for syscall in [libc::SYS_execve, libc::SYS_socket, libc::SYS_openat] {
        assert_eq!(
            action(&program, syscall, 0),
            0x0005_0000 | libc::EPERM as u32
        );
    }
}
#[test]
fn opaque_clone3_arguments_never_bypass_flag_validation() {
    assert_eq!(
        action(&clone3_unavailable().unwrap(), libc::SYS_clone3, u64::MAX),
        0x0005_0000 | libc::ENOSYS as u32
    );
    assert_eq!(
        action(&filter(0).unwrap(), libc::SYS_clone3, u64::MAX),
        0x7fff_0000
    );
}
