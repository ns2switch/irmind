use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus,
};
use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
};
use std::{collections::BTreeMap, fs::File, io, os::fd::AsRawFd};

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "EVTX requires fully enforced Landlock ABI 1 (Linux 5.13+) and seccomp; enable Landlock or upgrade the kernel",
    )
}

/// Restricts this single-threaded helper before it parses any untrusted records.
/// Input must be the inherited read-only evidence descriptor, duplicated before entry.
pub fn enter(input: &File) -> io::Result<()> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    setrlimit(
        Resource::As,
        Rlimit {
            current: Some(1024 * 1024 * 1024),
            maximum: Some(1024 * 1024 * 1024),
        },
    )
    .map_err(|_| denied())?;
    setrlimit(
        Resource::Cpu,
        Rlimit {
            current: Some(600),
            maximum: Some(600),
        },
    )
    .map_err(|_| denied())?;
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(|_| denied())?;
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|_| denied())?
        .create()
        .map_err(|_| denied())?
        .restrict_self()
        .map_err(|_| denied())?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(denied());
    }
    if !std::fs::read(crate::verification::CANARY)
        .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
    {
        return Err(denied());
    }
    let program = filter(input.as_raw_fd())?;
    seccompiler::apply_filter(&program).map_err(|_| denied())?;
    crate::verify_entry()
}

fn equals(arg: u8, value: u64) -> io::Result<SeccompRule> {
    SeccompRule::new(vec![
        SeccompCondition::new(arg, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
            .map_err(|_| denied())?,
    ])
    .map_err(|_| denied())
}

fn filter(input: i32) -> io::Result<seccompiler::BpfProgram> {
    let mut rules = BTreeMap::new();
    for syscall in [
        libc::SYS_close,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_sched_yield,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        rules.insert(syscall, Vec::new());
    }
    let fd = u64::try_from(input).map_err(|_| denied())?;
    for syscall in [
        libc::SYS_read,
        libc::SYS_pread64,
        libc::SYS_readv,
        libc::SYS_lseek,
        libc::SYS_fstat,
    ] {
        rules.insert(syscall, vec![equals(0, fd)?, equals(0, 0)?]);
    }
    for syscall in [libc::SYS_write, libc::SYS_writev] {
        rules.insert(syscall, vec![equals(0, 1)?, equals(0, 2)?]);
    }
    // Only anonymous mappings: an unrelated inherited file cannot be mapped for reading.
    rules.insert(libc::SYS_mmap, vec![equals(4, u64::from(u32::MAX))?]);
    SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into().map_err(|_| denied())?,
    )
    .map_err(|_| denied())?
    .try_into()
    .map_err(|_| denied())
}
