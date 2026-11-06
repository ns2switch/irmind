#![cfg(windows)]
use super::{Handle, error};
use std::{io, ptr};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
pub(super) fn create() -> io::Result<Handle> {
    // SAFETY: null security/name requests an unnamed, non-inheritable owned job.
    let job = Handle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = 1024 * 1024 * 1024;
    // SAFETY: exact class, correctly aligned initialized structure, matching byte length and live handle.
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(std::mem::size_of_val(&limits)).map_err(|_| error("job-size"))?,
        )
    } == 0
    {
        return Err(error("job-limits"));
    }
    Ok(job)
}
pub(super) fn assign(job: &Handle, process: &Handle) -> io::Result<()> {
    // SAFETY: both owned handles are live; the child is still suspended.
    if unsafe { AssignProcessToJobObject(job.raw(), process.raw()) } == 0 {
        Err(error("job-assignment"))
    } else {
        Ok(())
    }
}
pub(super) fn terminate(job: &Handle) -> io::Result<()> {
    // SAFETY: live owned job; termination covers every member and descendant.
    if unsafe { TerminateJobObject(job.raw(), 1) } == 0 {
        Err(error("job-termination"))
    } else {
        Ok(())
    }
}
