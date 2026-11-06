#![cfg(windows)]
mod attributes;
mod handles;
mod identity;
mod job;
mod pipes;
mod profile;
mod token;
use crate::launch::{Mode, PreparedChild as Prepared};
use handles::Handle;
pub(crate) use identity::Identity;
use std::{
    fs::File,
    io::{self, Read},
    os::windows::ffi::OsStrExt as _,
    ptr,
};
pub(crate) use token::verify_token;
use windows_sys::Win32::{
    Foundation::{GetLastError, STILL_ACTIVE, WAIT_OBJECT_0},
    System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, PROCESS_INFORMATION, ResumeThread,
        STARTF_USESTDHANDLES, STARTUPINFOEXW, WaitForSingleObject,
    },
};

fn error(stage: &'static str) -> io::Error {
    // SAFETY: GetLastError takes no pointers and reads this thread's last-error value.
    let code = unsafe { GetLastError() };
    io::Error::other(format!(
        "Windows EVTX containment failed at {stage} (error {code})"
    ))
}

pub(crate) struct Child {
    process: Handle,
    job: Handle,
    stdout: Option<File>,
    stderr: Option<File>,
}

pub(crate) fn spawn(program: &Prepared, input: &File, mode: Mode) -> io::Result<Child> {
    let pipes = pipes::Pipes::new(input)?;
    let job = job::create()?;
    let mut attributes = attributes::Attributes::new(program.identity(), &pipes)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb =
        u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).map_err(|_| error("startup-size"))?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = pipes.input.raw();
    startup.StartupInfo.hStdOutput = pipes.output_write.raw();
    startup.StartupInfo.hStdError = pipes.error_write.raw();
    startup.lpAttributeList = attributes.raw();
    let executable = wide(program.path().as_os_str())?;
    let directory = wide(program.work_dir().as_os_str())?;
    let mut command = vec![u16::from(b'"')];
    command.extend_from_slice(&executable[..executable.len() - 1]);
    command.extend("\" ".encode_utf16());
    command.extend(mode.arg().encode_utf16());
    command.push(0);
    let environment = environment()?;
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: every UTF-16 buffer is terminated and live; startup/attributes retain
    // their aligned buffers, SID and explicit handles until CreateProcess returns.
    let created = unsafe {
        CreateProcessW(
            executable.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            &raw const startup.StartupInfo,
            &raw mut info,
        )
    };
    if created == 0 {
        return Err(error("create-AppContainer"));
    }
    let process = Handle::new(info.hProcess)?;
    let mut child = Child {
        process,
        job,
        stdout: Some(pipes.output_read.into_file()),
        stderr: Some(pipes.error_read.into_file()),
    };
    let thread = Handle::new(info.hThread)?;
    if let Err(failure) = job::assign(&child.job, &child.process) {
        let _ = child.terminate();
        return Err(failure);
    }
    // SAFETY: this is the live primary thread of our suspended, now job-bound child.
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        let failure = error("resume");
        let _ = child.terminate();
        return Err(failure);
    }
    Ok(child)
}

fn environment() -> io::Result<Vec<u16>> {
    let mut directory = vec![0u16; 32768];
    // SAFETY: the initialized output buffer has the declared capacity. No inherited environment is read.
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            directory.as_mut_ptr(),
            32768,
        )
    } as usize;
    if length == 0 || length >= directory.len() {
        return Err(error("system-runtime-directory"));
    }
    let mut block = "SystemRoot=".encode_utf16().collect::<Vec<_>>();
    block.extend_from_slice(&directory[..length]);
    block.extend_from_slice(&[0, 0]);
    Ok(block)
}

fn wide(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    let mut out = value.encode_wide().collect::<Vec<_>>();
    if out.contains(&0) || out.contains(&u16::from(b'"')) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid helper runtime path",
        ));
    }
    // CreateProcess AppContainer paths use the DOS spelling, rather than the
    // verbatim prefix returned by Rust filesystem canonicalization.
    let prefix: Vec<u16> = r"\\?\".encode_utf16().collect();
    if out.starts_with(&prefix) && out.get(5) == Some(&u16::from(b':')) {
        out.drain(..4);
    }
    out.push(0);
    Ok(out)
}

impl Child {
    pub(crate) fn stdout(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.stdout
            .take()
            .map(|f| Box::new(f) as Box<dyn Read + Send>)
            .ok_or_else(|| io::Error::other("missing helper stdout"))
    }
    pub(crate) fn stderr(&mut self) -> io::Result<Box<dyn Read + Send>> {
        self.stderr
            .take()
            .map(|f| Box::new(f) as Box<dyn Read + Send>)
            .ok_or_else(|| io::Error::other("missing helper stderr"))
    }
    fn exit_code(&self) -> io::Result<Option<u32>> {
        let mut exit = 0;
        // SAFETY: the owned process handle is live and output points to initialized u32 storage.
        if unsafe { GetExitCodeProcess(self.process.raw(), &raw mut exit) } == 0 {
            return Err(error("exit-code"));
        }
        Ok((exit != STILL_ACTIVE as u32).then_some(exit))
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<bool>> {
        Ok(self.exit_code()?.map(|exit| exit == 0))
    }
    pub(crate) fn exit_description(&mut self) -> io::Result<Option<String>> {
        Ok(self.exit_code()?.map(|exit| format!("code={exit:#x}")))
    }
    pub(crate) fn terminate(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_none() {
            let _ = job::terminate(&self.job);
            if self.try_wait()?.is_none() {
                // SAFETY: our owned child handle includes terminate access; this also cleans up failed job assignment before resume.
                if unsafe {
                    windows_sys::Win32::System::Threading::TerminateProcess(self.process.raw(), 1)
                } == 0
                {
                    return Err(error("process-termination"));
                }
            }
        }
        // SAFETY: live process handle; a finite wait follows termination or observed exit.
        if unsafe { WaitForSingleObject(self.process.raw(), 5000) } != WAIT_OBJECT_0 {
            return Err(error("wait-for-exit"));
        }
        Ok(())
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(test)]
mod tests;
