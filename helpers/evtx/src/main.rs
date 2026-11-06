#![forbid(unsafe_code)]
use std::{
    fs::File,
    io::{self, Read as _},
    process::ExitCode,
};

fn input() -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd as _;
        Ok(File::from(io::stdin().as_fd().try_clone_to_owned()?))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle as _;
        Ok(File::from(io::stdin().as_handle().try_clone_to_owned()?))
    }
}
fn run() -> io::Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 1
        || (args[0] != "--protocol-v1"
            && args[0] != "--probe-v1"
            && args[0] != "--network-witness-v1")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported helper arguments",
        ));
    }
    #[cfg(not(windows))]
    if args[0] == "--network-witness-v1" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported helper arguments",
        ));
    }
    let mut file = input()?;
    let executable = std::env::current_exe()?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "EVTX requires a read-only regular input handle",
        ));
    }
    #[cfg(windows)]
    if args[0] == "--network-witness-v1" {
        return irmind_process_containment::network_witness(&file);
    }
    irmind_process_containment::enter(&file)?;
    if args[0] == "--probe-v1" {
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte)?;
        match std::process::Command::new(executable)
            .arg("--probe-v1")
            .spawn()
        {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "EVTX child process isolation failed",
                ));
            }
            Err(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("EVTX child process isolation could not be verified ({:?}/{})", error.kind(), error.raw_os_error().unwrap_or(0)),
                ));
            }
        }
        println!("{{\"kind\":\"probe\",\"protocol\":\"irmind-evtx-ndjson-v1\",\"isolated\":true}}");
        return Ok(());
    }
    irmind_evtx::decode(file, &mut io::stdout().lock())
}
fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| eprintln!("EVTX decoder failed")));
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("EVTX decoding or containment failed: {error}");
            ExitCode::from(2)
        }
    }
}
