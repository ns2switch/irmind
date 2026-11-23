//! Forward Cargo's compiler invocation and save the build arguments to a
//! private directory. Only the normalizer emits public, path-independent data.
#![forbid(unsafe_code)]
use std::{
    env,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

fn run() -> io::Result<ExitCode> {
    let mut arguments = env::args_os().skip(1);
    let rustc = arguments
        .next()
        .ok_or_else(|| io::Error::other("missing Rust compiler"))?;
    let arguments: Vec<_> = arguments.collect();
    let status = Command::new(rustc).args(&arguments).status()?;
    if !status.success() {
        return Ok(status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(1)
            .into());
    }
    if arguments.iter().any(|arg| arg == "--crate-name")
        && arguments.iter().any(|arg| arg == "--out-dir")
    {
        let spool = PathBuf::from(
            env::var_os("IRMIND_NATIVE_MAPPING_OBSERVATIONS")
                .ok_or_else(|| io::Error::other("missing native mapping observation directory"))?,
        );
        let mut file = create_observation(&spool, std::process::id())?;
        for name in [
            "CARGO_MANIFEST_DIR",
            "CARGO_PKG_NAME",
            "CARGO_PKG_VERSION",
            "OUT_DIR",
        ] {
            write_field(&mut file, env::var_os(name).unwrap_or_default())?;
        }
        for argument in arguments {
            write_field(&mut file, argument)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn create_observation(spool: &Path, pid: u32) -> io::Result<File> {
    // Windows may recycle a compiler process ID within the same build.
    for ordinal in 0..=u16::MAX {
        let path = spool.join(format!("{pid}-{ordinal}.bin"));
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            result => return result,
        }
    }
    Err(io::Error::other(
        "too many compiler observations for one process ID",
    ))
}

fn write_field(file: &mut impl Write, value: std::ffi::OsString) -> io::Result<()> {
    let text = value
        .into_string()
        .map_err(|_| io::Error::other("non-UTF-8 native mapping build input"))?;
    let length = u32::try_from(text.len()).map_err(io::Error::other)?;
    file.write_all(&length.to_be_bytes())?;
    file.write_all(text.as_bytes())
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Could not record the compiler invocation: {error}");
            ExitCode::FAILURE
        }
    }
}
