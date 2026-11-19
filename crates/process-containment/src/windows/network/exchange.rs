#![cfg(windows)]
use super::{
    diagnostics::{self, FrameFailure},
    files,
    sockets::{Listeners, blocked_candidates},
};
use crate::{
    launch::{Prepared, PreparedChild},
    witness_protocol::{self as protocol, denied},
};
use std::{
    fs::File,
    io::{self, BufRead as _, BufReader, Read as _},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};
struct Running {
    child: super::super::process::Child,
    receive: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    stderr: mpsc::Receiver<String>,
    readers: Vec<thread::JoinHandle<()>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.terminate();
        self.receive.take();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}
impl Running {
    fn start(runtime: &PreparedChild, input: &File) -> io::Result<Self> {
        let mut child = super::super::process::spawn_witness(runtime, input)?;
        let stdout = child.stdout()?;
        let stderr = child.stderr()?;
        let (send, receive) = mpsc::sync_channel(2);
        let (report, stderr_report) = mpsc::sync_channel(1);
        let mut out = Self {
            child,
            receive: Some(receive),
            stderr: stderr_report,
            readers: Vec::new(),
        };
        out.readers.push(
            thread::Builder::new()
                .name("evtx-witness-reader".into())
                .spawn(move || {
                    let mut reader = BufReader::new(stdout);
                    for _ in 0..3 {
                        let mut bytes = Vec::new();
                        let result = reader
                            .by_ref()
                            .take(protocol::MAX_MESSAGE as u64 + 1)
                            .read_until(b'\n', &mut bytes)
                            .map_err(|_| FrameFailure::Read.into_io())
                            .and_then(|_| {
                                if bytes.len() <= protocol::MAX_MESSAGE {
                                    Ok(bytes)
                                } else {
                                    Err(FrameFailure::TooLong.into_io())
                                }
                            });
                        if send.send(result).is_err() {
                            return;
                        }
                    }
                })?,
        );
        out.readers.push(
            thread::Builder::new()
                .name("evtx-witness-reader".into())
                .spawn(move || diagnostics::drain_stderr(stderr, &report))?,
        );
        Ok(out)
    }
    fn line(&self, cancelled: &dyn Fn() -> bool) -> io::Result<Vec<u8>> {
        let start = Instant::now();
        loop {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            match self
                .receive
                .as_ref()
                .ok_or_else(denied)?
                .recv_timeout(Duration::from_millis(10))
            {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout)
                    if start.elapsed() < Duration::from_secs(5) => {}
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(FrameFailure::Deadline.into_io());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(FrameFailure::Disconnected.into_io());
                }
            }
        }
    }
    fn expected_frame(
        &mut self,
        name: &'static str,
        cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Vec<u8>> {
        match self.line(cancelled) {
            Ok(frame) if frame.is_empty() => {
                let error = FrameFailure::Missing.into_io();
                // An EOF can precede the recorded exit status by a scheduler tick.
                // This observation window applies only after the frame has failed.
                let start = Instant::now();
                loop {
                    if let Some(exit) = self.child.exit_description().ok().flatten() {
                        return Err(self.with_exit(name, &error, &exit));
                    }
                    if cancelled() || start.elapsed() >= Duration::from_millis(50) {
                        return Err(stage_error(name, &error, None));
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(frame) => Ok(frame),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                Err(stage_error(name, &error, None))
            }
            Err(error) => match self.child.exit_description().ok().flatten() {
                Some(exit) => Err(self.with_exit(name, &error, &exit)),
                None => Err(stage_error(name, &error, None)),
            },
        }
    }
    fn with_exit(&self, name: &'static str, error: &io::Error, exit: &str) -> io::Error {
        let stderr = self
            .stderr
            .recv_timeout(Duration::from_millis(50))
            .unwrap_or_else(|_| "unavailable".into());
        let exit = format!("helper exited ({exit}; stderr: {stderr})");
        stage_error(name, error, Some(&exit))
    }
    fn require_running(&mut self, name: &'static str) -> io::Result<()> {
        if let Some(exit) = stage(name, self.child.exit_description())? {
            return Err(self.with_exit(name, &denied(), &exit));
        }
        Ok(())
    }
    fn success(&mut self, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
        let start = Instant::now();
        loop {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            match stage("exit", self.child.try_wait())? {
                Some(true) => return Ok(()),
                None if start.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Some(false) => {
                    return Err(match self.child.exit_description().ok().flatten() {
                        Some(exit) => self.with_exit("exit", &denied(), &exit),
                        None => stage_error("exit", &denied(), None),
                    });
                }
                None => return Err(stage_error("exit", &denied(), None)),
            }
        }
    }
}
fn stage<T>(name: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| stage_error(name, &error, None))
}
fn stage_error(name: &'static str, error: &io::Error, exit: Option<&str>) -> io::Error {
    let mut message = format!(
        "EVTX network witness {name} failed ({:?}/{})",
        error.kind(),
        error.raw_os_error().unwrap_or(0)
    );
    if let Some(diagnostic) = error.get_ref() {
        if let Some(rejection) = diagnostic.downcast_ref::<protocol::ReceiptFailure>() {
            message.push_str(": ");
            message.push_str(rejection.description());
        } else if let Some(failure) = diagnostic.downcast_ref::<FrameFailure>() {
            message.push_str(": ");
            message.push_str(&failure.to_string());
        }
    }
    if let Some(detail) = exit {
        message.push_str("; ");
        message.push_str(detail);
    }
    io::Error::new(error.kind(), message)
}
pub(super) fn verify(program: &Arc<Prepared>, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
    let listeners = stage("bind", Listeners::bind())?;
    stage("positive-before", listeners.positive_control())?;
    let runtime = stage(
        "runtime",
        PreparedChild::new(program, true, listeners.ports()?, None),
    )?;
    let input = program.probe_input()?;
    let mut running = stage("start", Running::start(&runtime, &input))?;
    let ready = running.expected_frame("ready-frame", cancelled)?;
    let ports = stage(
        "ready-content",
        protocol::parse_ready(&ready, &runtime.ticket.nonce),
    )?;
    let pid = running.child.id()?;
    running.require_running("exit-after-ready")?;
    stage("listeners-before", super::listening::verify(pid, ports))?;
    stage("outbound", listeners.empty())?;
    stage("inbound", blocked_candidates(ports))?;
    running.require_running("exit-before-ack")?;
    stage("listeners-after", super::listening::verify(pid, ports))?;
    stage("positive-after", listeners.positive_control())?;
    let temporary = runtime.work_dir().join("irmind-network-ack.tmp");
    stage(
        "ack-write",
        files::write(
            &temporary,
            protocol::receipt(&runtime.ticket.nonce, false).as_bytes(),
            runtime.identity(),
        ),
    )?;
    stage(
        "ack-rename",
        std::fs::rename(temporary, runtime.work_dir().join(protocol::ACK)),
    )?;
    let complete = running.expected_frame("complete-frame", cancelled)?;
    stage(
        "complete-content",
        protocol::check_receipt(&complete, &runtime.ticket.nonce, true),
    )?;
    if !running.line(cancelled)?.is_empty() {
        return stage("trailing-data", Err(denied()));
    }
    running.success(cancelled)?;
    stage("positive-final", listeners.positive_control())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn exit_and_invalid_receipt_have_distinct_failure_details() {
        let missing = FrameFailure::Missing.into_io();
        let exit = stage_error(
            "complete-frame",
            &missing,
            Some("helper exited (code=0x2; stderr: witness ack deadline expired)"),
        );
        assert_eq!(exit.kind(), io::ErrorKind::PermissionDenied);
        assert!(exit.to_string().contains("expected frame absent"));
        assert!(exit.to_string().contains("code=0x2"));
        assert!(
            exit.to_string()
                .contains("stderr: witness ack deadline expired")
        );

        let nonce = [1; 32];
        let wrong = protocol::receipt(&[2; 32], true);
        let rejected = protocol::check_receipt(wrong.as_bytes(), &nonce, true).unwrap_err();
        let error = stage_error("complete-content", &rejected, None);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("receipt nonce mismatch"));
        assert!(!error.to_string().contains(&protocol::hex(&[2; 32])));
    }
}
