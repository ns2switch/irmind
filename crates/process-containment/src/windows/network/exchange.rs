#![cfg(windows)]
use super::{
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
        let mut out = Self {
            child,
            receive: Some(receive),
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
                            .map_err(|_| denied())
                            .and_then(|_| {
                                if bytes.len() <= protocol::MAX_MESSAGE {
                                    Ok(bytes)
                                } else {
                                    Err(denied())
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
                .spawn(move || {
                    let _ = io::copy(&mut stderr.take(65536), &mut io::sink());
                })?,
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
                _ => return Err(denied()),
            }
        }
    }
    fn success(&mut self, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
        let start = Instant::now();
        loop {
            if cancelled() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            match self.child.try_wait()? {
                Some(true) => return Ok(()),
                None if start.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(10));
                }
                Some(false) | None => return Err(denied()),
            }
        }
    }
}
pub(super) fn verify(program: &Arc<Prepared>, cancelled: &dyn Fn() -> bool) -> io::Result<()> {
    let listeners = Listeners::bind()?;
    listeners.positive_control()?;
    let runtime = PreparedChild::new(program, true, listeners.ports()?, None)?;
    let input = program.probe_input()?;
    let mut running = Running::start(&runtime, &input)?;
    let ports = protocol::parse_ready(&running.line(cancelled)?, &runtime.ticket.nonce)?;
    let pid = running.child.id()?;
    if running.child.try_wait()?.is_some() {
        return Err(denied());
    }
    super::listening::verify(pid, ports)?;
    listeners.empty()?;
    blocked_candidates(ports)?;
    if running.child.try_wait()?.is_some() {
        return Err(denied());
    }
    super::listening::verify(pid, ports)?;
    listeners.positive_control()?;
    let temporary = runtime.work_dir().join("irmind-network-ack.tmp");
    files::write(
        &temporary,
        protocol::receipt(&runtime.ticket.nonce, false).as_bytes(),
        runtime.identity(),
    )?;
    std::fs::rename(temporary, runtime.work_dir().join(protocol::ACK))?;
    protocol::check_receipt(&running.line(cancelled)?, &runtime.ticket.nonce, true)?;
    if !running.line(cancelled)?.is_empty() {
        return Err(denied());
    }
    running.success(cancelled)?;
    listeners.positive_control()
}
