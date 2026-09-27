//! Timed control loop for an existing, owned engine process. This module does
//! not create a daemon, call a server or depend on a UI connection. EOF refers
//! to the dispatcher's engine control pipe and requires native shutdown.
//!
//! Windows integration is NOT a drop-in replacement: request_primitive currently
//! reads stdin for primitive_ok. A single reader/router must also deliver those
//! replies before this loop can own stdin; never run two readers on that pipe.
//! The platform owner supplies that routing separately.

use nelomai_contracts::dispatcher::{frame_body, read_frame, MAX_ENGINE_FRAME};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

const TICK_INTERVAL_MS: u64 = 100;

/// Runs only on the engine owner thread. Frames and responses include the
/// existing four-byte dispatcher length prefix. Implementations must keep all
/// callbacks bounded: synchronous handling/writing cannot be preempted by ticks.
pub trait Handler {
    fn handle(&mut self, frame: &[u8]) -> io::Result<Vec<u8>>;
    fn tick(&mut self, now_ms: u64) -> io::Result<()>;
    fn shutdown(&mut self) -> io::Result<()>;
}

pub enum ChannelEvent {
    Frame(Vec<u8>),
    /// Only EOF at a frame boundary is clean; truncated frames are read errors.
    Eof,
    ReadError(io::Error),
}

/// Clock/wait seam for deterministic tests and an externally owned receiver.
/// Time is monotonic milliseconds in one domain throughout a run. Timeout must
/// behave like Receiver::recv_timeout; disconnect is not a clean EOF event.
pub trait ChannelWait {
    fn now_ms(&self) -> u64;
    fn recv_timeout(&mut self, timeout: Duration) -> Result<ChannelEvent, RecvTimeoutError>;
}

struct ReceiverWait {
    receiver: Receiver<ChannelEvent>,
    origin: Instant,
}

impl ChannelWait for ReceiverWait {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    fn recv_timeout(&mut self, timeout: Duration) -> Result<ChannelEvent, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

/// Own a single read-frame pump with capacity one and run the handler in this
/// thread. Input frames use the existing MAX_ENGINE_FRAME bound, including
/// rejecting an oversized length before allocating/reading its body. Nothing
/// logs frame bodies. Backpressure bounds queued frames to one, plus at most
/// one frame held by the pump while sending and one being handled.
///
/// ONLY use with this engine process's owned control input. The caller MUST exit
/// the engine process after return: on handler/tick/write failure the detached
/// reader can remain blocked in Read until process exit. Joining it here could
/// hang cleanup forever. No per-probe thread is created, and no handler/native
/// state moves into the pump. Spawn failure also invokes shutdown.
pub fn run_engine_channel<R: Read + Send + 'static>(
    reader: R,
    writer: &mut impl Write,
    handler: &mut impl Handler,
) -> io::Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("engine-control-reader".into())
        .spawn(move || {
            let mut reader = BufReader::new(reader);
            loop {
                // The shared read_frame uses read_exact, which otherwise makes
                // a clean pipe close indistinguishable from a truncated header.
                let event = match reader.fill_buf() {
                    Ok([]) => ChannelEvent::Eof,
                    Ok(_) => match read_frame(&mut reader, MAX_ENGINE_FRAME) {
                        Ok(frame) => ChannelEvent::Frame(frame),
                        Err(error) => ChannelEvent::ReadError(error),
                    },
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => ChannelEvent::ReadError(error),
                };
                let terminal = !matches!(&event, ChannelEvent::Frame(_));
                if sender.send(event).is_err() || terminal {
                    break;
                }
            }
        });
    match spawned {
        Ok(reader_thread) => drop(reader_thread),
        Err(error) => {
            let _ = handler.shutdown();
            return Err(error);
        }
    }
    run_receiver(receiver, writer, handler)
}

/// Receiver-based core with a real monotonic clock starting at zero for this
/// run. An external pump must use sync_channel(1) and send an explicit terminal
/// event. This function creates no thread and does not read any pipe itself.
pub fn run_receiver(
    receiver: Receiver<ChannelEvent>,
    writer: &mut impl Write,
    handler: &mut impl Handler,
) -> io::Result<()> {
    run_with_wait(
        &mut ReceiverWait {
            receiver,
            origin: Instant::now(),
        },
        writer,
        handler,
    )
}

/// Tick immediately, then on a 100ms timer checked between every queued frame.
/// Sustained input cannot bypass the timer. All ordinary exit paths invoke
/// shutdown exactly once; its error is returned only if no earlier error exists.
pub fn run_with_wait(
    wait: &mut impl ChannelWait,
    writer: &mut impl Write,
    handler: &mut impl Handler,
) -> io::Result<()> {
    let result = (|| {
        let mut next_tick_ms = wait.now_ms();
        loop {
            let now_ms = wait.now_ms();
            if now_ms >= next_tick_ms {
                handler.tick(now_ms)?;
                // Skip missed intervals instead of an unbounded catch-up burst.
                next_tick_ms = now_ms.saturating_add(TICK_INTERVAL_MS);
            }
            let timeout = Duration::from_millis(
                next_tick_ms
                    .saturating_sub(wait.now_ms())
                    .min(TICK_INTERVAL_MS),
            );
            match wait.recv_timeout(timeout) {
                Ok(ChannelEvent::Frame(frame)) => {
                    frame_body(&frame, MAX_ENGINE_FRAME)?;
                    let response = handler.handle(&frame)?;
                    writer.write_all(&response)?;
                    writer.flush()?;
                }
                Ok(ChannelEvent::Eof) => return Ok(()),
                Ok(ChannelEvent::ReadError(error)) => return Err(error),
                Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "engine_control_reader_disconnected",
                    ));
                }
            }
        }
    })();
    let cleanup = handler.shutdown();
    result.and(cleanup)
}
