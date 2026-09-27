use nelomai_client_tunnel::redundancy::engine_channel::{
    run_engine_channel, run_receiver, run_with_wait, ChannelEvent, ChannelWait, Handler,
};
use nelomai_contracts::dispatcher::{encode_frame, MAX_ENGINE_FRAME};
use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{self, Cursor, Read, Write},
    rc::Rc,
    sync::mpsc::{self, RecvTimeoutError},
    time::Duration,
};

type Trace = Rc<RefCell<Vec<String>>>;

struct FakeWait {
    now: u64,
    events: VecDeque<(u64, Result<ChannelEvent, RecvTimeoutError>)>,
    waits: Vec<Duration>,
}
impl FakeWait {
    fn new(events: Vec<(u64, Result<ChannelEvent, RecvTimeoutError>)>) -> Self {
        Self {
            now: 0,
            events: events.into(),
            waits: vec![],
        }
    }
}
impl ChannelWait for FakeWait {
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn recv_timeout(&mut self, timeout: Duration) -> Result<ChannelEvent, RecvTimeoutError> {
        assert!(timeout <= Duration::from_millis(100));
        self.waits.push(timeout);
        let (elapsed, event) = self.events.pop_front().expect("unexpected extra wait");
        self.now += elapsed;
        event
    }
}

#[derive(Default)]
struct FakeHandler {
    trace: Trace,
    handle_error: bool,
    tick_error_at: Option<u64>,
    shutdown_error: bool,
}
impl Handler for FakeHandler {
    fn handle(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        self.trace.borrow_mut().push("frame".into());
        if self.handle_error {
            return Err(io::Error::other("handle"));
        }
        Ok(frame.to_vec())
    }
    fn tick(&mut self, now_ms: u64) -> io::Result<()> {
        self.trace.borrow_mut().push(format!("tick:{now_ms}"));
        if self.tick_error_at == Some(now_ms) {
            return Err(io::Error::other("tick"));
        }
        Ok(())
    }
    fn shutdown(&mut self) -> io::Result<()> {
        self.trace.borrow_mut().push("shutdown".into());
        if self.shutdown_error {
            return Err(io::Error::other("shutdown"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct FakeWriter {
    bytes: Vec<u8>,
    flushes: usize,
    write_error: bool,
    flush_error: bool,
}
impl Write for FakeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.write_error {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "write"));
        }
        // Force write_all to handle partial writes.
        let n = bytes.len().min(2);
        self.bytes.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flush_error {
            return Err(io::Error::other("flush"));
        }
        Ok(())
    }
}

fn frame() -> Vec<u8> {
    encode_frame(&serde_json::json!({"request":true})).unwrap()
}
fn assert_cleaned(handler: &FakeHandler) {
    let trace = handler.trace.borrow();
    assert_eq!(trace.last().map(String::as_str), Some("shutdown"));
    assert_eq!(trace.iter().filter(|s| *s == "shutdown").count(), 1);
}

#[test]
fn idle_dispatcher_pipe_ticks_without_ui_requests() {
    let mut wait = FakeWait::new(vec![
        (100, Err(RecvTimeoutError::Timeout)),
        (100, Err(RecvTimeoutError::Timeout)),
        (100, Err(RecvTimeoutError::Timeout)),
        (0, Ok(ChannelEvent::Eof)),
    ]);
    let mut handler = FakeHandler::default();
    run_with_wait(&mut wait, &mut FakeWriter::default(), &mut handler).unwrap();
    assert_eq!(
        *handler.trace.borrow(),
        ["tick:0", "tick:100", "tick:200", "tick:300", "shutdown"]
    );
    assert!(wait.waits.iter().all(|d| *d == Duration::from_millis(100)));
}

#[test]
fn queued_frame_flood_cannot_starve_timer_and_every_response_is_flushed() {
    let mut events = (0..10)
        .map(|_| (30, Ok(ChannelEvent::Frame(frame()))))
        .collect::<Vec<_>>();
    events.push((0, Ok(ChannelEvent::Eof)));
    let mut wait = FakeWait::new(events);
    let mut handler = FakeHandler::default();
    let mut writer = FakeWriter::default();
    run_with_wait(&mut wait, &mut writer, &mut handler).unwrap();
    assert_eq!(
        *handler.trace.borrow(),
        [
            "tick:0", "frame", "frame", "frame", "frame", "tick:120", "frame", "frame", "frame",
            "frame", "tick:240", "frame", "frame", "shutdown",
        ]
    );
    assert_eq!(writer.bytes, frame().repeat(10));
    assert_eq!(writer.flushes, 10);
    assert_eq!(wait.waits[3], Duration::from_millis(10));
}

#[test]
fn eof_is_clean_only_if_shutdown_succeeds() {
    for fails in [false, true] {
        let mut handler = FakeHandler {
            shutdown_error: fails,
            ..Default::default()
        };
        let mut wait = FakeWait::new(vec![(0, Ok(ChannelEvent::Eof))]);
        let result = run_with_wait(&mut wait, &mut FakeWriter::default(), &mut handler);
        assert_eq!(result.is_err(), fails);
        if fails {
            assert_eq!(result.unwrap_err().to_string(), "shutdown");
        }
        assert_cleaned(&handler);
    }
}

#[test]
fn read_handler_write_flush_and_tick_errors_cleanup_and_preserve_first_error() {
    for failure in ["read", "handle", "write", "flush", "tick"] {
        let mut handler = FakeHandler {
            handle_error: failure == "handle",
            tick_error_at: (failure == "tick").then_some(100),
            shutdown_error: true,
            ..Default::default()
        };
        let mut writer = FakeWriter {
            write_error: failure == "write",
            flush_error: failure == "flush",
            ..Default::default()
        };
        let event = match failure {
            "read" => (0, Ok(ChannelEvent::ReadError(io::Error::other("read")))),
            "tick" => (100, Err(RecvTimeoutError::Timeout)),
            _ => (0, Ok(ChannelEvent::Frame(frame()))),
        };
        let mut wait = FakeWait::new(vec![event]);
        assert_eq!(
            run_with_wait(&mut wait, &mut writer, &mut handler)
                .unwrap_err()
                .to_string(),
            failure
        );
        assert_cleaned(&handler);
    }
}

#[test]
fn receiver_disconnection_without_eof_is_an_error_and_cleans_up() {
    let (sender, receiver) = mpsc::sync_channel(1);
    drop(sender);
    let mut handler = FakeHandler::default();
    assert!(run_receiver(receiver, &mut FakeWriter::default(), &mut handler).is_err());
    assert_cleaned(&handler);
}

#[test]
fn owned_reader_pump_preserves_frames_and_reports_clean_eof() {
    let input = frame().repeat(3);
    let mut writer = FakeWriter::default();
    let mut handler = FakeHandler::default();
    run_engine_channel(Cursor::new(input.clone()), &mut writer, &mut handler).unwrap();
    assert_eq!(writer.bytes, input);
    assert_eq!(writer.flushes, 3);
    assert_cleaned(&handler);
}

#[test]
fn partial_header_or_body_is_read_error_not_clean_eof() {
    for bytes in [vec![1], vec![1, 0, 0], vec![3, 0, 0, 0, 42]] {
        let mut handler = FakeHandler::default();
        let result =
            run_engine_channel(Cursor::new(bytes), &mut FakeWriter::default(), &mut handler);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_cleaned(&handler);
        assert!(!handler.trace.borrow().iter().any(|s| s == "frame"));
    }
}

struct OversizedHeader {
    read: bool,
}
impl Read for OversizedHeader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(!self.read, "oversized body must not be read");
        self.read = true;
        bytes[..4].copy_from_slice(&(MAX_ENGINE_FRAME as u32 + 1).to_le_bytes());
        Ok(4)
    }
}

#[test]
fn oversized_length_is_rejected_before_reading_body() {
    let mut handler = FakeHandler::default();
    let error = run_engine_channel(
        OversizedHeader { read: false },
        &mut FakeWriter::default(),
        &mut handler,
    )
    .unwrap_err();
    assert_ne!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_cleaned(&handler);
    assert!(!handler.trace.borrow().iter().any(|s| s == "frame"));
}

#[test]
fn receiver_core_rejects_malformed_frame_before_handler() {
    let mut wait = FakeWait::new(vec![(0, Ok(ChannelEvent::Frame(vec![9, 0, 0, 0])))]);
    let mut handler = FakeHandler::default();
    assert!(run_with_wait(&mut wait, &mut FakeWriter::default(), &mut handler).is_err());
    assert_cleaned(&handler);
    assert!(!handler.trace.borrow().iter().any(|s| s == "frame"));
}
