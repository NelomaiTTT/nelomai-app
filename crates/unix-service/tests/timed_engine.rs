use nelomai_client_tunnel::{
    redundancy::engine_channel::{self, ChannelEvent, ChannelWait},
    DesktopTunnelOptions,
};
use nelomai_contracts::dispatcher as d;
use nelomai_unix_service::{
    decode_response, encode_request, run_timed_engine_channel, ParsedConfiguration, Request,
    ServiceError, ServiceTunnelBackend, ServiceTunnelState, TunnelRequestHandler, PROTOCOL_VERSION,
};
use std::{
    collections::VecDeque,
    io::{self, Cursor, Write},
    sync::mpsc::RecvTimeoutError,
    time::Duration,
};

#[derive(Default)]
struct Backend {
    calls: Vec<String>,
    fail_tick: bool,
    fail_shutdowns: usize,
}
impl ServiceTunnelBackend for Backend {
    fn start(
        &mut self,
        _: &ParsedConfiguration,
        _: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.calls.push("start".into());
        Ok(ServiceTunnelState::Running)
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.calls.push("stop".into());
        Ok(ServiceTunnelState::Stopped)
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        Ok(ServiceTunnelState::Running)
    }
    fn tick(&mut self, now: u64) -> Result<(), ServiceError> {
        self.calls.push(format!("tick:{now}"));
        if self.fail_tick {
            Err(ServiceError::Backend("SECRET_NATIVE_DETAIL".into()))
        } else {
            Ok(())
        }
    }
    fn shutdown(&mut self) -> Result<(), ServiceError> {
        self.calls.push("shutdown".into());
        if self.fail_shutdowns > 0 {
            self.fail_shutdowns -= 1;
            Err(ServiceError::Backend("SECRET_CLEANUP_DETAIL".into()))
        } else {
            Ok(())
        }
    }
}
struct Wait {
    now: u64,
    events: VecDeque<(u64, Result<ChannelEvent, RecvTimeoutError>)>,
}
impl Wait {
    fn new(events: Vec<(u64, Result<ChannelEvent, RecvTimeoutError>)>) -> Self {
        Self {
            now: 0,
            events: events.into(),
        }
    }
}
impl ChannelWait for Wait {
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn recv_timeout(&mut self, timeout: Duration) -> Result<ChannelEvent, RecvTimeoutError> {
        assert!(timeout <= Duration::from_millis(100));
        let (elapsed, event) = self.events.pop_front().expect("unexpected wait");
        self.now += elapsed;
        event
    }
}
fn frame(bytes: Vec<u8>) -> (u64, Result<ChannelEvent, RecvTimeoutError>) {
    (0, Ok(ChannelEvent::Frame(bytes)))
}
fn eof() -> (u64, Result<ChannelEvent, RecvTimeoutError>) {
    (0, Ok(ChannelEvent::Eof))
}
fn control(action: &str) -> Vec<u8> {
    d::encode_frame(&serde_json::json!({"dispatcher_control":action})).unwrap()
}
fn start() -> Vec<u8> {
    encode_request(&Request::start("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.1.2/32\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n".into())).unwrap()
}
fn responses(mut bytes: &[u8]) -> Vec<serde_json::Value> {
    let mut result = vec![];
    while !bytes.is_empty() {
        let frame = d::read_frame(&mut bytes, d::MAX_ENGINE_FRAME).unwrap();
        result.push(
            serde_json::from_slice(d::frame_body(&frame, d::MAX_ENGINE_FRAME).unwrap()).unwrap(),
        );
    }
    result
}

#[test]
fn idle_gui_does_not_stop_backend_ticks() {
    let mut handler = TunnelRequestHandler::new(Backend::default(), "test");
    let mut wait = Wait::new(vec![
        (100, Err(RecvTimeoutError::Timeout)),
        (100, Err(RecvTimeoutError::Timeout)),
        eof(),
    ]);
    let mut output = vec![];
    engine_channel::run_with_wait(&mut wait, &mut output, &mut handler).unwrap();
    assert_eq!(
        handler.backend().calls,
        ["tick:0", "tick:100", "tick:200", "shutdown"]
    );
    assert!(output.is_empty());
}

#[test]
fn ordinary_stop_allows_later_start_and_is_not_force_shutdown() {
    let mut handler = TunnelRequestHandler::new(Backend::default(), "test");
    let mut wait = Wait::new(vec![
        frame(encode_request(&Request::stop()).unwrap()),
        frame(start()),
        eof(),
    ]);
    let mut output = vec![];
    engine_channel::run_with_wait(&mut wait, &mut output, &mut handler).unwrap();
    assert_eq!(
        handler.backend().calls,
        ["tick:0", "stop", "start", "shutdown"]
    );
    let values = responses(&output);
    assert_eq!(values[0]["state"], "stopped");
    assert_eq!(values[1]["state"], "running");
}

#[test]
fn control_stop_acknowledges_cleanup_and_fences_future_start_in_same_process() {
    let mut handler = TunnelRequestHandler::new(Backend::default(), "test");
    let mut wait = Wait::new(vec![
        frame(control("ready")),
        frame(control("stop")),
        (100, Err(RecvTimeoutError::Timeout)),
        frame(control("stop")),
        frame(start()),
        eof(),
    ]);
    let mut output = vec![];
    engine_channel::run_with_wait(&mut wait, &mut output, &mut handler).unwrap();
    let values = responses(&output);
    assert_eq!(values[0], serde_json::json!({"engine_ready":true}));
    assert_eq!(values[1], serde_json::json!({"engine_stopped":true}));
    assert_eq!(values[2], serde_json::json!({"engine_stopped":true}));
    assert_eq!(values[3]["ok"], false);
    assert_eq!(handler.backend().calls, ["tick:0", "shutdown"]);
    assert!(!handler.handle(Request::start("irrelevant".into())).ok);
}

#[test]
fn failed_control_stop_reports_false_and_can_retry_cleanup_without_restarting() {
    let mut handler = TunnelRequestHandler::new(
        Backend {
            fail_shutdowns: 1,
            ..Default::default()
        },
        "test",
    );
    let mut wait = Wait::new(vec![
        frame(control("stop")),
        frame(start()),
        frame(control("stop")),
        eof(),
    ]);
    let mut output = vec![];
    engine_channel::run_with_wait(&mut wait, &mut output, &mut handler).unwrap();
    let values = responses(&output);
    assert_eq!(values[0], serde_json::json!({"engine_stopped":false}));
    assert_eq!(values[1]["ok"], false);
    assert_eq!(values[2], serde_json::json!({"engine_stopped":true}));
    assert_eq!(handler.backend().calls, ["tick:0", "shutdown", "shutdown"]);
}

#[test]
fn malformed_private_request_closes_native_and_returns_no_input_secrets() {
    let mut handler = TunnelRequestHandler::new(Backend::default(), "test");
    let malformed = d::encode_frame(
        &serde_json::json!({"command":"SECRET_BAD_COMMAND","configuration":"SECRET_KEY"}),
    )
    .unwrap();
    let mut wait = Wait::new(vec![frame(malformed), frame(start()), eof()]);
    let mut output = vec![];
    engine_channel::run_with_wait(&mut wait, &mut output, &mut handler).unwrap();
    let values = responses(&output);
    assert_eq!(values[0]["errorCode"], "invalid_request");
    assert_eq!(values[1]["ok"], false);
    assert!(!output
        .windows(b"SECRET".len())
        .any(|bytes| bytes == b"SECRET"));
    assert_eq!(handler.backend().calls, ["tick:0", "shutdown"]);
}

#[test]
fn old_protocol_gets_the_existing_bounded_rejection() {
    let mut handler = TunnelRequestHandler::new(Backend::default(), "test");
    let request = Request::Status {
        protocol_version: PROTOCOL_VERSION - 1,
    };
    let mut output = vec![];
    run_timed_engine_channel(
        Cursor::new(encode_request(&request).unwrap()),
        &mut output,
        &mut handler,
    )
    .unwrap();
    let response = decode_response(&output).unwrap();
    assert_eq!(response.error_code.as_deref(), Some("unsupported_protocol"));
    assert_eq!(
        handler
            .backend()
            .calls
            .iter()
            .filter(|s| *s == "shutdown")
            .count(),
        1
    );
}

struct BrokenWriter {
    flush: bool,
}
impl Write for BrokenWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.flush {
            Ok(bytes.len())
        } else {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "write_failed"))
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush_failed"))
    }
}

#[test]
fn write_and_flush_failure_cleanup_native_and_preserve_transport_error() {
    for flush in [false, true] {
        let mut handler = TunnelRequestHandler::new(
            Backend {
                fail_shutdowns: 1,
                ..Default::default()
            },
            "test",
        );
        let mut wait = Wait::new(vec![frame(control("ready"))]);
        let error =
            engine_channel::run_with_wait(&mut wait, &mut BrokenWriter { flush }, &mut handler)
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            if flush {
                "flush_failed"
            } else {
                "write_failed"
            }
        );
        assert_eq!(handler.backend().calls, ["tick:0", "shutdown"]);
    }
}

#[test]
fn failed_stop_ack_write_does_not_repeat_successful_native_cleanup() {
    for flush in [false, true] {
        let mut handler = TunnelRequestHandler::new(Backend::default(), "test");
        let mut wait = Wait::new(vec![frame(control("stop"))]);
        let error =
            engine_channel::run_with_wait(&mut wait, &mut BrokenWriter { flush }, &mut handler)
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            if flush {
                "flush_failed"
            } else {
                "write_failed"
            }
        );
        assert_eq!(handler.backend().calls, ["tick:0", "shutdown"]);
        assert!(!handler.handle(Request::start("unused".into())).ok);
    }
}

#[test]
fn decode_failure_keeps_first_error_when_native_cleanup_also_fails() {
    let mut handler = TunnelRequestHandler::new(
        Backend {
            fail_shutdowns: 2,
            ..Default::default()
        },
        "test",
    );
    let malformed = d::encode_frame(&serde_json::json!({"command":"SECRET_BAD_COMMAND"})).unwrap();
    let mut wait = Wait::new(vec![frame(malformed)]);
    let mut output = vec![];
    let error = engine_channel::run_with_wait(&mut wait, &mut output, &mut handler).unwrap_err();
    assert_eq!(error.to_string(), "invalid_request");
    assert!(output.is_empty());
    // Cleanup is attempted while handling the bad frame, then retried on exit.
    // Neither attempt succeeded, so the idempotence cache must not suppress it.
    assert_eq!(handler.backend().calls, ["tick:0", "shutdown", "shutdown"]);
    assert!(!handler.handle(Request::start("unused".into())).ok);
}

#[test]
fn read_and_framing_errors_shutdown_native() {
    for bytes in [vec![1, 0], vec![3, 0, 0, 0, 42]] {
        let mut handler = TunnelRequestHandler::new(Backend::default(), "test");
        let error =
            run_timed_engine_channel(Cursor::new(bytes), &mut vec![], &mut handler).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            handler
                .backend()
                .calls
                .iter()
                .filter(|s| *s == "shutdown")
                .count(),
            1
        );
    }
}

#[test]
fn tick_error_cleanup_and_eof_cleanup_failure_use_only_stable_error_codes() {
    for fail_tick in [false, true] {
        let mut handler = TunnelRequestHandler::new(
            Backend {
                fail_tick,
                fail_shutdowns: 1,
                ..Default::default()
            },
            "test",
        );
        let mut wait = Wait::new(vec![eof()]);
        let error =
            engine_channel::run_with_wait(&mut wait, &mut vec![], &mut handler).unwrap_err();
        assert_eq!(error.to_string(), "service_unavailable");
        assert_eq!(handler.backend().calls, ["tick:0", "shutdown"]);
    }
}
