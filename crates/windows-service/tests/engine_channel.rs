#[path = "../src/engine_channel.rs"]
mod channel;

use nelomai_client_tunnel::redundancy::engine_channel::{self, ChannelEvent, ChannelWait, Handler};
use nelomai_contracts::dispatcher::{self as d, EnginePrimitive};
use std::{
    io::{self, Write},
    sync::mpsc::RecvTimeoutError,
    time::Duration,
};

struct ReplyWriter<'a> {
    router: &'a mut channel::InputRouter,
    replies: Vec<Vec<u8>>,
    bytes: Vec<u8>,
}
impl Write for ReplyWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        for frame in self.replies.drain(..) {
            let _ = self.router.route_frame(frame);
        }
        Ok(())
    }
}
fn ack(value: bool) -> Vec<u8> {
    d::encode_frame(&serde_json::json!({"primitive_ok":value})).unwrap()
}
fn tick() -> Vec<u8> {
    d::encode_frame(&serde_json::json!({"dispatcher_control":"tick"})).unwrap()
}

#[test]
fn queued_control_frame_cannot_steal_primitive_reply() {
    let (mut router, frames, client) = channel::channel();
    channel::with_owner(client, || {
        let mut writer = ReplyWriter {
            router: &mut router,
            replies: vec![tick(), ack(true)],
            bytes: vec![],
        };
        channel::request_primitive(EnginePrimitive::RebindService, &mut writer).unwrap();
        let request: d::PrimitiveRequest =
            serde_json::from_slice(d::frame_body(&writer.bytes, d::MAX_ENGINE_FRAME).unwrap())
                .unwrap();
        assert!(matches!(
            request.engine_primitive,
            EnginePrimitive::RebindService
        ));
        assert!(
            matches!(frames.try_recv().unwrap(), ChannelEvent::Frame(frame) if frame == tick())
        );
        assert!(frames.try_recv().is_err());
    })
    .unwrap();
}

#[test]
fn unsolicited_duplicate_extra_field_and_malformed_ack_fail_closed() {
    let (mut router, _frames, client) = channel::channel();
    assert!(router.route_frame(ack(true)).is_err());
    channel::with_owner(client, || assert!(channel::ensure_healthy().is_err())).unwrap();

    for replies in [
        vec![ack(true), ack(true)],
        vec![d::encode_frame(&serde_json::json!({"primitive_ok":"true"})).unwrap()],
        vec![d::encode_frame(&serde_json::json!({"primitive_ok":true,"extra":"SECRET"})).unwrap()],
        {
            let body = br#"{"primitive_ok":true,"primitive_ok":true}"#;
            let mut f = (body.len() as u32).to_le_bytes().to_vec();
            f.extend_from_slice(body);
            vec![f]
        },
    ] {
        let (mut router, _frames, client) = channel::channel();
        channel::with_owner(client, || {
            let mut writer = ReplyWriter {
                router: &mut router,
                replies,
                bytes: vec![],
            };
            let error = channel::request_primitive(EnginePrimitive::RebindService, &mut writer)
                .unwrap_err();
            assert!(!error.to_string().contains("SECRET"));
            assert!(channel::ensure_healthy().is_err());
        })
        .unwrap();
    }
}

#[test]
fn negative_ack_is_a_primitive_failure_not_success() {
    let (mut router, _frames, client) = channel::channel();
    channel::with_owner(client, || {
        let mut writer = ReplyWriter {
            router: &mut router,
            replies: vec![ack(false)],
            bytes: vec![],
        };
        assert!(channel::request_primitive(EnginePrimitive::RebindService, &mut writer).is_err());
        channel::ensure_healthy().unwrap();
    })
    .unwrap();
}

#[test]
fn full_command_queue_fails_instead_of_blocking_the_ack_pump() {
    let (mut router, _frames, client) = channel::channel();
    channel::with_owner(client, || {
        let mut writer = ReplyWriter {
            router: &mut router,
            replies: vec![tick(), tick(), ack(true)],
            bytes: vec![],
        };
        assert!(channel::request_primitive(EnginePrimitive::RebindService, &mut writer).is_err());
    })
    .unwrap();
}

#[test]
fn primitive_api_is_owner_thread_only_and_never_reads_input() {
    let (_router, _frames, client) = channel::channel();
    channel::with_owner(client, || {
        std::thread::spawn(|| {
            let mut output = vec![];
            assert!(
                channel::request_primitive(EnginePrimitive::RebindService, &mut output).is_err()
            );
            assert!(output.is_empty());
        })
        .join()
        .unwrap();
    })
    .unwrap();
    assert!(channel::ensure_healthy().is_err());
}

#[test]
fn eof_unblocks_pending_primitive_without_a_second_reader() {
    struct EofWriter(channel::InputRouter);
    impl Write for EofWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.finish(None);
            Ok(())
        }
    }
    let (router, frames, client) = channel::channel();
    channel::with_owner(client, || {
        assert!(
            channel::request_primitive(EnginePrimitive::RebindService, &mut EofWriter(router))
                .is_err()
        );
        assert!(matches!(frames.try_recv().unwrap(), ChannelEvent::Eof));
    })
    .unwrap();
}

#[test]
fn sole_owned_reader_reports_eof_and_shared_loop_performs_cleanup() {
    struct Owner(usize);
    impl Handler for Owner {
        fn handle(&mut self, _: &[u8]) -> io::Result<Vec<u8>> {
            unreachable!()
        }
        fn tick(&mut self, _: u64) -> io::Result<()> {
            Ok(())
        }
        fn shutdown(&mut self) -> io::Result<()> {
            self.0 += 1;
            Ok(())
        }
    }
    let (frames, client) = channel::spawn_input(std::io::Cursor::new(Vec::<u8>::new())).unwrap();
    let mut owner = Owner(0);
    channel::with_owner(client, || {
        engine_channel::run_receiver(frames, &mut vec![], &mut owner)
    })
    .unwrap()
    .unwrap();
    assert_eq!(owner.0, 1);
}

#[test]
fn idle_owner_can_request_a_primitive_before_broker_tick_arrives() {
    // flush simulates the manager exchange: it queues tick then handles the
    // already-written primitive, without any GUI request or a second reader.
    struct Owner<'a> {
        router: &'a mut channel::InputRouter,
        shutdowns: usize,
    }
    impl Handler for Owner<'_> {
        fn handle(&mut self, _: &[u8]) -> io::Result<Vec<u8>> {
            d::encode_frame(&serde_json::json!({"engine_tick":true}))
        }
        fn tick(&mut self, _: u64) -> io::Result<()> {
            channel::request_primitive(
                EnginePrimitive::RebindService,
                &mut ReplyWriter {
                    router: self.router,
                    replies: vec![tick(), ack(true)],
                    bytes: vec![],
                },
            )
        }
        fn shutdown(&mut self) -> io::Result<()> {
            self.shutdowns += 1;
            Ok(())
        }
    }
    struct Wait(std::sync::mpsc::Receiver<ChannelEvent>, bool);
    impl ChannelWait for Wait {
        fn now_ms(&self) -> u64 {
            0
        }
        fn recv_timeout(&mut self, _: Duration) -> Result<ChannelEvent, RecvTimeoutError> {
            if self.1 {
                return Ok(ChannelEvent::Eof);
            }
            self.1 = true;
            self.0
                .try_recv()
                .map_err(|_| RecvTimeoutError::Disconnected)
        }
    }
    let (mut router, frames, client) = channel::channel();
    channel::with_owner(client, || {
        let mut owner = Owner {
            router: &mut router,
            shutdowns: 0,
        };
        let mut output = vec![];
        engine_channel::run_with_wait(&mut Wait(frames, false), &mut output, &mut owner).unwrap();
        assert_eq!(
            output,
            d::encode_frame(&serde_json::json!({"engine_tick":true})).unwrap()
        );
        assert_eq!(owner.shutdowns, 1);
    })
    .unwrap();
}
