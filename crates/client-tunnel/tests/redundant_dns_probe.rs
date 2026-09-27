use nelomai_client_tunnel::redundancy::{DnsProbe, ProbeDatagram, ProbePoll};
use std::{collections::VecDeque, io, net::Ipv4Addr};

#[derive(Default)]
struct Datagram {
    sent: Vec<Vec<u8>>,
    replies: VecDeque<Vec<u8>>,
}
impl ProbeDatagram for &mut Datagram {
    fn send(&mut self, data: &[u8]) -> io::Result<usize> {
        self.sent.push(data.to_vec());
        Ok(data.len())
    }
    fn receive(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let data = self.replies.pop_front().ok_or(io::ErrorKind::WouldBlock)?;
        buffer[..data.len()].copy_from_slice(&data);
        Ok(data.len())
    }
}

fn answer() -> Vec<u8> {
    // ID 0x1234, normal recursive answer, one question and one A record.
    b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01".to_vec()
}

#[test]
fn sends_one_dns_query_and_accepts_only_its_complete_answer() {
    let mut socket = Datagram::default();
    socket.replies.push_back(answer());
    let mut probe = DnsProbe::start(&mut socket, "example.com", 0x1234, 100, 1000).unwrap();
    assert_eq!(probe.poll(101), ProbePoll::Succeeded);
    assert_eq!(probe.poll(102), ProbePoll::Finished);
    drop(probe);
    assert_eq!(socket.sent, [b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01".to_vec()]);
}

#[test]
fn unrelated_truncated_error_and_query_packets_cannot_prove_reserve_healthy() {
    let good = answer();
    let mut packets = Vec::new();
    let mut wrong_id = good.clone();
    wrong_id[0] = 0x13;
    packets.push(wrong_id);
    let mut wrong_name = good.clone();
    wrong_name[13] = b'X';
    packets.push(wrong_name);
    let mut error = good.clone();
    error[3] = 0x83;
    packets.push(error);
    let mut query = good.clone();
    query[2] = 0x01;
    packets.push(query);
    let mut truncated = good.clone();
    truncated[2] = 0x83;
    packets.push(truncated);
    let mut no_answer = good.clone();
    no_answer[7] = 0;
    packets.push(no_answer);
    for length in 0..good.len() {
        packets.push(good[..length].to_vec());
    }
    for packet in packets {
        let mut socket = Datagram::default();
        socket.replies.push_back(packet);
        let mut probe = DnsProbe::start(&mut socket, "example.com", 0x1234, 100, 1000).unwrap();
        assert_eq!(probe.poll(101), ProbePoll::Pending);
        assert_eq!(probe.poll(1100), ProbePoll::Failed);
    }
}

#[test]
fn queued_success_at_deadline_is_timeout_and_poll_never_blocks() {
    let mut socket = Datagram::default();
    socket.replies.push_back(answer());
    let mut probe = DnsProbe::start(&mut socket, "example.com", 0x1234, 0, 1000).unwrap();
    assert_eq!(probe.poll(1000), ProbePoll::Failed);
    assert_eq!(probe.poll(1001), ProbePoll::Finished);
}

#[test]
fn malformed_name_and_invalid_deadline_are_rejected_before_any_send() {
    for name in ["", ".", "a..b", "a/b", "a\nb", "-a.com", "a-.com"] {
        assert!(DnsProbe::start(&mut Datagram::default(), name, 1, 0, 1000).is_err());
    }
    assert!(DnsProbe::start(&mut Datagram::default(), "example.com", 1, 0, 0).is_err());
    assert!(DnsProbe::start(&mut Datagram::default(), "example.com", 1, u64::MAX, 1000).is_err());
}

#[test]
fn bound_socket_rejects_missing_interface_before_network_io() {
    use nelomai_client_tunnel::redundancy::NativeProbeSocket;
    assert!(
        NativeProbeSocket::open(0, Ipv4Addr::new(10, 10, 0, 1), Ipv4Addr::new(9, 9, 9, 9)).is_err()
    );
}
