//! Direct DNS over sockets bound to an explicitly discovered physical link.
use super::physical::{DnsServer, Interface, Snapshot};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, UdpSocket},
};

const MAX_SERVERS: usize = 16;
const MAX_ADDRESSES: usize = 64;
const MAX_CNAME_HOPS: usize = 8;
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_RESPONSE: usize = u16::MAX as usize;

pub(super) type BindSocket = fn(&socket2::Socket, &Interface, SocketAddr) -> io::Result<()>;

pub(super) async fn resolve(
    host: &str,
    snapshot: &Snapshot,
    servers: &[DnsServer],
    bind: BindSocket,
) -> io::Result<Vec<IpAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        snapshot.interface(address).map_err(|_| unavailable())?;
        return Ok(vec![address]);
    }
    if servers.is_empty() || servers.len() > MAX_SERVERS {
        return Err(unavailable());
    }
    let mut name = Name::from_ascii(host).map_err(|_| unavailable())?;
    if name.is_root() {
        return Err(unavailable());
    }
    name.set_fqdn(true);
    let mut addresses = Vec::new();
    for (available, kind) in [
        (snapshot.ipv4.is_some(), RecordType::A),
        (snapshot.ipv6.is_some(), RecordType::AAAA),
    ] {
        if !available {
            continue;
        }
        for server in servers {
            // One deadline covers this server's whole CNAME chain and any TCP
            // retry. The caller's dial deadline also covers all servers/families.
            if let Ok(Ok(answer)) = tokio::time::timeout(
                ATTEMPT_TIMEOUT,
                query_chain(name.clone(), kind, server, bind),
            )
            .await
            {
                for address in answer {
                    if addresses.len() < MAX_ADDRESSES && !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
                break;
            }
        }
        if addresses.len() == MAX_ADDRESSES {
            break;
        }
    }
    if addresses.is_empty() {
        Err(unavailable())
    } else {
        Ok(addresses)
    }
}

async fn query_chain(
    mut name: Name,
    kind: RecordType,
    server: &DnsServer,
    bind: BindSocket,
) -> io::Result<Vec<IpAddr>> {
    let mut visited = HashSet::from([name.clone()]);
    let mut hops = 0;
    loop {
        let mut query = Message::new();
        let random = uuid::Uuid::new_v4();
        query
            .set_id(u16::from_be_bytes([
                random.as_bytes()[0],
                random.as_bytes()[1],
            ]))
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(name.clone(), kind));
        let response = exchange(&query, server, bind).await?;
        if response.response_code() != ResponseCode::NoError {
            return Err(unavailable());
        }
        let original = name.clone();
        let mut owners = HashSet::new();
        let mut addresses = Vec::new();
        loop {
            owners.insert(name.clone());
            let mut alias = None;
            for record in response
                .answers()
                .iter()
                .filter(|record| record.name() == &name)
            {
                if record.dns_class() != DNSClass::IN {
                    return Err(unavailable());
                }
                match record.data() {
                    Some(RData::CNAME(target)) => {
                        if alias.as_ref().is_some_and(|existing| existing != &target.0) {
                            return Err(unavailable());
                        }
                        alias = Some(target.0.clone());
                    }
                    Some(RData::A(address)) if kind == RecordType::A => {
                        let address = IpAddr::V4(address.0);
                        if addresses.len() < MAX_ADDRESSES && !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                    Some(RData::AAAA(address)) if kind == RecordType::AAAA => {
                        let address = IpAddr::V6(address.0);
                        if addresses.len() < MAX_ADDRESSES && !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(target) = alias {
                hops += 1;
                if !addresses.is_empty()
                    || target.is_root()
                    || hops > MAX_CNAME_HOPS
                    || !visited.insert(target.clone())
                {
                    return Err(unavailable());
                }
                name = target;
            } else {
                break;
            }
        }
        // Address/CNAME records outside the validated chain cannot become an
        // origin address, even when the same packet has a plausible answer.
        if response.answers().iter().any(|record| {
            matches!(
                record.data(),
                Some(RData::A(_) | RData::AAAA(_) | RData::CNAME(_))
            ) && (!owners.contains(record.name()) || record.dns_class() != DNSClass::IN)
        }) {
            return Err(unavailable());
        }
        if !addresses.is_empty() || name == original {
            return Ok(addresses);
        }
        // The CNAME target was not answered in this packet. Query it only on
        // this same explicit DNS server and physical interface.
    }
}

fn fresh_socket(
    server: &DnsServer,
    kind: Type,
    protocol: Protocol,
    bind: BindSocket,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(server.address), kind, Some(protocol))?;
    socket.set_nonblocking(true)?;
    bind(&socket, &server.interface, server.address)?;
    Ok(socket)
}

fn matches_query(response: &Message, query: &Message) -> bool {
    response.id() == query.id()
        && response.message_type() == MessageType::Response
        && response.op_code() == OpCode::Query
        && response.queries() == query.queries()
}

async fn exchange(query: &Message, server: &DnsServer, bind: BindSocket) -> io::Result<Message> {
    let bytes = query.to_vec().map_err(|_| unavailable())?;
    let socket = fresh_socket(server, Type::DGRAM, Protocol::UDP, bind)?;
    let local = SocketAddr::new(
        if server.address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    socket.bind(&local.into())?;
    let socket = UdpSocket::from_std(socket.into())?;
    // A connected UDP socket also restricts accepted replies to this server.
    socket.connect(server.address).await?;
    socket.send(&bytes).await?;
    let mut buffer = vec![0; MAX_RESPONSE];
    loop {
        let length = socket.recv(&mut buffer).await?;
        let Ok(response) = Message::from_vec(&buffer[..length]) else {
            continue;
        };
        if !matches_query(&response, query) {
            continue;
        }
        if !response.truncated() {
            return Ok(response);
        }
        // The UDP payload is incomplete and is never used as an answer.
        let socket = fresh_socket(server, Type::STREAM, Protocol::TCP, bind)?;
        let mut stream = TcpSocket::from_std_stream(socket.into())
            .connect(server.address)
            .await?;
        let length = u16::try_from(bytes.len()).map_err(|_| unavailable())?;
        stream.write_u16(length).await?;
        stream.write_all(&bytes).await?;
        let length = usize::from(stream.read_u16().await?);
        if length < 12 {
            return Err(unavailable());
        }
        let mut buffer = vec![0; length];
        stream.read_exact(&mut buffer).await?;
        let response = Message::from_vec(&buffer).map_err(|_| unavailable())?;
        if response.truncated() || !matches_query(&response, query) {
            return Err(unavailable());
        }
        return Ok(response);
    }
}

fn unavailable() -> io::Error {
    io::Error::other("physical_dns_unavailable")
}

#[cfg(test)]
mod tests {
    use super::super::physical::DnsServer;
    use super::*;
    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{
            rdata::{A, AAAA, CNAME},
            Name, RData, Record, RecordType,
        },
    };
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    struct Server {
        address: SocketAddr,
        hits: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn udp(mut respond: impl FnMut(&Message) -> Vec<Message> + Send + 'static) -> Server {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 65535];
            loop {
                let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_vec(&bytes[..length]).unwrap();
                for message in respond(&request) {
                    socket
                        .send_to(&message.to_vec().unwrap(), peer)
                        .await
                        .unwrap();
                }
            }
        });
        Server {
            address,
            hits,
            task,
        }
    }

    fn interface() -> Interface {
        Interface {
            index: 7,
            name: "physical-test".into(),
            identity: "test-link".into(),
            addresses: vec!["192.0.2.4".parse().unwrap(), "2001:db8::4".parse().unwrap()],
            gateway: None,
        }
    }
    fn snapshot(address: SocketAddr, ipv6: bool) -> (Snapshot, Vec<DnsServer>) {
        (
            Snapshot {
                ipv4: Some(interface()),
                ipv6: ipv6.then(interface),
            },
            vec![DnsServer {
                address,
                interface: interface(),
            }],
        )
    }
    // Only the native interface-bind operation is replaced. DNS encoding,
    // transport, framing, parsing, retries, and deadlines use the real code.
    fn bind_loopback(
        _socket: &socket2::Socket,
        link: &Interface,
        remote: SocketAddr,
    ) -> io::Result<()> {
        if link != &interface() || !remote.ip().is_loopback() {
            return Err(io::Error::other("test_wrong_link"));
        }
        Ok(())
    }
    fn deny_bind(_: &socket2::Socket, _: &Interface, _: SocketAddr) -> io::Result<()> {
        Err(io::Error::other("test_bind_denied"))
    }
    fn deny_tcp_bind(
        socket: &socket2::Socket,
        link: &Interface,
        remote: SocketAddr,
    ) -> io::Result<()> {
        if socket.r#type()? == socket2::Type::STREAM {
            return Err(io::Error::other("test_tcp_bind_denied"));
        }
        bind_loopback(socket, link, remote)
    }
    fn response(request: &Message) -> Message {
        let mut message = Message::new();
        message
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_recursion_available(true)
            .add_queries(request.queries().iter().cloned());
        message
    }
    fn address_answer(message: &mut Message, name: Name, address: &str) {
        let data = match address.parse::<IpAddr>().unwrap() {
            IpAddr::V4(value) => RData::A(A(value)),
            IpAddr::V6(value) => RData::AAAA(AAAA(value)),
        };
        message.add_answer(Record::from_rdata(name, 60, data));
    }
    fn answer(request: &Message, address: &str) -> Message {
        let mut message = response(request);
        address_answer(&mut message, request.queries()[0].name().clone(), address);
        message
    }
    fn cname(request: &Message, alias: &str) -> Message {
        let mut message = response(request);
        message.add_answer(Record::from_rdata(
            request.queries()[0].name().clone(),
            60,
            RData::CNAME(CNAME(Name::from_ascii(alias).unwrap())),
        ));
        message
    }
    async fn lookup(
        state: &(Snapshot, Vec<DnsServer>),
        bind: BindSocket,
    ) -> io::Result<Vec<IpAddr>> {
        tokio::time::timeout(
            Duration::from_secs(3),
            resolve("service.invalid", &state.0, &state.1, bind),
        )
        .await
        .expect("DNS resolver did not respect its bounded attempts")
    }

    // Returning a resolver/default address instead of the configured server's
    // answer, or skipping the physical bind, must fail this pair of tests.
    #[tokio::test]
    async fn configured_dns_uses_real_udp_and_the_selected_link() {
        let server = udp(|request| vec![answer(request, "192.0.2.80")]).await;
        assert_eq!(
            lookup(&snapshot(server.address, false), bind_loopback)
                .await
                .unwrap(),
            vec!["192.0.2.80".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_physical_bind_sends_no_dns_packet_and_has_no_fallback() {
        let server = udp(|request| vec![answer(request, "192.0.2.80")]).await;
        let error = lookup(&snapshot(server.address, false), deny_bind)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "physical_dns_unavailable");
        assert_eq!(server.hits.load(Ordering::SeqCst), 0);
    }

    // Removing response transaction/question/opcode validation returns poison.
    #[tokio::test]
    async fn mismatched_udp_responses_are_ignored_before_the_matching_response() {
        for mismatch in 0..4 {
            let server = udp(move |request| {
                let mut poison = answer(request, "203.0.113.66");
                match mismatch {
                    0 => {
                        poison.set_id(request.id().wrapping_add(1));
                    }
                    1 => {
                        poison.set_op_code(OpCode::Status);
                    }
                    2 => {
                        poison.queries_mut()[0]
                            .set_name(Name::from_ascii("other.invalid.").unwrap());
                    }
                    _ => {
                        poison.set_message_type(MessageType::Query);
                    }
                }
                vec![poison, answer(request, "192.0.2.80")]
            })
            .await;
            assert_eq!(
                lookup(&snapshot(server.address, false), bind_loopback)
                    .await
                    .unwrap(),
                vec!["192.0.2.80".parse::<IpAddr>().unwrap()]
            );
        }
    }

    #[tokio::test]
    async fn unrelated_answer_cannot_supply_the_origin_address() {
        let server = udp(|request| {
            let mut message = response(request);
            address_answer(
                &mut message,
                Name::from_ascii("other.invalid.").unwrap(),
                "203.0.113.66",
            );
            vec![message]
        })
        .await;
        assert!(lookup(&snapshot(server.address, false), bind_loopback)
            .await
            .is_err());
    }

    // Returning early after A NODATA would lose a working physical IPv6 route.
    #[tokio::test]
    async fn a_nodata_still_queries_aaaa_when_ipv6_is_available() {
        let server = udp(|request| {
            vec![if request.queries()[0].query_type() == RecordType::A {
                response(request)
            } else {
                answer(request, "2001:db8::80")
            }]
        })
        .await;
        assert_eq!(
            lookup(&snapshot(server.address, true), bind_loopback)
                .await
                .unwrap(),
            vec!["2001:db8::80".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cname_is_followed_on_the_same_configured_dns_link() {
        let server = udp(|request| {
            vec![
                if request.queries()[0].name() == &Name::from_ascii("service.invalid.").unwrap() {
                    cname(request, "alias.invalid.")
                } else {
                    answer(request, "192.0.2.81")
                },
            ]
        })
        .await;
        assert_eq!(
            lookup(&snapshot(server.address, false), bind_loopback)
                .await
                .unwrap(),
            vec!["192.0.2.81".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cname_cycle_is_rejected_without_repeating_the_cycle() {
        let server = udp(|request| {
            vec![
                if request.queries()[0].name() == &Name::from_ascii("service.invalid.").unwrap() {
                    cname(request, "alias.invalid.")
                } else {
                    cname(request, "service.invalid.")
                },
            ]
        })
        .await;
        assert!(lookup(&snapshot(server.address, false), bind_loopback)
            .await
            .is_err());
        assert_eq!(server.hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cname_chain_longer_than_eight_hops_is_rejected() {
        let mut number = 0;
        let server = udp(move |request| {
            number += 1;
            vec![cname(request, &format!("alias{number}.invalid."))]
        })
        .await;
        assert!(lookup(&snapshot(server.address, false), bind_loopback)
            .await
            .is_err());
        assert!(server.hits.load(Ordering::SeqCst) <= 9);
    }

    async fn truncated_servers() -> (Server, Server) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = UdpSocket::bind(address).await.unwrap();
        let udp_hits = Arc::new(AtomicUsize::new(0));
        let observed = udp_hits.clone();
        let udp_task = tokio::spawn(async move {
            let mut bytes = [0; 65535];
            loop {
                let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                let request = Message::from_vec(&bytes[..length]).unwrap();
                let mut message = answer(&request, "203.0.113.66");
                message.set_truncated(true);
                socket
                    .send_to(&message.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let observed = tcp_hits.clone();
        let tcp_task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                let length = socket.read_u16().await.unwrap();
                let mut bytes = vec![0; usize::from(length)];
                socket.read_exact(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes).unwrap();
                let bytes = answer(&request, "192.0.2.82").to_vec().unwrap();
                socket.write_u16(bytes.len() as u16).await.unwrap();
                // Split the frame so a single read cannot satisfy the response.
                socket.write_all(&bytes[..3]).await.unwrap();
                tokio::task::yield_now().await;
                socket.write_all(&bytes[3..]).await.unwrap();
            }
        });
        (
            Server {
                address,
                hits: udp_hits,
                task: udp_task,
            },
            Server {
                address,
                hits: tcp_hits,
                task: tcp_task,
            },
        )
    }

    // Accepting the truncated UDP payload, omitting TCP, or reading an
    // unframed/partial TCP response would return poison or fail this result.
    #[tokio::test]
    async fn truncated_udp_retries_with_length_framed_tcp() {
        let (udp, tcp) = truncated_servers().await;
        assert_eq!(
            lookup(&snapshot(udp.address, false), bind_loopback)
                .await
                .unwrap(),
            vec!["192.0.2.82".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(udp.hits.load(Ordering::SeqCst), 1);
        assert_eq!(tcp.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tcp_fallback_cannot_bypass_a_failed_physical_bind() {
        let (udp, tcp) = truncated_servers().await;
        assert!(lookup(&snapshot(udp.address, false), deny_tcp_bind)
            .await
            .is_err());
        assert_eq!(tcp.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn silent_dns_server_times_out_instead_of_waiting_forever() {
        let server = udp(|_| vec![]).await;
        let started = tokio::time::Instant::now();
        assert!(lookup(&snapshot(server.address, false), bind_loopback)
            .await
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn literal_origin_requires_the_matching_physical_family() {
        let state = Snapshot {
            ipv4: Some(interface()),
            ipv6: None,
        };
        assert_eq!(
            resolve("192.0.2.90", &state, &[], deny_bind).await.unwrap(),
            vec!["192.0.2.90".parse::<IpAddr>().unwrap()]
        );
        assert!(resolve("2001:db8::90", &state, &[], bind_loopback)
            .await
            .is_err());
        assert!(resolve("service.invalid", &state, &[], bind_loopback)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn address_results_are_bounded() {
        let server = udp(|request| {
            let mut message = response(request);
            for last in 1..=80 {
                address_answer(
                    &mut message,
                    request.queries()[0].name().clone(),
                    &format!("192.0.2.{last}"),
                );
            }
            vec![message]
        })
        .await;
        let addresses = lookup(&snapshot(server.address, false), bind_loopback)
            .await
            .unwrap();
        assert_eq!(addresses.len(), 64);
        assert_eq!(addresses[0], "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(addresses[63], "192.0.2.64".parse::<IpAddr>().unwrap());
    }
}
