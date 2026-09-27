//! Addressed kernel WG socket reset; never reconfigure/flush the interface.
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_wireguard::{WireguardAttribute, WireguardCmd, WireguardMessage};
use std::io;

trait KernelRebindIo {
    fn exchange(&mut self, request: &[u8]) -> io::Result<Vec<u8>>;
}
fn packet<T: NetlinkSerializable>(
    mut request: NetlinkMessage<T>,
    sequence: u32,
    flags: u16,
) -> Vec<u8> {
    request.header.sequence_number = sequence;
    request.header.flags = flags;
    request.finalize();
    let mut bytes = vec![0; request.buffer_len()];
    request.serialize(&mut bytes);
    bytes
}
fn reset_port_with(index: u32, io: &mut impl KernelRebindIo) -> io::Result<()> {
    if index == 0 {
        return Err(invalid());
    }
    let family_request = packet(
        NetlinkMessage::from(GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName("wireguard".into())],
        })),
        1,
        NLM_F_REQUEST,
    );
    let reply = io.exchange(&family_request)?;
    let family =
        NetlinkMessage::<GenlMessage<GenlCtrl>>::deserialize(&reply).map_err(|_| invalid())?;
    if family.header.sequence_number != 1 {
        return Err(invalid());
    }
    let NetlinkPayload::InnerMessage(family) = family.payload else {
        return Err(invalid());
    };
    if family.payload.cmd != GenlCtrlCmd::NewFamily {
        return Err(invalid());
    }
    let ids = family
        .payload
        .nlas
        .iter()
        .filter_map(|a| match a {
            GenlCtrlAttrs::FamilyId(id) => Some(*id),
            _ => None,
        })
        .collect::<Vec<_>>();
    if ids.len() != 1 || ids[0] <= 16 {
        return Err(invalid());
    }
    let mut set = GenlMessage::from_payload(WireguardMessage {
        cmd: WireguardCmd::SetDevice,
        attributes: vec![
            WireguardAttribute::IfIndex(index),
            WireguardAttribute::ListenPort(0),
        ],
    });
    set.set_resolved_family_id(ids[0]);
    let reply = io.exchange(&packet(
        NetlinkMessage::from(set),
        2,
        NLM_F_REQUEST | NLM_F_ACK,
    ))?;
    let ack = NetlinkMessage::<GenlMessage<WireguardMessage>>::deserialize(&reply)
        .map_err(|_| invalid())?;
    if ack.header.sequence_number != 2 {
        return Err(invalid());
    }
    match ack.payload {
        NetlinkPayload::Error(e) if e.code.is_none() => Ok(()),
        _ => Err(invalid()),
    }
}
fn invalid() -> io::Error {
    io::Error::other("kernel_rebind_unconfirmed")
}

#[cfg(target_os = "linux")]
pub(super) fn reset_kernel_port(index: u32) -> io::Result<()> {
    reset_port_with(index, &mut NativeKernel)
}
#[cfg(target_os = "linux")]
struct NativeKernel;
#[cfg(target_os = "linux")]
impl KernelRebindIo for NativeKernel {
    fn exchange(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
        use netlink_sys::{constants::NETLINK_GENERIC, Socket, SocketAddr};
        use std::{
            os::fd::AsRawFd,
            time::{Duration, Instant},
        };
        let socket = Socket::new(NETLINK_GENERIC)?;
        socket.set_non_blocking(true)?;
        socket.connect(&SocketAddr::new(0, 0))?;
        if socket.send(request, 0)? != request.len() {
            return Err(invalid());
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "kernel_rebind_timeout",
                ));
            }
            let mut fd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready =
                unsafe { libc::poll(&mut fd, 1, (deadline - now).as_millis().max(1) as i32) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            let mut buffer = [0u8; 8192];
            match socket.recv_from(&mut &mut buffer[..], 0) {
                Ok((len, from))
                    if from.port_number() == 0
                        && from.multicast_groups() == 0
                        && len < buffer.len() =>
                {
                    return Ok(buffer[..len].to_vec())
                }
                Ok(_) => return Err(invalid()),
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted =>
                {
                    continue
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{
        ErrorMessage, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
    };
    use netlink_packet_generic::{
        ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
        GenlMessage,
    };
    use netlink_packet_wireguard::{WireguardAttribute, WireguardCmd, WireguardMessage};
    use std::io;

    struct Kernel {
        requests: Vec<Vec<u8>>,
        fail_family: bool,
        fail_set: bool,
        wrong_sequence: bool,
        wrong_family: bool,
    }
    impl KernelRebindIo for Kernel {
        fn exchange(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
            self.requests.push(request.to_vec());
            if self.requests.len() == 1 {
                let req = NetlinkMessage::<GenlMessage<GenlCtrl>>::deserialize(request).unwrap();
                let NetlinkPayload::InnerMessage(g) = req.payload else {
                    panic!("family request");
                };
                assert_eq!(
                    g.payload.nlas,
                    vec![GenlCtrlAttrs::FamilyName("wireguard".into())]
                );
                if self.fail_family {
                    return Err(io::Error::other("kernel unavailable"));
                }
                let mut response = NetlinkMessage::from(GenlMessage::from_payload(GenlCtrl {
                    cmd: if self.wrong_family {
                        GenlCtrlCmd::DelFamily
                    } else {
                        GenlCtrlCmd::NewFamily
                    },
                    nlas: vec![GenlCtrlAttrs::FamilyId(31)],
                }));
                response.header.sequence_number = req.header.sequence_number;
                response.finalize();
                let mut bytes = vec![0; response.buffer_len()];
                response.serialize(&mut bytes);
                Ok(bytes)
            } else {
                let req =
                    NetlinkMessage::<GenlMessage<WireguardMessage>>::deserialize(request).unwrap();
                assert_eq!(req.header.flags, NLM_F_REQUEST | NLM_F_ACK);
                assert_eq!(req.header.message_type, 31);
                let NetlinkPayload::InnerMessage(g) = req.payload else {
                    panic!("set device");
                };
                assert_eq!(g.payload.cmd, WireguardCmd::SetDevice);
                // In particular no key/peer/AllowedIPs/MTU/address changes.
                assert_eq!(
                    g.payload.attributes,
                    vec![
                        WireguardAttribute::IfIndex(42),
                        WireguardAttribute::ListenPort(0)
                    ]
                );
                let mut error = ErrorMessage::default();
                error.code = if self.fail_set {
                    std::num::NonZeroI32::new(-1)
                } else {
                    None
                };
                let mut h = NetlinkHeader::default();
                h.sequence_number = req.header.sequence_number + u32::from(self.wrong_sequence);
                let mut ack = NetlinkMessage::<GenlMessage<WireguardMessage>>::new(
                    h,
                    NetlinkPayload::Error(error),
                );
                ack.finalize();
                let mut bytes = vec![0; ack.buffer_len()];
                ack.serialize(&mut bytes);
                Ok(bytes)
            }
        }
    }
    fn kernel() -> Kernel {
        Kernel {
            requests: vec![],
            fail_family: false,
            fail_set: false,
            wrong_sequence: false,
            wrong_family: false,
        }
    }
    #[test]
    fn rebind_changes_only_listening_socket_of_the_verified_kernel_index() {
        let mut k = kernel();
        reset_port_with(42, &mut k).unwrap();
        assert_eq!(k.requests.len(), 2);
    }
    #[test]
    fn invalid_index_or_family_failure_never_sends_set_device() {
        let mut k = kernel();
        assert!(reset_port_with(0, &mut k).is_err());
        assert!(k.requests.is_empty());
        k.fail_family = true;
        assert!(reset_port_with(42, &mut k).is_err());
        assert_eq!(k.requests.len(), 1);
    }
    #[test]
    fn failed_or_unrelated_kernel_ack_never_reports_rebind_success() {
        let mut k = kernel();
        k.fail_set = true;
        assert!(reset_port_with(42, &mut k).is_err());
        let mut k = kernel();
        k.wrong_sequence = true;
        assert!(reset_port_with(42, &mut k).is_err());
    }
    #[test]
    fn unrelated_family_message_cannot_authorize_a_set_device_request() {
        let mut k = kernel();
        k.wrong_family = true;
        assert!(reset_port_with(42, &mut k).is_err());
        assert_eq!(k.requests.len(), 1);
    }
}
