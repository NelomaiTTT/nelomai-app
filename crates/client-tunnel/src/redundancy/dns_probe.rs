use std::io;

/// A connected, nonblocking datagram bound to the selected native member.
/// NativeProbeSocket is the production implementation; tests replace only I/O.
pub trait ProbeDatagram {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize>;
    fn receive(&mut self, packet: &mut [u8]) -> io::Result<usize>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbePoll {
    Pending,
    Succeeded,
    Failed,
    Finished,
}

/// One query, no retry loop or background thread. Dropping it closes its socket;
/// the session must also fence its ProbeTicket after Stop/rebind/promotion.
pub struct DnsProbe<S> {
    socket: S,
    query: Vec<u8>,
    started_ms: u64,
    deadline_ms: u64,
    finished: bool,
}

impl<S: ProbeDatagram> DnsProbe<S> {
    pub fn start(
        mut socket: S,
        name: &str,
        id: u16,
        now_ms: u64,
        timeout_ms: u64,
    ) -> io::Result<Self> {
        let deadline_ms = now_ms
            .checked_add(timeout_ms)
            .filter(|_| (1..=8000).contains(&timeout_ms))
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let query = query(name, id)?;
        if socket.send(&query)? != query.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(Self {
            socket,
            query,
            started_ms: now_ms,
            deadline_ms,
            finished: false,
        })
    }

    pub fn poll(&mut self, now_ms: u64) -> ProbePoll {
        if self.finished {
            return ProbePoll::Finished;
        }
        if now_ms < self.started_ms || now_ms >= self.deadline_ms {
            self.finished = true;
            return ProbePoll::Failed;
        }
        let mut packet = [0; 4096];
        // Bound work even if the peer floods invalid responses.
        for _ in 0..8 {
            match self.socket.receive(&mut packet) {
                Ok(n) if n <= packet.len() && accepts(&self.query, &packet[..n]) => {
                    self.finished = true;
                    return ProbePoll::Succeeded;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.finished = true;
                    return ProbePoll::Failed;
                }
            }
        }
        ProbePoll::Pending
    }
}

fn query(name: &str, id: u16) -> io::Result<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut result = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(result)
}

fn accepts(query: &[u8], packet: &[u8]) -> bool {
    if packet.len() < query.len() || packet[..2] != query[..2]
        || packet[2] & 0xfa != 0x80 // QR, normal opcode, no truncation
        || packet[3] & 0x0f != 0 || packet[4..6] != [0, 1]
        || packet[12..query.len()] != query[12..]
    {
        return false;
    }
    let count = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    if count == 0 || count > 128 {
        return false;
    }
    let mut offset = query.len();
    let mut has_a = false;
    for _ in 0..count {
        let Some(end) = skip_name(packet, offset) else {
            return false;
        };
        offset = end;
        let Some(header) = packet.get(offset..offset + 10) else {
            return false;
        };
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        offset += 10;
        if packet.get(offset..offset + length).is_none() {
            return false;
        }
        has_a |= header[..4] == [0, 1, 0, 1] && length == 4;
        offset += length;
    }
    has_a
}

fn skip_name(packet: &[u8], mut at: usize) -> Option<usize> {
    let mut end = None;
    let mut length = 0usize;
    for _ in 0..128 {
        let n = *packet.get(at)?;
        if n & 0xc0 == 0xc0 {
            let target = (usize::from(n & 0x3f) << 8) | usize::from(*packet.get(at + 1)?);
            // Compression points backwards; forbids cycles and header pointers.
            if target < 12 || target >= at {
                return None;
            }
            end.get_or_insert(at + 2);
            at = target;
        } else if n == 0 {
            return Some(end.unwrap_or(at + 1));
        } else if n <= 63 {
            let next = at + 1 + usize::from(n);
            packet.get(at + 1..next)?;
            length += usize::from(n) + 1;
            if length > 254 {
                return None;
            }
            at = next;
        } else {
            return None;
        }
    }
    None
}
