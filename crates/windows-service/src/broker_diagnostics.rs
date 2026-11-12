use nelomai_contracts::dispatcher::BrokerDenial;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

const SOURCE: &str = "NelomaiTunnelBroker";
const FIRST_EVENT_ID: u32 = 9101;
pub const APPLICATION_EVENT_LIMIT: usize = 24;
const DENIALS: [BrokerDenial; 5] = [
    BrokerDenial::UidMismatch,
    BrokerDenial::SidMismatch,
    BrokerDenial::PathMismatch,
    BrokerDenial::ExecutableDigestMismatch,
    BrokerDenial::ExecutableUnavailableOrChanged,
];

#[cfg(windows)]
pub fn application_query() -> String {
    let last_event_id = FIRST_EVENT_ID + DENIALS.len() as u32 - 1;
    format!(
        "/q:*[System[Provider[@Name='{SOURCE}' or @EventSourceName='{SOURCE}'] \
         and (EventID >= {FIRST_EVENT_ID} and EventID <= {last_event_id}) \
         and TimeCreated[timediff(@SystemTime) <= 3600000]]]"
    )
}

/// Project only the fixed event IDs from `wevtutil qe Application /f:xml`.
/// Interactive users can write to Application under its default ACL, so these
/// events are support hints and must never be used for authorization.
pub fn application_denials(output: &[u8]) -> Vec<BrokerDenial> {
    String::from_utf8_lossy(output)
        .split("</Event>")
        .filter_map(|event| {
            let (_, system) = event.split_once("<System>")?;
            let (system, _) = system.split_once("</System>")?;
            let (_, provider) = system.split_once("<Provider ")?;
            let (provider, _) = provider.split_once('>')?;
            if !provider.split_ascii_whitespace().any(is_source_attribute) {
                return None;
            }
            let (_, id) = system.split_once("<EventID")?;
            let (qualifier, id) = id.split_once('>')?;
            // Legacy providers put the high 16 bits in the Qualifiers attribute.
            if !matches!(qualifier.trim(), "" | "Qualifiers='0'" | "Qualifiers=\"0\"") {
                return None;
            }
            let (id, _) = id.split_once("</EventID>")?;
            let index = id.parse::<u32>().ok()?.checked_sub(FIRST_EVENT_ID)? as usize;
            DENIALS.get(index).copied()
        })
        .take(APPLICATION_EVENT_LIMIT)
        .collect()
}

fn is_source_attribute(attribute: &str) -> bool {
    let Some((name, value)) = attribute.trim_end_matches('/').split_once('=') else {
        return false;
    };
    matches!(name, "Name" | "EventSourceName")
        && value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .or_else(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
            })
            == Some(SOURCE)
}

fn denial_index(denial: BrokerDenial) -> Option<usize> {
    DENIALS.iter().position(|known| *known == denial)
}

#[derive(Default)]
struct RateLimit {
    last_attempt: [Option<Instant>; DENIALS.len()],
}

impl RateLimit {
    fn next_event(&mut self, denial: BrokerDenial, now: Instant) -> Option<u32> {
        let index = denial_index(denial)?;
        let previous = &mut self.last_attempt[index];
        if previous.is_some_and(|time| now.duration_since(time) < Duration::from_secs(60)) {
            return None;
        }
        *previous = Some(now);
        Some(FIRST_EVENT_ID + index as u32)
    }
}

#[derive(Default)]
struct PendingDenials(AtomicU8);

impl PendingDenials {
    fn insert(&self, denial: BrokerDenial) -> bool {
        let Some(index) = denial_index(denial) else {
            return false;
        };
        let flag = 1 << index;
        self.0.fetch_or(flag, Ordering::Release) & flag == 0
    }

    fn take(&self) -> impl Iterator<Item = BrokerDenial> {
        let pending = self.0.swap(0, Ordering::AcqRel);
        DENIALS
            .into_iter()
            .enumerate()
            .filter_map(move |(index, denial)| (pending & (1 << index) != 0).then_some(denial))
    }
}

#[cfg(windows)]
pub(crate) use writer::{record, start};

#[cfg(windows)]
mod writer {
    use super::*;
    use std::ptr::{null, null_mut};
    use std::sync::OnceLock;
    use std::thread;
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_WARNING_TYPE,
    };

    static WORKER: OnceLock<Option<thread::Thread>> = OnceLock::new();
    static PENDING: PendingDenials = PendingDenials(AtomicU8::new(0));

    pub(crate) fn start() {
        WORKER.get_or_init(|| {
            let worker = thread::Builder::new()
                .name("nelomai-broker-event-log".into())
                .spawn(|| {
                    let mut limit = RateLimit::default();
                    loop {
                        thread::park();
                        for denial in PENDING.take() {
                            if let Some(id) = limit.next_event(denial, Instant::now()) {
                                report(id);
                            }
                        }
                    }
                })
                .ok()?;
            Some(worker.thread().clone())
        });
    }

    pub(crate) fn record(denial: BrokerDenial) {
        // One pending bit per reason keeps the accept loops independent of the
        // Event Log service, even while an Event Log call is stalled.
        if let Some(Some(worker)) = WORKER.get() {
            if PENDING.insert(denial) {
                worker.unpark();
            }
        }
    }

    fn report(id: u32) {
        // Windows uses Application for unregistered sources. The ID encodes the
        // denial and the event contains no client SID, strings, or binary data.
        let source = crate::windows::wide(SOURCE);
        unsafe {
            let handle = RegisterEventSourceW(null(), source.as_ptr());
            if !handle.is_null() {
                ReportEventW(
                    handle,
                    EVENTLOG_WARNING_TYPE,
                    0,
                    id,
                    null_mut(),
                    0,
                    0,
                    null(),
                    null(),
                );
                DeregisterEventSource(handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_events_project_only_known_denials_from_the_broker_provider() {
        let output = br#"
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
              <Provider Name='NelomaiTunnelBroker'/><EventID Qualifiers='0'>9104</EventID>
            </System><EventData><Data>private client path</Data></EventData></Event>
            <Event><System><Provider Name='OtherProvider'/><EventID>9102</EventID></System></Event>
            <Event><System><Provider Name='NelomaiTunnelBroker'/><EventID>9106</EventID></System></Event>
            <Event><System><Provider Name='NelomaiTunnelBroker'/><EventID Qualifiers='1'>9102</EventID></System></Event>
            <Event><System><Provider Name='Other' EventSourceName="NelomaiTunnelBroker"/>
              <EventID Qualifiers="0">9105</EventID></System></Event>
            <Event><System><Provider Name="NelomaiTunnelBroker"/><EventID>9101</EventID></System></Event>
        "#;
        assert_eq!(
            application_denials(output),
            [
                BrokerDenial::ExecutableDigestMismatch,
                BrokerDenial::ExecutableUnavailableOrChanged,
                BrokerDenial::UidMismatch,
            ]
        );
    }

    #[test]
    fn application_projection_caps_events() {
        let output = "<Event><System><Provider Name='NelomaiTunnelBroker'/><EventID>9103</EventID></System></Event>".repeat(25);
        assert_eq!(application_denials(output.as_bytes()).len(), 24);
    }

    #[test]
    fn repeated_denials_do_not_displace_other_pending_reasons() {
        let pending = PendingDenials::default();
        assert!(pending.insert(BrokerDenial::PathMismatch));
        for _ in 0..1024 {
            assert!(!pending.insert(BrokerDenial::PathMismatch));
        }
        assert!(pending.insert(BrokerDenial::SidMismatch));
        assert_eq!(
            pending.take().collect::<Vec<_>>(),
            [BrokerDenial::SidMismatch, BrokerDenial::PathMismatch]
        );
        assert!(pending.take().next().is_none());
        assert!(pending.insert(BrokerDenial::PathMismatch));
    }

    #[test]
    fn broker_event_attempts_are_throttled_per_denial() {
        let mut limit = RateLimit::default();
        let now = Instant::now();
        assert_eq!(
            limit.next_event(BrokerDenial::PathMismatch, now),
            Some(9103)
        );
        assert_eq!(
            limit.next_event(BrokerDenial::PathMismatch, now + Duration::from_secs(59)),
            None
        );
        assert_eq!(
            limit.next_event(BrokerDenial::SidMismatch, now + Duration::from_secs(59)),
            Some(9102)
        );
        assert_eq!(
            limit.next_event(BrokerDenial::PathMismatch, now + Duration::from_secs(60)),
            Some(9103)
        );
    }
}
