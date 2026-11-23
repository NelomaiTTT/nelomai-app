//! Gate automatic recovery on system power, not display/user-idle state.
use std::time::{Duration, Instant};

// On first observation, kern.waketime may already describe this wake.
const RECENT_WAKE_SECONDS: i64 = 15;
pub(crate) const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const FULL_WAKE: u64 = 0x01 | 0x02 | 0x08; // CPU, graphics capability, network.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryReadiness {
    Sleeping,
    WaitingForPanel,
    Ready,
}

impl RecoveryReadiness {
    pub(crate) fn allows_local_repair(self) -> bool {
        self != Self::Sleeping
    }

    pub(crate) fn allows_panel_work(self) -> bool {
        self == Self::Ready
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn defer_reason(self) -> Option<&'static str> {
        match self {
            Self::Sleeping => Some("sleep_or_dark_wake"),
            Self::WaitingForPanel => Some("wake_network_pending"),
            Self::Ready => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PanelWorkEpoch(u64, Option<i64>);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalRepairEpoch(u64, Option<i64>);

#[derive(Default)]
struct RecoveryGate {
    was_dark: bool,
    wake_stamp: Option<i64>,
    generation: u64,
    waiting_for_network: bool,
    next_probe: Option<Instant>,
}

impl RecoveryGate {
    fn observe(
        &mut self,
        capabilities: Option<u64>,
        wake: Option<i64>,
        unix: i64,
    ) -> RecoveryReadiness {
        let Some(capabilities) = capabilities else {
            return self.readiness();
        };
        if capabilities & FULL_WAKE != FULL_WAKE {
            self.was_dark = true;
            self.wake_stamp = wake.or(self.wake_stamp);
            return RecoveryReadiness::Sleeping;
        }
        let new_wake = wake.is_some_and(|stamp| {
            self.wake_stamp.is_some_and(|previous| previous != stamp)
                || (self.wake_stamp.is_none()
                    && (0..RECENT_WAKE_SECONDS).contains(&unix.saturating_sub(stamp)))
        });
        if self.was_dark || new_wake {
            self.generation = self.generation.wrapping_add(1);
            self.waiting_for_network = true;
            self.next_probe = None;
        }
        self.was_dark = false;
        self.wake_stamp = wake.or(self.wake_stamp);
        self.readiness()
    }

    fn readiness(&self) -> RecoveryReadiness {
        if self.was_dark {
            RecoveryReadiness::Sleeping
        } else if self.waiting_for_network {
            RecoveryReadiness::WaitingForPanel
        } else {
            RecoveryReadiness::Ready
        }
    }

    fn panel_work_epoch(&self) -> Option<PanelWorkEpoch> {
        self.readiness()
            .allows_panel_work()
            .then_some(PanelWorkEpoch(self.generation, None))
    }

    fn allows_panel_work(&self, epoch: PanelWorkEpoch) -> bool {
        self.readiness().allows_panel_work() && epoch.0 == self.generation
    }

    fn local_repair_epoch(&self) -> Option<LocalRepairEpoch> {
        self.readiness()
            .allows_local_repair()
            .then_some(LocalRepairEpoch(self.generation, None))
    }

    fn allows_local_repair(&self, epoch: LocalRepairEpoch) -> bool {
        self.readiness().allows_local_repair() && epoch.0 == self.generation
    }

    fn begin_probe(&mut self, now: Instant) -> Option<u64> {
        if self.was_dark
            || !self.waiting_for_network
            || self.next_probe.is_some_and(|next| now < next)
        {
            return None;
        }
        self.next_probe = Some(now + RETRY_INTERVAL);
        Some(self.generation)
    }

    fn confirm_network(&mut self, generation: u64) {
        if !self.was_dark && generation == self.generation {
            self.waiting_for_network = false;
        }
    }
}

#[cfg(target_os = "macos")]
fn observe<T>(use_gate: impl FnOnce(&mut RecoveryGate, RecoveryReadiness, Option<i64>) -> T) -> T {
    use std::sync::{Mutex, OnceLock, PoisonError};

    static GATE: OnceLock<Mutex<RecoveryGate>> = OnceLock::new();
    let mut gate = GATE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let capabilities = native::capabilities();
    let wake_stamp = native::wake_stamp();
    let reason = gate.observe(
        capabilities,
        wake_stamp.map(|stamp| stamp / 1_000_000),
        crate::current_unix_time(),
    );
    use_gate(&mut gate, reason, wake_stamp)
}

#[cfg(target_os = "macos")]
pub(crate) fn readiness() -> RecoveryReadiness {
    observe(|_, readiness, _| readiness)
}

#[cfg(target_os = "macos")]
pub(crate) fn panel_work_epoch() -> Option<PanelWorkEpoch> {
    observe(|gate, _, stamp| {
        gate.panel_work_epoch()
            .map(|epoch| PanelWorkEpoch(epoch.0, stamp))
    })
}

#[cfg(target_os = "macos")]
impl PanelWorkEpoch {
    pub(crate) fn wake_stamp(self) -> Option<i64> {
        self.1
    }

    pub(crate) fn is_current(self) -> bool {
        observe(|gate, _, stamp| gate.allows_panel_work(self) && self.1 == stamp)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn local_repair_epoch() -> Option<LocalRepairEpoch> {
    observe(|gate, _, stamp| {
        gate.local_repair_epoch()
            .map(|epoch| LocalRepairEpoch(epoch.0, stamp))
    })
}

#[cfg(target_os = "macos")]
impl LocalRepairEpoch {
    pub(crate) fn wake_stamp(self) -> Option<i64> {
        self.1
    }

    pub(crate) fn is_current(self) -> bool {
        observe(|gate, _, stamp| gate.allows_local_repair(self) && self.1 == stamp)
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn dispatch_wake_is_current(wake_stamp: Option<i64>) -> bool {
    accepts_dispatch_wake(wake_stamp, native::capabilities(), native::wake_stamp())
}

#[cfg(any(target_os = "macos", test))]
fn accepts_dispatch_wake(
    expected_wake: Option<i64>,
    capabilities: Option<u64>,
    current_wake: Option<i64>,
) -> bool {
    expected_wake == current_wake && capabilities.is_none_or(|caps| caps & FULL_WAKE == FULL_WAKE)
}

#[cfg(target_os = "macos")]
pub(crate) async fn check_recovery_network(
    application: &crate::NativeApplication,
) -> RecoveryReadiness {
    let (current, generation) =
        observe(|gate, readiness, _| (readiness, gate.begin_probe(Instant::now())));
    let Some(generation) = generation else {
        return current;
    };
    if application.probe_wake_control_network().await {
        observe(|gate, readiness, _| {
            if readiness == RecoveryReadiness::WaitingForPanel {
                gate.confirm_network(generation);
            }
        });
    }
    readiness()
}

#[cfg(target_os = "macos")]
mod native {
    use std::ffi::{c_char, c_void};
    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOServiceMatching(name: *const c_char) -> *mut c_void;
        fn IOServiceGetMatchingService(port: u32, matching: *mut c_void) -> u32;
        fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: *const c_void,
            allocator: *const c_void,
            options: u32,
        ) -> *const c_void;
        fn IOObjectRelease(object: u32) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithCString(
            allocator: *const c_void,
            text: *const c_char,
            encoding: u32,
        ) -> *const c_void;
        fn CFNumberGetValue(value: *const c_void, kind: i32, output: *mut c_void) -> u8;
        fn CFNumberGetTypeID() -> usize;
        fn CFGetTypeID(value: *const c_void) -> usize;
        fn CFRelease(value: *const c_void);
    }

    pub(super) fn capabilities() -> Option<u64> {
        // Root-domain capabilities describe full/dark wake, unlike display-idle
        // or user activity. XNU publishes this property as a 64-bit OSNumber.
        unsafe {
            let matching = IOServiceMatching(c"IOPMrootDomain".as_ptr());
            if matching.is_null() {
                return None;
            }
            let service = IOServiceGetMatchingService(0, matching); // consumes matching
            if service == 0 {
                return None;
            }
            let key = CFStringCreateWithCString(
                std::ptr::null(),
                c"System Capabilities".as_ptr(),
                0x08000100,
            );
            if key.is_null() {
                IOObjectRelease(service);
                return None;
            }
            let value = IORegistryEntryCreateCFProperty(service, key, std::ptr::null(), 0);
            CFRelease(key);
            IOObjectRelease(service);
            if value.is_null() {
                return None;
            }
            let mut number: i64 = 0;
            let valid = CFGetTypeID(value) == CFNumberGetTypeID()
                && CFNumberGetValue(value, 4, (&mut number as *mut i64).cast()) != 0;
            CFRelease(value);
            valid.then_some(number as u64)
        }
    }

    pub(super) fn wake_stamp() -> Option<i64> {
        let mut value: libc::timeval = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&value);
        let result = unsafe {
            libc::sysctlbyname(
                c"kern.waketime".as_ptr(),
                (&mut value as *mut libc::timeval).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || size != std::mem::size_of_val(&value) || value.tv_sec <= 0 {
            return None;
        }
        value
            .tv_sec
            .checked_mul(1_000_000)?
            .checked_add(i64::from(value.tv_usec))
    }

    #[test]
    fn reads_real_host_capabilities_without_mutating_power_state() {
        assert!(capabilities().is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_start_only_crosses_common_for_the_same_full_wake() {
        let wake = Some(1_000_100);
        assert!(accepts_dispatch_wake(wake, Some(FULL_WAKE), wake));
        assert!(!accepts_dispatch_wake(wake, Some(0x01), wake));
        assert!(!accepts_dispatch_wake(
            wake,
            Some(FULL_WAKE),
            Some(1_000_200)
        ));
        assert!(!accepts_dispatch_wake(wake, Some(FULL_WAKE), None));
        assert!(!accepts_dispatch_wake(None, Some(FULL_WAKE), wake));
        assert!(accepts_dispatch_wake(None, Some(FULL_WAKE), None));
    }

    #[test]
    fn dark_wake_defers_but_full_wake_can_resume_immediately() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        assert_eq!(
            gate.observe(Some(9), Some(90), 100),
            RecoveryReadiness::Sleeping
        );
        assert_eq!(gate.begin_probe(now), None);

        assert_eq!(
            gate.observe(Some(15), Some(90), 101),
            RecoveryReadiness::WaitingForPanel
        );
        let generation = gate.begin_probe(now).unwrap();
        gate.confirm_network(generation);
        assert_eq!(
            gate.observe(Some(15), Some(90), 101),
            RecoveryReadiness::Ready
        );
    }

    #[test]
    fn missed_sleep_between_polls_still_requires_a_fresh_network_check() {
        let mut gate = RecoveryGate::default();
        assert_eq!(
            gate.observe(Some(15), Some(50), 100),
            RecoveryReadiness::Ready
        );
        assert_eq!(
            gate.observe(Some(15), Some(101), 104),
            RecoveryReadiness::WaitingForPanel
        );
    }

    #[test]
    fn result_from_a_previous_wake_does_not_open_the_gate() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        assert_eq!(
            gate.observe(Some(15), Some(99), 100),
            RecoveryReadiness::WaitingForPanel
        );
        let first = gate.begin_probe(now).unwrap();
        assert_eq!(
            gate.observe(Some(9), Some(99), 101),
            RecoveryReadiness::Sleeping
        );
        gate.confirm_network(first);
        assert_eq!(
            gate.observe(Some(15), Some(99), 102),
            RecoveryReadiness::WaitingForPanel
        );
        let second = gate.begin_probe(now).unwrap();
        gate.confirm_network(first);
        assert_eq!(
            gate.observe(Some(15), Some(99), 102),
            RecoveryReadiness::WaitingForPanel
        );
        gate.confirm_network(second);
        assert_eq!(
            gate.observe(Some(15), Some(99), 102),
            RecoveryReadiness::Ready
        );
    }

    #[test]
    fn full_wake_still_waits_after_fifteen_seconds_without_network() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        gate.observe(Some(9), Some(90), 100);
        assert!(!gate.observe(Some(15), Some(90), 100).allows_panel_work());
        // A failed check leaves readiness pending and limits retries across callers.
        assert!(gate.begin_probe(now).is_some());
        assert_eq!(
            gate.begin_probe(now + RETRY_INTERVAL - Duration::from_millis(1)),
            None
        );
        assert!(gate.begin_probe(now + RETRY_INTERVAL).is_some());
        assert_eq!(
            gate.observe(Some(15), Some(90), 120),
            RecoveryReadiness::WaitingForPanel
        );
    }

    #[test]
    fn unavailable_panel_after_full_wake_defers_panel_work_but_allows_local_repair() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        let dark = gate.observe(Some(9), Some(90), 100);
        assert!(!dark.allows_local_repair());
        assert!(!dark.allows_panel_work());

        let full = gate.observe(Some(15), Some(90), 101);
        assert!(full.allows_local_repair());
        assert!(!full.allows_panel_work());
        let generation = gate.begin_probe(now).unwrap();

        // A transient failure reading the sensor must not clear pending readiness.
        assert!(!gate.observe(None, None, 117).allows_panel_work());
        gate.confirm_network(generation);
        assert!(gate.observe(Some(15), Some(90), 118).allows_panel_work());
    }

    #[test]
    fn work_started_before_sleep_is_stale_after_the_new_wake_is_confirmed() {
        let mut gate = RecoveryGate::default();
        gate.observe(Some(15), Some(50), 100);
        let previous = gate.panel_work_epoch().unwrap();
        gate.observe(Some(9), Some(101), 101);
        assert!(!gate.allows_panel_work(previous));
        gate.observe(Some(15), Some(101), 102);
        let probe = gate.begin_probe(Instant::now()).unwrap();
        gate.confirm_network(probe);
        let current = gate.panel_work_epoch().unwrap();
        assert!(gate.allows_panel_work(current));
        assert!(!gate.allows_panel_work(previous));
    }

    #[test]
    fn local_repair_ignores_observations_from_the_previous_wake() {
        let mut gate = RecoveryGate::default();
        gate.observe(Some(15), Some(50), 100);
        let previous = gate.local_repair_epoch().unwrap();
        gate.observe(Some(9), Some(101), 101);
        assert!(!gate.allows_local_repair(previous));
        assert!(gate.local_repair_epoch().is_none());
        assert_eq!(
            gate.observe(Some(15), Some(101), 102),
            RecoveryReadiness::WaitingForPanel
        );
        let current = gate.local_repair_epoch().unwrap();
        assert!(gate.allows_local_repair(current));
        assert!(!gate.allows_local_repair(previous));
        let probe = gate.begin_probe(Instant::now()).unwrap();
        gate.confirm_network(probe);
        assert!(gate.allows_local_repair(current));
        assert!(!gate.allows_local_repair(previous));
    }

    #[test]
    fn active_system_and_unavailable_sensor_do_not_disable_recovery() {
        let mut gate = RecoveryGate::default();
        // System graphics capability persists when only the display turns off.
        assert_eq!(
            gate.observe(Some(15), Some(50), 100),
            RecoveryReadiness::Ready
        );
        assert_eq!(gate.observe(None, None, 100), RecoveryReadiness::Ready);
    }
}
