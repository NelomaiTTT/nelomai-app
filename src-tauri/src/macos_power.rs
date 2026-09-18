//! Gate automatic recovery on system power, not display/user-idle state.
use std::time::{Duration, Instant};

const WAKE_GRACE: Duration = Duration::from_secs(15);
const FULL_WAKE: u64 = 0x01 | 0x02 | 0x08; // CPU, graphics capability, network.

#[derive(Default)]
struct RecoveryGate {
    was_dark: bool,
    wake_stamp: Option<i64>,
    resume_after: Option<Instant>,
}

impl RecoveryGate {
    fn observe(
        &mut self,
        capabilities: Option<u64>,
        wake: Option<i64>,
        now: Instant,
        unix: i64,
    ) -> Option<&'static str> {
        if capabilities.is_some_and(|value| value & FULL_WAKE != FULL_WAKE) {
            self.was_dark = true;
            self.wake_stamp = wake;
            return Some("sleep_or_dark_wake");
        }
        // A failed sensor must not permanently disable the existing recovery path.
        capabilities?;
        let new_wake = wake.is_some_and(|stamp| {
            self.wake_stamp.is_some_and(|previous| previous != stamp)
                || (self.wake_stamp.is_none() && (0..15).contains(&unix.saturating_sub(stamp)))
        });
        if self.was_dark || new_wake {
            self.resume_after = Some(now + WAKE_GRACE);
        }
        self.was_dark = false;
        if wake.is_some() {
            self.wake_stamp = wake;
        }
        if self.resume_after.is_some_and(|deadline| now < deadline) {
            return Some("wake_grace");
        }
        self.resume_after = None;
        None
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn defer_reason() -> Option<&'static str> {
    static GATE: std::sync::OnceLock<std::sync::Mutex<RecoveryGate>> = std::sync::OnceLock::new();
    let caps = native::capabilities();
    let wake = native::wake_time();
    GATE.get_or_init(Default::default).lock().ok()?.observe(
        caps,
        wake,
        Instant::now(),
        crate::current_unix_time(),
    )
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

    pub(super) fn wake_time() -> Option<i64> {
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
        (result == 0 && size == std::mem::size_of_val(&value) && value.tv_sec > 0)
            .then_some(value.tv_sec)
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
    fn dark_wake_defers_until_full_wake_grace_expires() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        assert_eq!(
            gate.observe(Some(9), Some(90), now, 100),
            Some("sleep_or_dark_wake")
        );
        assert_eq!(
            gate.observe(Some(15), Some(90), now + Duration::from_secs(1), 101),
            Some("wake_grace")
        );
        assert_eq!(
            gate.observe(Some(15), Some(90), now + Duration::from_secs(15), 115),
            Some("wake_grace")
        );
        assert_eq!(
            gate.observe(Some(15), Some(90), now + Duration::from_secs(16), 116),
            None
        );
    }

    #[test]
    fn missed_sleep_between_polls_still_starts_grace() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        assert_eq!(gate.observe(Some(15), Some(50), now, 100), None);
        assert_eq!(
            gate.observe(Some(15), Some(101), now + Duration::from_secs(4), 104),
            Some("wake_grace")
        );
    }

    #[test]
    fn recent_wake_at_startup_and_another_dark_cycle_get_their_own_grace() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        assert_eq!(
            gate.observe(Some(15), Some(99), now, 100),
            Some("wake_grace")
        );
        assert_eq!(
            gate.observe(Some(9), Some(99), now + Duration::from_secs(14), 114),
            Some("sleep_or_dark_wake")
        );
        assert_eq!(
            gate.observe(Some(15), Some(99), now + Duration::from_secs(15), 115),
            Some("wake_grace")
        );
        assert_eq!(
            gate.observe(Some(15), Some(99), now + Duration::from_secs(29), 129),
            Some("wake_grace")
        );
        assert_eq!(
            gate.observe(Some(15), Some(99), now + Duration::from_secs(30), 130),
            None
        );
    }

    #[test]
    fn active_system_and_unavailable_sensor_do_not_disable_recovery() {
        let mut gate = RecoveryGate::default();
        let now = Instant::now();
        // System graphics capability persists when only the display turns off.
        assert_eq!(gate.observe(Some(15), Some(50), now, 100), None);
        assert_eq!(gate.observe(None, None, now, 100), None);
    }
}
