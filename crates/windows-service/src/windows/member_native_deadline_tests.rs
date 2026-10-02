use super::*;

// Pure Win32 result decoding only; never start a watchdog, capture a process or
// invoke native termination in these tests. Actual native files compile on MSVC.
#[test]
fn unknown_or_failed_wait_is_not_a_start_or_completion_ack() {
    assert_eq!(decode_wait(WAIT_OBJECT_0), Ok(policy::Wait::Signaled));
    assert_eq!(decode_wait(WAIT_TIMEOUT), Ok(policy::Wait::Timeout));
    for code in [128, u32::MAX, 1] {
        assert_eq!(decode_wait(code), Err(policy::Error::Worker));
    }
}
#[test]
fn only_os_handles_and_bookkeeping_are_sendable_to_the_worker() {
    fn handles<T: Send + Sync>() {}
    handles::<CurrentKernel>();
    handles::<OwnedHandle>();
    // NativeDeadline/ReadPin deliberately keep real !Send/!Sync RuntimeRead.
}
