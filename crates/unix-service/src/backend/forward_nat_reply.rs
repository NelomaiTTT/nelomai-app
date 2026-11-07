//! Only a freshly owned VPN link may forward reverse-NAT replies to a VM.
use std::io;

trait ReplyPathIo {
    fn index(&mut self) -> io::Result<u32>;
    fn read(&mut self) -> io::Result<u8>;
    fn enable(&mut self) -> io::Result<()>;
}

fn owned_name(name: &str) -> bool {
    matches!(
        name,
        "nlm-wg0" | "nlm-awg0" | "nlm-wga" | "nlm-wgb" | "nlm-awga" | "nlm-awgb"
    )
}
fn allow_owned_replies(name: &str, index: u32, control: &mut impl ReplyPathIo) -> io::Result<()> {
    if !owned_name(name) || index == 0 || index > i32::MAX as u32 || control.index()? != index {
        return Err(unconfirmed());
    }
    let current = control.read()?;
    if current > 1 || control.index()? != index {
        return Err(unconfirmed());
    }
    if current == 0 {
        control.enable()?;
    }
    if control.read()? != 1 || control.index()? != index {
        return Err(unconfirmed());
    }
    Ok(())
}
fn unconfirmed() -> io::Error {
    io::Error::other("owned_vpn_reply_forwarding_unconfirmed")
}

/// The caller just created/configured this interface and retains its original
/// native index. No physical, VM-owned, global/default, or RPF setting is opened.
/// Interface deletion removes this setting with the interface itself.
#[cfg(target_os = "linux")]
pub(super) fn enable_owned_reply_path(name: &str, index: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if !owned_name(name) || index == 0 || index > i32::MAX as u32 {
        return Err(unconfirmed());
    }
    let name_c = std::ffi::CString::new(name).map_err(|_| unconfirmed())?;
    if unsafe { libc::if_nametoindex(name_c.as_ptr()) } != index {
        return Err(unconfirmed());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("/proc/sys/net/ipv4/conf/{name}/forwarding"))?;
    allow_owned_replies(name, index, &mut NativeReplyPath { name: name_c, file })
}
#[cfg(target_os = "linux")]
struct NativeReplyPath {
    name: std::ffi::CString,
    file: std::fs::File,
}
#[cfg(target_os = "linux")]
impl ReplyPathIo for NativeReplyPath {
    fn index(&mut self) -> io::Result<u32> {
        Ok(unsafe { libc::if_nametoindex(self.name.as_ptr()) })
    }
    fn read(&mut self) -> io::Result<u8> {
        use std::io::{Read, Seek};
        self.file.rewind()?;
        let mut text = String::new();
        (&mut self.file).take(8).read_to_string(&mut text)?;
        text.trim().parse().map_err(|_| unconfirmed())
    }
    fn enable(&mut self) -> io::Result<()> {
        use std::io::{Seek, Write};
        self.file.rewind()?;
        self.file.write_all(b"1\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Fake {
        indexes: VecDeque<u32>,
        value: u8,
        writes: Vec<u8>,
        ignore_write: bool,
        reads: usize,
    }
    impl Fake {
        fn new(value: u8) -> Self {
            Self {
                indexes: VecDeque::new(),
                value,
                writes: vec![],
                ignore_write: false,
                reads: 0,
            }
        }
    }
    impl ReplyPathIo for Fake {
        fn index(&mut self) -> io::Result<u32> {
            self.reads += 1;
            Ok(self.indexes.pop_front().unwrap_or(3))
        }
        fn read(&mut self) -> io::Result<u8> {
            self.reads += 1;
            Ok(self.value)
        }
        fn enable(&mut self) -> io::Result<()> {
            self.writes.push(1);
            if !self.ignore_write {
                self.value = 1;
            }
            Ok(())
        }
    }

    #[test]
    fn every_owned_mode_enables_only_its_reply_path() {
        for name in [
            "nlm-wg0", "nlm-awg0", "nlm-wga", "nlm-wgb", "nlm-awga", "nlm-awgb",
        ] {
            let mut control = Fake::new(0);
            allow_owned_replies(name, 3, &mut control).unwrap();
            assert_eq!(control.value, 1);
            assert_eq!(control.writes, [1]);
        }
    }
    #[test]
    fn already_enabled_owned_link_is_not_rewritten() {
        let mut control = Fake::new(1);
        allow_owned_replies("nlm-awga", 3, &mut control).unwrap();
        assert!(control.writes.is_empty());
    }
    #[test]
    fn foreign_global_physical_and_virtual_names_never_reach_io() {
        for name in [
            "all",
            "default",
            "eth0",
            "veth0",
            "virbr0",
            "wg0",
            "nlm-awga/../all",
        ] {
            let mut control = Fake::new(0);
            assert!(allow_owned_replies(name, 3, &mut control).is_err());
            assert_eq!(control.reads, 0);
            assert!(control.writes.is_empty());
        }
    }
    #[test]
    fn changed_identity_before_write_preserves_replacement() {
        for indexes in [vec![9], vec![3, 9]] {
            let mut control = Fake::new(0);
            control.indexes = indexes.into();
            assert!(allow_owned_replies("nlm-awga", 3, &mut control).is_err());
            assert!(control.writes.is_empty());
        }
    }
    #[test]
    fn ignored_write_or_replacement_after_write_is_not_acknowledged() {
        let mut control = Fake::new(0);
        control.ignore_write = true;
        assert!(allow_owned_replies("nlm-awga", 3, &mut control).is_err());
        assert_eq!(control.writes, [1]);
        let mut control = Fake::new(0);
        control.indexes = vec![3, 3, 9].into();
        assert!(allow_owned_replies("nlm-awga", 3, &mut control).is_err());
    }
    #[test]
    fn invalid_index_or_sysctl_value_never_gets_written() {
        for index in [0, u32::MAX] {
            let mut control = Fake::new(0);
            assert!(allow_owned_replies("nlm-awga", index, &mut control).is_err());
            assert!(control.writes.is_empty());
        }
        let mut control = Fake::new(2);
        assert!(allow_owned_replies("nlm-awga", 3, &mut control).is_err());
        assert!(control.writes.is_empty());
    }
}
