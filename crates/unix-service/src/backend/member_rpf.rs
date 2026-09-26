//! Per-member reply path: strict RPF otherwise rejects a standby probe reply
//! when the best ordinary route to its source still points at the active slot.

use std::io;

trait MemberFilterIo {
    fn index(&mut self) -> io::Result<u32>;
    fn read(&mut self) -> io::Result<u8>;
    fn write(&mut self, mode: u8) -> io::Result<()>;
}
fn allow_member_replies(index: u32, control: &mut impl MemberFilterIo) -> io::Result<()> {
    if index == 0 || control.index()? != index {
        return Err(unconfirmed());
    }
    let current = control.read()?;
    if current > 2 || control.index()? != index {
        return Err(unconfirmed());
    }
    // Linux evaluates max(conf/all, conf/interface). Setting only this owned
    // interface to loose(2) works even when conf/all is strict(1). Never write
    // global/default or physical-interface settings. Removing the member also
    // removes this per-interface setting, so no machine-wide restore is needed.
    if current != 2 {
        control.write(2)?;
    }
    if control.read()? != 2 || control.index()? != index {
        return Err(unconfirmed());
    }
    Ok(())
}
fn unconfirmed() -> io::Error {
    io::Error::other("member_reply_path_unconfirmed")
}

#[cfg(target_os = "linux")]
pub(super) fn enable_member_reply_path(name: &str, index: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if !matches!(name, "nlm-wga" | "nlm-wgb" | "nlm-awga" | "nlm-awgb") {
        return Err(unconfirmed());
    }
    let name_c = std::ffi::CString::new(name).map_err(|_| unconfirmed())?;
    if index == 0 || unsafe { libc::if_nametoindex(name_c.as_ptr()) } != index {
        return Err(unconfirmed());
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))?;
    allow_member_replies(index, &mut NativeFilter { name: name_c, file })
}
#[cfg(target_os = "linux")]
struct NativeFilter {
    name: std::ffi::CString,
    file: std::fs::File,
}
#[cfg(target_os = "linux")]
impl MemberFilterIo for NativeFilter {
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
    fn write(&mut self, mode: u8) -> io::Result<()> {
        use std::io::{Seek, Write};
        if mode != 2 {
            return Err(unconfirmed());
        }
        self.file.rewind()?;
        self.file.write_all(b"2\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Filter {
        indexes: VecDeque<u32>,
        mode: u8,
        writes: Vec<u8>,
        ignore_write: bool,
    }
    impl MemberFilterIo for Filter {
        fn index(&mut self) -> io::Result<u32> {
            Ok(self.indexes.pop_front().unwrap_or(20))
        }
        fn read(&mut self) -> io::Result<u8> {
            Ok(self.mode)
        }
        fn write(&mut self, mode: u8) -> io::Result<()> {
            self.writes.push(mode);
            if !self.ignore_write {
                self.mode = mode;
            }
            Ok(())
        }
    }
    fn filter(mode: u8) -> Filter {
        Filter {
            indexes: VecDeque::new(),
            mode,
            writes: vec![],
            ignore_write: false,
        }
    }
    #[test]
    fn strict_member_rpf_becomes_loose_with_readback() {
        let mut io = filter(1);
        allow_member_replies(20, &mut io).unwrap();
        assert_eq!(io.mode, 2);
        assert_eq!(io.writes, [2]);
    }
    #[test]
    fn local_zero_also_needs_loose_because_all_can_be_strict() {
        let mut io = filter(0);
        allow_member_replies(20, &mut io).unwrap();
        assert_eq!(io.mode, 2);
        assert_eq!(io.writes, [2]);
    }
    #[test]
    fn already_loose_is_not_rewritten() {
        let mut io = filter(2);
        allow_member_replies(20, &mut io).unwrap();
        assert!(io.writes.is_empty());
    }
    #[test]
    fn changed_identity_before_write_leaves_replacement_untouched() {
        let mut io = filter(1);
        io.indexes = VecDeque::from([20, 99]);
        assert!(allow_member_replies(20, &mut io).is_err());
        assert!(io.writes.is_empty());
        assert_eq!(io.mode, 1);
    }
    #[test]
    fn unconfirmed_write_and_identity_change_are_not_success() {
        let mut io = filter(1);
        io.ignore_write = true;
        assert!(allow_member_replies(20, &mut io).is_err());
        let mut io = filter(1);
        io.indexes = VecDeque::from([20, 20, 99]);
        assert!(allow_member_replies(20, &mut io).is_err());
    }
    #[test]
    fn malformed_filter_and_zero_index_never_write() {
        for (mode, index) in [(3, 20), (1, 0)] {
            let mut io = filter(mode);
            assert!(allow_member_replies(index, &mut io).is_err());
            assert!(io.writes.is_empty());
        }
    }
}
