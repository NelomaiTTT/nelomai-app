//! Read installed download metadata without accepting a translocated broker.
use std::{io, path::Path};

pub(crate) fn requires_installation_repair(bundle: &Path) -> io::Result<bool> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(bundle.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid application path"))?;
    // Quarantine is a property of the installed bundle, never evidence that a
    // translocated caller is trusted. Keep the exact executable-path guards.
    let size = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"com.apple.quarantine".as_ptr(),
            std::ptr::null_mut(),
            0,
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if size >= 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOATTR) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Bundle(PathBuf);
    impl Bundle {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir()
                .join(format!(
                    "nelomai-install-metadata-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ))
                .join("Nelomai.app");
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn quarantine(&self, value: &str) {
            assert!(Command::new("/usr/bin/xattr")
                .args(["-w", "com.apple.quarantine", value])
                .arg(&self.0)
                .status()
                .unwrap()
                .success());
        }
    }
    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    #[test]
    fn downloaded_protected_bundle_requires_repair_before_launch() {
        let bundle = Bundle::new();
        bundle.quarantine("00c1;6ae7b1f3;Telegram;");
        assert!(requires_installation_repair(&bundle.0).unwrap());
    }

    #[test]
    fn empty_quarantine_attribute_still_requires_repair() {
        let bundle = Bundle::new();
        bundle.quarantine("");
        assert!(requires_installation_repair(&bundle.0).unwrap());
    }

    #[test]
    fn normalized_installation_does_not_require_another_authorization() {
        let bundle = Bundle::new();
        assert!(!requires_installation_repair(&bundle.0).unwrap());
    }

    #[test]
    fn metadata_read_failure_is_not_treated_as_a_ready_installation() {
        let bundle = Bundle::new();
        std::fs::remove_dir(&bundle.0).unwrap();
        assert_eq!(
            requires_installation_repair(&bundle.0).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
