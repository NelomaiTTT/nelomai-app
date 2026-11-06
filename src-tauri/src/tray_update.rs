use tauri::image::Image;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IconState {
    pub dark: bool,
    pub update: bool,
}
impl IconState {
    pub fn image(self) -> Image<'static> {
        let bytes: &'static [u8] = match (self.dark, self.update) {
            (false, false) => include_bytes!("../icons/tray-light.rgba"),
            (true, false) => include_bytes!("../icons/tray-dark.rgba"),
            (false, true) => include_bytes!("../icons/tray-light-update.rgba"),
            (true, true) => include_bytes!("../icons/tray-dark-update.rgba"),
        };
        Image::new(bytes, 64, 64)
    }
    pub fn template(self) -> bool {
        cfg!(target_os = "macos") && !self.update
    }
}
#[cfg(target_os = "macos")]
pub(crate) fn system_dark() -> bool {
    objc2_foundation::NSUserDefaults::standardUserDefaults()
        .stringForKey(objc2_foundation::ns_string!("AppleInterfaceStyle"))
        .is_some_and(|s| s.to_string() == "Dark")
}
#[cfg(target_os = "linux")]
pub(crate) fn system_dark() -> bool {
    true
}
#[cfg(windows)]
pub(crate) use windows_theme::ThemeWatcher;
#[cfg(windows)]
mod windows_theme {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
        System::{
            Registry::*,
            Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
        },
    };
    // Handles are owned here and accessed only under TrayMenuState's Mutex.
    pub(crate) struct ThemeWatcher {
        key: usize,
        event: usize,
        dark: bool,
        armed: bool,
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    impl ThemeWatcher {
        pub fn new() -> Self {
            let mut key = std::ptr::null_mut();
            let path = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
            if unsafe {
                RegOpenKeyExW(
                    HKEY_CURRENT_USER,
                    path.as_ptr(),
                    0,
                    KEY_QUERY_VALUE | KEY_NOTIFY,
                    &mut key,
                )
            } != 0
            {
                return Self {
                    key: 0,
                    event: 0,
                    dark: true,
                    armed: false,
                };
            }
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            let mut state = Self {
                key: key as usize,
                event: event as usize,
                dark: true,
                armed: false,
            };
            state.read();
            state.arm();
            state
        }
        fn read(&mut self) {
            let mut value = 0_u32;
            let mut len = 4_u32;
            let name = wide("SystemUsesLightTheme");
            if unsafe {
                RegGetValueW(
                    self.key as HKEY,
                    std::ptr::null(),
                    name.as_ptr(),
                    RRF_RT_REG_DWORD,
                    std::ptr::null_mut(),
                    (&mut value as *mut u32).cast(),
                    &mut len,
                )
            } == 0
            {
                self.dark = value == 0;
            }
        }
        fn arm(&mut self) {
            self.armed = self.event != 0
                && unsafe {
                    RegNotifyChangeKeyValue(
                        self.key as HKEY,
                        0,
                        REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                        self.event as HANDLE,
                        1,
                    )
                } == 0;
        }
        pub fn dark(&mut self) -> bool {
            if self.key == 0 {
                return self.dark;
            }
            if !self.armed
                || unsafe { WaitForSingleObject(self.event as HANDLE, 0) } == WAIT_OBJECT_0
            {
                if self.event != 0 {
                    unsafe { ResetEvent(self.event as HANDLE) };
                }
                // Arm before read so a concurrent registry change cannot be lost.
                self.arm();
                self.read();
            }
            self.dark
        }
    }
    impl Drop for ThemeWatcher {
        fn drop(&mut self) {
            unsafe {
                if self.key != 0 {
                    RegCloseKey(self.key as HKEY);
                }
                if self.event != 0 {
                    CloseHandle(self.event as HANDLE);
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filled_glyph_and_red_badge_remain_distinct_in_both_themes() {
        for dark in [false, true] {
            let normal = IconState {
                dark,
                update: false,
            }
            .image();
            let badge = IconState { dark, update: true }.image();
            assert_eq!(normal.rgba().len(), 64 * 64 * 4);
            let center = &normal.rgba()[(32 * 64 + 32) * 4..][..4];
            assert_eq!(center[3], 255, "Windows glyph center is hollow");
            assert_eq!(center[0], if dark { 255 } else { 17 });
            assert_eq!(&normal.rgba()[..4], &[0, 0, 0, 0]);
            assert!(!normal
                .rgba()
                .chunks_exact(4)
                .any(|p| p[0] > 180 && p[1] < 80 && p[2] < 100 && p[3] > 200));
            assert!(badge
                .rgba()
                .chunks_exact(4)
                .any(|p| p[0] > 180 && p[1] < 80 && p[2] < 100 && p[3] > 200));
            assert!(!IconState { dark, update: true }.template());
        }
    }
}
