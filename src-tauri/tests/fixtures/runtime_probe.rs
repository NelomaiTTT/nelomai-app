use std::{
    fs::File,
    io::{Read, Write},
    os::fd::FromRawFd,
};
unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}
fn main() {
    if std::env::args().nth(1).as_deref() != Some("--private-runtime-v1") {
        // This ordinary process performs a real descriptor inventory, not just
        // an argv check. No launcher socket may survive its exec.
        for fd in 3..256 {
            if unsafe { fcntl(fd, 1) } >= 0 {
                eprintln!("unexpected inherited descriptor: {fd}");
                #[cfg(target_os = "linux")]
                eprintln!("descriptor target: {:?}", std::fs::read_link(format!("/proc/self/fd/{fd}")));
                std::process::exit(44);
            }
        }
        std::process::exit(42);
    }
    if unsafe { fcntl(3, 1) } < 0 || unsafe { fcntl(4, 1) } < 0 {
        std::process::exit(43);
    }
    let mut auth = unsafe { File::from_raw_fd(3) };
    let mut native = unsafe { File::from_raw_fd(4) };
    auth.write_all(b"NELORUNTIME1").unwrap();
    let extra_args = (std::env::args().count() != 2) as u8;
    let unexpected_env = std::env::vars().any(|(name, _)| {
        ![
            "HOME",
            "USER",
            "LOGNAME",
            "PATH",
            "TMPDIR",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "LANG",
            "LC_ALL",
        ]
        .contains(&name.as_str())
    }) as u8;
    native.write_all(&[extra_args, unexpected_env]).unwrap();
    let _ = auth.read(&mut [0; 1]);
}
