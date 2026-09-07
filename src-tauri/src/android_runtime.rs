//! One-shot admitted Android child endpoint, received before Tauri starts.
use jni::{
    objects::{JObject, JString},
    sys::jint,
    JNIEnv,
};
use nelomai_client_container::host::RuntimeBootstrapV1;
use std::{
    os::fd::{FromRawFd, OwnedFd},
    sync::{Mutex, OnceLock},
};

static BOOTSTRAP: OnceLock<Mutex<Option<(OwnedFd, RuntimeBootstrapV1)>>> = OnceLock::new();

pub fn take_bootstrap() -> std::io::Result<(OwnedFd, RuntimeBootstrapV1)> {
    BOOTSTRAP
        .get()
        .ok_or_else(blocked)?
        .lock()
        .map_err(|_| blocked())?
        .take()
        .ok_or_else(blocked)
}
fn blocked() -> std::io::Error {
    std::io::Error::other("runtime_startup_blocked: Android owner admission is required")
}

fn attach(mut env: JNIEnv, fd: jint, bootstrap: JString) {
    let descriptor = (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) });
    let result = (|| -> Result<(), ()> {
        let descriptor = descriptor.ok_or(())?;
        let value: String = env.get_string(&bootstrap).map_err(|_| ())?.into();
        if value.len() > 65536 {
            return Err(());
        }
        let bootstrap: RuntimeBootstrapV1 = serde_json::from_str(&value).map_err(|_| ())?;
        bootstrap
            .target
            .identity(bootstrap.session_generation)
            .map_err(|_| ())?;
        BOOTSTRAP
            .set(Mutex::new(Some((descriptor, bootstrap))))
            .map_err(|_| ())
    })();
    if result.is_err() {
        let _ = env.throw_new(
            "java/lang/IllegalStateException",
            "runtime_admission_rejected",
        );
    }
}

#[no_mangle]
pub extern "system" fn Java_ru_nelomai_client_RuntimeEntrypoint_attach(
    env: JNIEnv,
    _: JObject,
    fd: jint,
    bootstrap: JString,
) {
    attach(env, fd, bootstrap)
}

// Stable build generation emits only its namespaced export, never both slots.
#[no_mangle]
pub extern "C" fn nelomai_runtime_v1() -> u32 {
    1
}
