//! One-shot admitted Android child endpoint, received before Tauri starts.
use jni::{
    objects::{JClass, JObject, JString, JValue},
    sys::jint,
    JNIEnv, JavaVM,
};
use nelomai_client_container::host::RuntimeBootstrapV1;
use std::{
    os::fd::{FromRawFd, OwnedFd},
    sync::{Mutex, OnceLock},
};

static BOOTSTRAP: OnceLock<Mutex<Option<(OwnedFd, RuntimeBootstrapV1)>>> = OnceLock::new();

/// Read through the container class loader and its collector's rotation lock.
/// Diagnostics are optional: JNI failures must not prevent the existing report.
pub fn logcat_snapshot() -> Option<String> {
    let context = ndk_context::android_context();
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }.ok()?;
    let mut env = vm.attach_current_thread().ok()?;
    let result = env.with_local_frame(16, |env| -> jni::errors::Result<String> {
        let context = unsafe { JObject::from_raw(context.context().cast()) };
        let loader = env
            .call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?
            .l()?;
        let name = env.new_string("ru.nelomai.runtime.v1.PersistentLogcat")?;
        let class = env
            .call_method(
                loader,
                "loadClass",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                &[JValue::Object(&name)],
            )?
            .l()?;
        let files = env
            .call_method(&context, "getNoBackupFilesDir", "()Ljava/io/File;", &[])?
            .l()?;
        let path = env
            .call_method(files, "getAbsolutePath", "()Ljava/lang/String;", &[])?
            .l()?;
        let snapshot = env
            .call_static_method(
                JClass::from(class),
                "snapshot",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&path)],
            )?
            .l()?;
        let text: String = env.get_string(&JString::from(snapshot))?.into();
        Ok(text)
    });
    if result.is_err() {
        let _ = env.exception_clear();
    }
    result
        .ok()
        .filter(|text| !text.is_empty() && text.len() <= 2 * 1024 * 1024)
}

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
