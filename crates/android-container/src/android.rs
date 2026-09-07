use base64::Engine;
use jni::{
    objects::{GlobalRef, JObject, JString, JValue},
    sys::{jint, jlong, jstring},
    JNIEnv, JavaVM,
};
use nelomai_client_api::ClientApi;
use nelomai_client_container::{
    host::{CommonHost, HostNativePorts, RuntimeAttachRequest},
    ipc::{BackgroundAction, PrivateBackgroundDispatcher},
    BrokerError, LocalAuthStop, NativeAuthFailure, NativeAuthRequest, RuntimeClientProfile,
    RuntimeForceStop,
};
use nelomai_client_storage::SystemRecordFactory;
use std::{
    collections::HashMap,
    os::fd::{FromRawFd, OwnedFd},
    path::PathBuf,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex, OnceLock,
    },
};

struct Host {
    owner: CommonHost,
    runtime: tokio::runtime::Runtime,
}
static HOSTS: OnceLock<Mutex<HashMap<i64, Arc<Host>>>> = OnceLock::new();
static NEXT_HOST: AtomicI64 = AtomicI64::new(1);
static CONTEXT: OnceLock<GlobalRef> = OnceLock::new();

fn hosts() -> &'static Mutex<HashMap<i64, Arc<Host>>> {
    HOSTS.get_or_init(Mutex::default)
}
fn host(id: i64) -> Result<Arc<Host>, ()> {
    hosts().lock().map_err(|_| ())?.get(&id).cloned().ok_or(())
}
fn string(env: &mut JNIEnv, value: JString) -> Result<String, ()> {
    let value: String = env.get_string(&value).map_err(|_| ())?.into();
    if value.len() > 65536 {
        return Err(());
    }
    Ok(value)
}
fn failure(env: &mut JNIEnv) {
    let _ = env.exception_clear();
    let _ = env.throw_new(
        "java/lang/IllegalStateException",
        "runtime_owner_unavailable",
    );
}

struct Callbacks {
    vm: Arc<JavaVM>,
    object: GlobalRef,
}
enum Call {
    Revoke(u64),
    Stop(bool),
    Background(String, String),
    Install(String, String, String),
    Storage(String, String, bool, bool),
    StorageAck,
    PushCleanup,
}
impl Callbacks {
    fn call(&self, call: Call) -> Result<Option<String>, ()> {
        let mut env = self.vm.attach_current_thread().map_err(|_| ())?;
        let result = match call {
            Call::PushCleanup => env
                .call_method(self.object.as_obj(), "cleanupPush", "()Z", &[])
                .and_then(|v| v.z())
                .map(|ok| ok.then_some(None)),
            Call::Storage(slot, version, legacy, complete) => {
                let slot = env.new_string(slot).map_err(|_| ())?;
                let version = env.new_string(version).map_err(|_| ())?;
                env.call_method(
                    self.object.as_obj(),
                    "prepareNativeStorage",
                    "(Ljava/lang/String;Ljava/lang/String;ZZ)Z",
                    &[
                        JValue::Object(&slot),
                        JValue::Object(&version),
                        JValue::Bool(legacy.into()),
                        JValue::Bool(complete.into()),
                    ],
                )
                .and_then(|v| v.z())
                .map(|ok| ok.then_some(None))
            }
            Call::StorageAck => env
                .call_method(self.object.as_obj(), "acknowledgeNativeStorage", "()Z", &[])
                .and_then(|v| v.z())
                .map(|ok| ok.then_some(None)),
            Call::Install(path, version, signer) => {
                let path = env.new_string(path).map_err(|_| ())?;
                let version = env.new_string(version).map_err(|_| ())?;
                let signer = env.new_string(signer).map_err(|_| ())?;
                env.call_method(
                    self.object.as_obj(),
                    "installApk",
                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z",
                    &[
                        JValue::Object(&path),
                        JValue::Object(&version),
                        JValue::Object(&signer),
                    ],
                )
                .and_then(|v| v.z())
                .map(|ok| ok.then_some(None))
            }
            Call::Revoke(epoch) => env
                .call_method(
                    self.object.as_obj(),
                    "prepareRevocation",
                    "(J)Z",
                    &[JValue::Long(epoch.try_into().map_err(|_| ())?)],
                )
                .and_then(|v| v.z())
                .map(|ok| ok.then_some(None)),
            Call::Stop(force) => env
                .call_method(
                    self.object.as_obj(),
                    "stopVpn",
                    "(Z)Z",
                    &[JValue::Bool(force.into())],
                )
                .and_then(|v| v.z())
                .map(|ok| ok.then_some(None)),
            Call::Background(action, request) => {
                let action = env.new_string(action).map_err(|_| ())?;
                let request = env.new_string(request).map_err(|_| ())?;
                let reply = env
                    .call_method(
                        self.object.as_obj(),
                        "background",
                        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                        &[JValue::Object(&action), JValue::Object(&request)],
                    )
                    .and_then(|v| v.l());
                match reply {
                    Ok(value) => string(&mut env, JString::from(value))
                        .map(|v| Some(Some(v)))
                        .map_err(|_| jni::errors::Error::NullPtr("native response")),
                    Err(error) => Err(error),
                }
            }
        };
        if result.is_err() {
            let _ = env.exception_clear();
        }
        result.map_err(|_| ())?.ok_or(())
    }
}
#[derive(Clone)]
struct Native(Arc<Callbacks>);
impl nelomai_client_container::host::NativeRuntimeStorage for Native {
    fn prepare(
        &self,
        slot: nelomai_contracts::RuntimeSlot,
        version: &str,
        legacy: bool,
        complete: bool,
    ) -> Result<(), BrokerError> {
        let slot = match slot {
            nelomai_contracts::RuntimeSlot::Latest => "latest",
            nelomai_contracts::RuntimeSlot::Stable => "stable",
        };
        self.0
            .call(Call::Storage(slot.into(), version.into(), legacy, complete))
            .map(|_| ())
            .map_err(|_| BrokerError::RecoveryRequired)
    }
    fn acknowledge(&self) -> Result<(), BrokerError> {
        self.0
            .call(Call::StorageAck)
            .map(|_| ())
            .map_err(|_| BrokerError::RecoveryRequired)
    }
}
#[async_trait::async_trait]
impl nelomai_client_updater::AndroidApkInstaller for Native {
    async fn install_apk(
        &self,
        path: &std::path::Path,
        version: &str,
        signer: &str,
    ) -> Result<bool, nelomai_client_updater::UpdateBackendError> {
        self.call(Call::Install(
            path.to_string_lossy().into_owned(),
            version.into(),
            signer.into(),
        ))
        .await
        .map(|_| true)
        .map_err(|_| nelomai_client_updater::UpdateBackendError::new("apk_installer_unavailable"))
    }
}
impl Native {
    async fn call(&self, call: Call) -> Result<Option<String>, BrokerError> {
        let callback = self.0.clone();
        tokio::task::spawn_blocking(move || callback.call(call))
            .await
            .map_err(|_| BrokerError::RecoveryRequired)?
            .map_err(|_| BrokerError::RecoveryRequired)
    }
}
#[async_trait::async_trait]
impl LocalAuthStop for Native {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        self.call(Call::Stop(false)).await.map(|_| ())
    }
    async fn prepare_revocation(&self, epoch: u64) -> Result<(), BrokerError> {
        self.call(Call::Revoke(epoch)).await.map(|_| ())
    }
}
#[async_trait::async_trait]
impl RuntimeForceStop for Native {
    async fn force_stop(&self, _: &str) -> Result<(), BrokerError> {
        self.call(Call::Stop(true)).await.map(|_| ())
    }
}
#[async_trait::async_trait]
impl PrivateBackgroundDispatcher for Native {
    async fn cleanup_push(&self) -> Result<(), BrokerError> {
        self.call(Call::PushCleanup).await.map(|_| ())
    }
    async fn prepare_revocation(&self, epoch: u64) -> Result<(), BrokerError> {
        self.call(Call::Revoke(epoch)).await.map(|_| ())
    }
    async fn dispatch(
        &self,
        request: NativeAuthRequest,
        action: BackgroundAction,
    ) -> Result<Option<nelomai_client_api::TokenResponse>, NativeAuthFailure> {
        let operation = request
            .operation_json()
            .map_err(|_| NativeAuthFailure::NotIssued)?;
        let capability = if matches!(action, BackgroundAction::Provision) {
            // Owner-owned authenticated observation; the child cannot supply a
            // stale capability or another device's bootstrap to the native owner.
            let api = ClientApi::new("https://nelomai.ru")
                .and_then(|api| api.with_access_snapshot(&request.access))
                .map_err(|_| NativeAuthFailure::NotIssued)?;
            let bootstrap = api
                .bootstrap(request.access.access_token())
                .await
                .map_err(|_| NativeAuthFailure::NotIssued)?;
            if Some(bootstrap.device.id.as_str()) != request.ticket.device_id.as_deref() {
                return Err(NativeAuthFailure::NotIssued);
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| NativeAuthFailure::NotIssued)?
                .as_secs() as i64;
            let value = bootstrap.capabilities.as_ref();
            let enabled = value.is_some_and(|v| v.is_recovery_enabled_at(now));
            let revision = value.filter(|v| v.revision > 0).map_or(0, |v| v.revision);
            let expiry = if enabled {
                value.and_then(|v| v.expires_at_unix()).unwrap_or(1)
            } else {
                1
            };
            let expires_at = if enabled {
                value
                    .map(|v| v.expires_at.as_str())
                    .unwrap_or("1970-01-01T00:00:01Z")
            } else {
                "1970-01-01T00:00:01Z"
            };
            serde_json::json!({"revision":revision,"enabled":enabled,"expires_at_unix":expiry,"expires_at":expires_at})
        } else {
            serde_json::Value::Null
        };
        let action = match action {
            BackgroundAction::Provision => "provision",
            BackgroundAction::Recover => "recover",
            BackgroundAction::Status => "status",
        };
        let payload = serde_json::json!({"owner_operation":operation, "install_secret":request.install_secret,
            "access_token":request.access.access_token(), "device_id":request.ticket.device_id,
            "identity":request.access.identity(), "expires_at_unix_ms":request.expires_at_unix_ms,"capability":capability}).to_string();
        let value = self
            .call(Call::Background(action.into(), payload))
            .await
            .map_err(|_| NativeAuthFailure::OutcomeUnknown)?;
        match value {
            Some(value) => {
                serde_json::from_str(&value).map_err(|_| NativeAuthFailure::OutcomeUnknown)
            }
            None => Ok(None),
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ru_nelomai_client_RuntimeNativeHost_nativeOpen(
    mut env: JNIEnv,
    _: JObject,
    context: JObject,
    data: JString,
    resources: JString,
    callbacks: JObject,
) -> jlong {
    let result = (|| -> Result<i64, ()> {
        let data = PathBuf::from(string(&mut env, data)?);
        let resources = PathBuf::from(string(&mut env, resources)?);
        let context = env.new_global_ref(context).map_err(|_| ())?;
        let vm = Arc::new(env.get_java_vm().map_err(|_| ())?);
        let native = Arc::new(Native(Arc::new(Callbacks {
            vm: vm.clone(),
            object: env.new_global_ref(callbacks).map_err(|_| ())?,
        })));
        let cache = env
            .call_method(context.as_obj(), "getCacheDir", "()Ljava/io/File;", &[])
            .and_then(|v| v.l())
            .map_err(|_| ())?;
        let cache = env
            .call_method(cache, "getAbsolutePath", "()Ljava/lang/String;", &[])
            .and_then(|v| v.l())
            .map_err(|_| ())?;
        let cache = PathBuf::from(string(&mut env, JString::from(cache))?).join("updates");
        let updater = Arc::new(
            nelomai_client_updater::AndroidUpdateBackend::new(
                cache,
                env!("CARGO_PKG_VERSION").into(),
                native.clone(),
            )
            .map_err(|_| ())?,
        );
        let key = option_env!("NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64")
            .map(|v| base64::engine::general_purpose::STANDARD.decode(v))
            .transpose()
            .map_err(|_| ())?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .map_err(|_| ())?;
        let owner = runtime.block_on(async {
            CommonHost::open(
                &data,
                &resources,
                key.as_deref(),
                "android",
                "aarch64",
                || {
                    CONTEXT.get_or_init(|| {
                        // Verified host factory is the first permitted Keystore init.
                        unsafe {
                            ndk_context::initialize_android_context(
                                vm.get_java_vm_pointer() as _,
                                context.as_obj().as_raw() as _,
                            );
                        }
                        context
                    });
                    SystemRecordFactory::new("primary", None)
                },
                ClientApi::new("https://nelomai.ru").map_err(|_| ())?,
                RuntimeClientProfile {
                    platform: nelomai_contracts::Platform::Android,
                    platform_version: None,
                    architecture: "aarch64".into(),
                },
                HostNativePorts {
                    stop: native.clone(),
                    force: native.clone(),
                    background: native.clone(),
                    updater: Some(updater),
                    storage: Some(native),
                },
            )
            .map_err(|_| ())
        })?;
        let id = NEXT_HOST.fetch_add(1, Ordering::Relaxed);
        if id <= 0 {
            return Err(());
        }
        hosts()
            .lock()
            .map_err(|_| ())?
            .insert(id, Arc::new(Host { owner, runtime }));
        Ok(id)
    })();
    match result {
        Ok(id) => id,
        Err(_) => {
            failure(&mut env);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ru_nelomai_client_RuntimeNativeHost_nativeSelection(
    mut env: JNIEnv,
    _: JObject,
    id: jlong,
) -> jstring {
    let result = (|| -> Result<_, ()> {
        let host = host(id)?;
        let selection = host
            .runtime
            .block_on(host.owner.selection())
            .map_err(|_| ())?;
        let json = serde_json::to_string(&selection).map_err(|_| ())?;
        env.new_string(json).map(|s| s.into_raw()).map_err(|_| ())
    })();
    match result {
        Ok(value) => value,
        Err(_) => {
            failure(&mut env);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ru_nelomai_client_RuntimeNativeHost_nativeAttach(
    mut env: JNIEnv,
    _: JObject,
    id: jlong,
    fd: jint,
    pid: jint,
    uid: jint,
    request: JString,
) -> jstring {
    // Own immediately, including every rejected identity or serialization path.
    let descriptor = (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) });
    let result = (|| -> Result<_, ()> {
        let descriptor = descriptor.ok_or(())?;
        let request: RuntimeAttachRequest =
            serde_json::from_str(&string(&mut env, request)?).map_err(|_| ())?;
        let host = host(id)?;
        let stream = std::os::unix::net::UnixStream::from(descriptor);
        stream.set_nonblocking(true).map_err(|_| ())?;
        let bootstrap = host.runtime.block_on(async {
            let stream = tokio::net::UnixStream::from_std(stream).map_err(|_| ())?;
            host.owner
                .attach_android(
                    stream,
                    pid.try_into().map_err(|_| ())?,
                    uid.try_into().map_err(|_| ())?,
                    unsafe { libc::getuid() },
                    &request,
                )
                .await
                .map_err(|_| ())
        })?;
        env.new_string(serde_json::to_string(&bootstrap).map_err(|_| ())?)
            .map(|s| s.into_raw())
            .map_err(|_| ())
    })();
    match result {
        Ok(value) => value,
        Err(_) => {
            failure(&mut env);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_ru_nelomai_client_RuntimeNativeHost_nativeClose(
    _: JNIEnv,
    _: JObject,
    id: jlong,
) {
    if let Ok(mut registry) = hosts().lock() {
        registry.remove(&id);
    }
}
