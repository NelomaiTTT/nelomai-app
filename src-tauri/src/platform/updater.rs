use async_trait::async_trait;
use nelomai_client_api::{panel_backup_url, resolve_panel_addresses, AccessSnapshot};
#[cfg(not(windows))]
use nelomai_client_updater::InstalledUpdate;
use nelomai_client_updater::{
    DownloadProgress, InstallResult, UpdateBackend, UpdateBackendError, UpdateBarrierPhase,
    UpdateEndpointPolicy,
};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Runtime};
use tauri_plugin_updater::UpdaterExt;

const PANEL_BASE: &str = "https://nelomai.ru";

pub struct DesktopUpdateBackend<R: Runtime> {
    app: AppHandle<R>,
    endpoint_policy: UpdateEndpointPolicy,
    public_key: String,
}

impl<R: Runtime> DesktopUpdateBackend<R> {
    pub fn from_build(app: AppHandle<R>) -> Result<Self, UpdateBackendError> {
        let public_key = option_env!("NELOMAI_UPDATER_PUBLIC_KEY")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| UpdateBackendError::new("updater_public_key_missing"))?;
        Self::new(app, PANEL_BASE, public_key)
    }

    pub fn new(
        app: AppHandle<R>,
        panel_base: &str,
        public_key: impl Into<String>,
    ) -> Result<Self, UpdateBackendError> {
        let public_key = public_key.into();
        if public_key.trim().is_empty() {
            return Err(UpdateBackendError::new("updater_public_key_missing"));
        }
        let endpoint_policy = UpdateEndpointPolicy::new(panel_base)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        Ok(Self {
            app,
            endpoint_policy,
            public_key,
        })
    }
}

#[async_trait]
impl<R: Runtime> UpdateBackend for DesktopUpdateBackend<R> {
    async fn install(
        &self,
        access_token: &AccessSnapshot,
        expected_version: &str,
        barrier: UpdateBarrierPhase,
        progress: Arc<dyn Fn(DownloadProgress) + Send + Sync>,
    ) -> Result<InstallResult, UpdateBackendError> {
        debug_assert_eq!(barrier, UpdateBarrierPhase::LocalStopped);
        let target = tauri_plugin_updater::target()
            .ok_or_else(|| UpdateBackendError::new("unsupported_update_target"))?;
        let current_version = self.app.package_info().version.to_string();
        let endpoint = self
            .endpoint_policy
            .manifest_url(&target, &current_version)
            .map_err(|_| UpdateBackendError::new("invalid_update_endpoint"))?;
        // The durable LocalStopped barrier blocks native Start throughout this
        // install. The plugin runs after our VPN is stopped, so it needs no
        // second physical relay adapter across incompatible reqwest versions.
        // The plugin uses reqwest 0.13. Pass the shared resolver's address
        // snapshot through its supported hook, for both check and download.
        let check_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let backup_endpoint = panel_backup_url(&endpoint);
        let backup_host = backup_endpoint
            .as_ref()
            .and_then(|url| url.host_str())
            .map(str::to_owned);
        let panel_host = endpoint
            .host_str()
            .ok_or_else(|| UpdateBackendError::new("invalid_update_endpoint"))?
            .to_owned();
        let (panel_addresses, backup_addresses) = tokio::time::timeout_at(check_deadline, async {
            Ok::<_, UpdateBackendError>(if let Some(host) = &backup_host {
                let (primary, backup) = tokio::join!(
                    resolve_panel_addresses(&panel_host),
                    resolve_panel_addresses(host)
                );
                (
                    primary.map_err(|_| UpdateBackendError::new("update_check_failed"))?,
                    Some(backup.map_err(|_| UpdateBackendError::new("update_check_failed"))?),
                )
            } else {
                (
                    resolve_panel_addresses(&panel_host)
                        .await
                        .map_err(|_| UpdateBackendError::new("update_check_failed"))?,
                    None,
                )
            })
        })
        .await
        .map_err(|_| UpdateBackendError::new("update_check_failed"))??;
        let Some(update) = updater_request(
            endpoint,
            check_deadline,
            "update_check_failed",
            |endpoint, remaining| {
                let panel_host = panel_host.clone();
                let panel_addresses = panel_addresses.clone();
                let backup_host = backup_host.clone();
                let backup_addresses = backup_addresses.clone();
                async move {
                    // One endpoint per plugin instance: its internal multi-endpoint
                    // loop would otherwise retry HTTP and parse failures too.
                    let mut builder = self
                        .app
                        .updater_builder()
                        .pubkey(self.public_key.clone())
                        .endpoints(vec![endpoint])
                        .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?
                        .timeout(remaining)
                        .configure_client(move |builder| {
                            let builder = configure_updater_client(builder)
                                .resolve_to_addrs(&panel_host, &panel_addresses);
                            if let (Some(host), Some(addresses)) = (&backup_host, &backup_addresses)
                            {
                                builder.resolve_to_addrs(host, addresses)
                            } else {
                                builder
                            }
                        });
                    for (name, value) in access_token.bearer_headers() {
                        builder = builder
                            .header(name, value)
                            .map_err(|_| UpdateBackendError::new("updater_authorization_failed"))?;
                    }
                    let updater = builder
                        .build()
                        .map_err(|_| UpdateBackendError::new("updater_configuration_failed"))?;
                    updater
                        .check()
                        .await
                        .map_err(UpdaterAttemptError::Transport)
                }
            },
        )
        .await?
        else {
            return Ok(InstallResult::NoUpdate);
        };
        if update.version != expected_version {
            return Err(UpdateBackendError::new("update_version_changed"));
        }
        if !self
            .endpoint_policy
            .is_trusted_artifact(&update.download_url)
        {
            return Err(UpdateBackendError::new("untrusted_update_artifact"));
        }

        #[cfg(target_os = "macos")]
        let macos_package = MacosUpdatePackage::from_url(&update.download_url)?;

        let download_deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
        let bytes = updater_request(
            update.download_url.clone(),
            download_deadline,
            "update_install_failed",
            |url, remaining| {
                let mut download = update.clone();
                let progress = progress.clone();
                async move {
                    download.download_url = url;
                    download.timeout = Some(remaining);
                    let mut downloaded = 0_u64;
                    download
                        .download(
                            |chunk, total| {
                                downloaded = downloaded.saturating_add(chunk as u64);
                                progress(DownloadProgress { downloaded, total });
                            },
                            || {},
                        )
                        .await
                        .map_err(UpdaterAttemptError::Transport)
                }
            },
        )
        .await?;

        let stop_proof = crate::container::begin_installation(&self.app, expected_version)
            .await
            .map_err(|_| UpdateBackendError::new("update_stop_proof_unavailable"))?;
        #[cfg(windows)]
        {
            crate::desktop::set_tray_visible(&self.app, false);
            let result = crate::container::handoff_windows_installer(&self.app, stop_proof, || {
                update
                    .install(bytes)
                    .map_err(|_| std::io::Error::other("update install failed"))
            })
            .await;
            // The dependency normally exits without returning. A return (even
            // Ok) is not replacement evidence and must never enable restart.
            crate::desktop::set_tray_visible(&self.app, true);
            Err(UpdateBackendError::new(if result.is_err() {
                "update_install_failed"
            } else {
                "update_install_outcome_unknown"
            }))
        }
        #[cfg(not(windows))]
        {
            #[cfg(target_os = "linux")]
            let install = install_linux_common(bytes).await;
            #[cfg(target_os = "macos")]
            let install = install_macos_common(bytes, macos_package).await;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            let install = update
                .install(bytes)
                .map_err(|_| UpdateBackendError::new("update_install_failed"));
            install.map_err(|_| UpdateBackendError::new("update_install_failed"))?;
            crate::container::installation_succeeded(&self.app, stop_proof)
                .await
                .map_err(|_| UpdateBackendError::new("update_stop_proof_changed"))?;
            Ok(InstallResult::Installed(InstalledUpdate {
                version: update.version,
            }))
        }
    }
}

/// Like Linux, macOS activates the complete root-owned common bundle in one
/// authorization. Stock Update::install leaves a user-owned extracted bundle,
/// which otherwise forces another privileged repair during pre-auth startup.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacosUpdatePackage {
    Archive,
    Dmg,
}

#[cfg(target_os = "macos")]
impl MacosUpdatePackage {
    fn from_url(url: &tauri::Url) -> Result<Self, UpdateBackendError> {
        if url.path().ends_with(".app.tar.gz") {
            Ok(Self::Archive)
        } else if url.path().ends_with(".dmg") {
            Ok(Self::Dmg)
        } else {
            Err(UpdateBackendError::new("unsupported_update_package"))
        }
    }
    fn filename(self) -> &'static str {
        match self {
            Self::Archive => "Nelomai.app.tar.gz",
            Self::Dmg => "Nelomai.dmg",
        }
    }
}

#[cfg(target_os = "macos")]
async fn install_macos_common(
    bytes: Vec<u8>,
    package: MacosUpdatePackage,
) -> Result<(), UpdateBackendError> {
    let resources = std::path::Path::new(
        "/Library/Application Support/Nelomai/common/Nelomai.app/Contents/Resources",
    );
    for name in [
        "install-common-macos.sh",
        "install-common-macos.applescript",
    ] {
        for path in resources.join(name).ancestors() {
            nelomai_contracts::dispatcher::trusted(path, 0)
                .map_err(|_| UpdateBackendError::new("common_installer_untrusted"))?;
        }
    }
    let (staging, mut command) =
        stage_macos_update(&bytes, resources, unsafe { libc::getuid() }, package)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _staging = staging;
        let status = super::unix::installer_status(&mut command)
            .map_err(|_| UpdateBackendError::new("update_install_failed"))?;
        if !status.success() {
            return Err(UpdateBackendError::new("update_install_failed"));
        }
        Ok(())
    })
    .await
    .map_err(|_| UpdateBackendError::new("update_install_failed"))?
}

/// Caller verified Update::download's signature, stop barrier and root-owned
/// installer paths. Keep staging alive through authorization; the installer
/// hashes its protected copy before extraction, closing the source-file race.
#[cfg(target_os = "macos")]
fn stage_macos_update(
    bytes: &[u8],
    resources: &std::path::Path,
    owner_uid: libc::uid_t,
    package: MacosUpdatePackage,
) -> Result<(tempfile::TempDir, std::process::Command), UpdateBackendError> {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    if owner_uid == 0 {
        return Err(UpdateBackendError::new("helper_owner_is_root"));
    }
    let staging = tempfile::Builder::new()
        .prefix("nelomai-verified-update-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    let archive = staging.path().join(package.filename());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&archive)
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command
        .arg(resources.join("install-common-macos.applescript"))
        .arg(resources.join("install-common-macos.sh"))
        .arg(owner_uid.to_string())
        .arg(archive)
        .arg(nelomai_contracts::dispatcher::digest(bytes));
    Ok((staging, command))
}

/// `Update::download` has already verified the updater signature. The root
/// installer copies and hashes these exact bytes before extracting/activating
/// the complete AppImage; auth and stop barriers stay in the common updater.
#[cfg(target_os = "linux")]
async fn install_linux_common(bytes: Vec<u8>) -> Result<(), UpdateBackendError> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
    let installer = Path::new("/usr/local/libexec/nelomai/common/install-common-linux.sh");
    for path in installer.ancestors() {
        nelomai_contracts::dispatcher::trusted(path, 0)
            .map_err(|_| UpdateBackendError::new("common_installer_untrusted"))?;
    }
    let staging = tempfile::Builder::new()
        .prefix("nelomai-verified-update-")
        .tempdir()
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    let image = staging.path().join("Nelomai.AppImage");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&image)
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| UpdateBackendError::new("update_staging_failed"))?;
    drop(file);
    let sha = nelomai_contracts::dispatcher::digest(&bytes);
    tauri::async_runtime::spawn_blocking(move || {
        let _staging = staging;
        let status = super::unix::installer_status(
            std::process::Command::new("/usr/bin/pkexec")
                .arg("/bin/sh")
                .arg(installer)
                .arg(image)
                .arg(sha),
        )
        .map_err(|_| UpdateBackendError::new("update_install_failed"))?;
        if !status.success() {
            return Err(UpdateBackendError::new("update_install_failed"));
        }
        Ok(())
    })
    .await
    .map_err(|_| UpdateBackendError::new("update_install_failed"))?
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::{ffi::OsString, os::unix::fs::PermissionsExt, path::Path};

    #[test]
    fn macos_update_handoff_pins_private_bytes_and_installed_installer() {
        let resources =
            Path::new("/Library/Application Support/Nelomai/common/Nelomai.app/Contents/Resources");
        let (staging, command) =
            stage_macos_update(b"abc", resources, 501, MacosUpdatePackage::Archive).unwrap();
        let archive = staging.path().join("Nelomai.app.tar.gz");
        assert_eq!(std::fs::read(&archive).unwrap(), b"abc");
        assert_eq!(
            std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(staging.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(command.get_program(), "/usr/bin/osascript");
        assert_eq!(
            command.get_args().map(OsString::from).collect::<Vec<_>>(),
            vec![
                resources
                    .join("install-common-macos.applescript")
                    .into_os_string(),
                resources.join("install-common-macos.sh").into_os_string(),
                OsString::from("501"),
                archive.clone().into_os_string(),
                OsString::from("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ]
        );
        drop(staging);
        assert!(!archive.exists());
    }

    #[test]
    fn dmg_update_stages_verified_image_and_removes_it_on_drop() {
        let package = MacosUpdatePackage::from_url(
            &tauri::Url::parse("https://nelomai.ru/api/artifacts/verified.dmg?token=fixture")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(package, MacosUpdatePackage::Dmg);
        let (staging, command) =
            stage_macos_update(b"signed-image", Path::new("/installed"), 501, package).unwrap();
        let image = staging.path().join("Nelomai.dmg");
        assert_eq!(std::fs::read(&image).unwrap(), b"signed-image");
        assert_eq!(
            std::fs::metadata(&image).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(command.get_args().any(|arg| arg == image.as_os_str()));
        drop(staging);
        assert!(!image.exists());
    }

    #[test]
    fn macos_update_format_uses_only_supported_url_path_suffix() {
        for path in [
            "update.exe",
            "update.zip",
            "update.dmg/other",
            "update.bin?name=update.dmg",
        ] {
            let url = tauri::Url::parse(&format!("https://nelomai.ru/{path}")).unwrap();
            assert!(MacosUpdatePackage::from_url(&url).is_err());
        }
        assert_eq!(
            MacosUpdatePackage::from_url(
                &tauri::Url::parse("https://nelomai.ru/old.app.tar.gz").unwrap()
            )
            .unwrap(),
            MacosUpdatePackage::Archive
        );
    }

    #[test]
    fn macos_update_rejects_root_owner_before_authorization() {
        assert!(
            stage_macos_update(b"abc", Path::new("/unused"), 0, MacosUpdatePackage::Archive)
                .is_err()
        );
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    #[tokio::test]
    async fn production_updater_loop_retries_manifest_and_download_once_and_keeps_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let _ = rustls::crypto::ring::default_provider().install_default();
        for operation in ["manifest", "download"] {
            let url =
                reqwest_updater::Url::parse(&format!("https://nelomai.ru/api/{operation}?x=a%2Fb"))
                    .unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = calls.clone();
            let result = updater_request(
                url,
                tokio::time::Instant::now() + Duration::from_secs(1),
                "fixture_failure",
                move |url, _| {
                    let seen = seen.clone();
                    async move {
                        seen.fetch_add(1, Ordering::SeqCst);
                        if url.host_str() == Some("nelomai.top") {
                            return Ok(url.to_string());
                        }
                        let error = pre_http_tls_failure(url).await;
                        Err(UpdaterAttemptError::Transport(error.into()))
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(
                calls.load(Ordering::SeqCst),
                2,
                "{operation} loop omitted its safe alternate"
            );
            assert_eq!(
                result,
                format!("https://nelomai.top/api/{operation}?x=a%2Fb")
            );
        }
        // HTTP/parse failures represented by plugin ReleaseNotFound and
        // configuration errors never select the second origin.
        for backend in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = calls.clone();
            let result: Result<(), _> = updater_request(
                reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
                tokio::time::Instant::now() + Duration::from_secs(1),
                "fixture_failure",
                move |_, _| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if backend {
                            Err(UpdaterAttemptError::Backend(UpdateBackendError::new(
                                "configuration",
                            )))
                        } else {
                            Err(UpdaterAttemptError::Transport(
                                tauri_plugin_updater::Error::ReleaseNotFound,
                            ))
                        }
                    }
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        // Obtain the real connect error before timing the loop: neither the
        // deadline test nor its second-attempt count depends on OS refusal latency.
        let mut timeout_error = Some(
            pre_http_tls_failure(reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap())
                .await,
        );
        let start = std::time::Instant::now();
        let result = updater_request(
            reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
            tokio::time::Instant::now() + Duration::from_millis(120),
            "fixture_timeout",
            move |url, _| {
                let seen = seen.clone();
                let error = timeout_error.take();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    if url.host_str() == Some("nelomai.top") {
                        Ok(())
                    } else {
                        Err(UpdaterAttemptError::Transport(error.unwrap().into()))
                    }
                }
            },
        )
        .await;
        assert_eq!(result.unwrap_err().code(), "fixture_timeout");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(start.elapsed() < Duration::from_millis(180));
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let result: Result<(), _> = updater_request(
            reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            "fixture_failure",
            move |url, _| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Err(UpdaterAttemptError::Transport(
                        pre_http_tls_failure(url).await.into(),
                    ))
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "backup failure recursively retried"
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let cancelled = updater_request(
            reqwest_updater::Url::parse("https://nelomai.ru/check").unwrap(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            "fixture_failure",
            move |_, _| {
                seen.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, UpdaterAttemptError>(())
                }
            },
        );
        assert!(tokio::time::timeout(Duration::from_millis(20), cancelled)
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Avoid depending on OS closed-port refusal latency: observe a real
    // TLS ClientHello and reject the handshake before
    // HTTP. The DNS override keeps the production HTTPS/default-port URL intact.
    // Both futures are owned here and dropped together on timeout/cancellation.
    async fn pre_http_tls_failure(url: reqwest_updater::Url) -> reqwest_updater::Error {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = configure_updater_client(reqwest_updater::Client::builder())
            .resolve_to_addrs(url.host_str().unwrap(), &[listener.local_addr().unwrap()])
            .build()
            .unwrap();
        let (response, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(client.post(url.clone()).body("once").send(), async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                socket.read_exact(&mut header).await.unwrap();
                assert_eq!(
                    header[0], 22,
                    "expected TLS handshake, not HTTP: {header:?}"
                );
                assert_eq!(header[1], 3, "expected TLS record version: {header:?}");
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                assert!(
                    (4..=16384).contains(&length),
                    "invalid ClientHello record length"
                );
                let mut hello = vec![0; length];
                socket.read_exact(&mut hello).await.unwrap();
                assert_eq!(hello[0], 1, "expected TLS ClientHello");
                // TLS fatal handshake_failure alert; no certificate or HTTP response.
                socket.write_all(&[21, 3, 3, 0, 2, 2, 40]).await.unwrap();
                socket.shutdown().await.unwrap();
            })
        })
        .await
        .expect("local TLS failure fixture exceeded its bound");
        let error = response.unwrap_err();
        assert!(
            error.is_connect() && !error.is_timeout() && error.url() == Some(&url),
            "TLS fixture: connect={} timeout={} url={:?} error={error:?}",
            error.is_connect(),
            error.is_timeout(),
            error.url()
        );
        error
    }

    // Real reqwest 0.13 errors: textual error matching would not establish
    // whether HTTP bytes had already reached the peer.
    #[tokio::test]
    async fn updater_classifier_accepts_only_initial_pre_http_connect_failure() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let url = reqwest_updater::Url::parse("https://nelomai.ru/initial").unwrap();
        let error = tauri_plugin_updater::Error::from(pre_http_tls_failure(url.clone()).await);
        eprintln!("local pre-HTTP TLS fixture returned {error:?}");
        assert!(safe_updater_connect_failure(&error, &url), "{error:?}");
        assert!(
            !safe_updater_connect_failure(&error, &url.join("/later").unwrap()),
            "a connect error for a different URL qualified for fallback: {error:?}"
        );
        let client = configure_updater_client(reqwest_updater::Client::builder())
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        for mode in 0..3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = reqwest_updater::Url::parse(&format!(
                "http://{}/initial",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let later = format!("http://{}/later", closed.local_addr().unwrap());
            drop(closed);
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = [0; 4096];
                assert!(socket.read(&mut bytes).await.unwrap() > 0);
                if mode == 1 {
                    socket.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                } else if mode == 2 {
                    socket.write_all(format!("HTTP/1.1 307 Redirect\r\nLocation: {later}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                }
            });
            // Exercise the production policy: even a same-operation later
            // connect error cannot turn an accepted redirect into a replay.
            let result = client
                .post(url.clone())
                .body("once")
                .send()
                .await
                .and_then(|r| r.error_for_status());
            if mode == 2 {
                assert_eq!(
                    result.unwrap().status(),
                    307,
                    "redirect was followed after HTTP was sent"
                );
            } else {
                let error = result.unwrap_err();
                assert!(
                    !safe_updater_connect_failure(&error.into(), &url),
                    "ambiguous outcome mode {mode} qualified for fallback"
                );
            }
            server.await.unwrap();
        }
        assert!(!safe_updater_connect_failure(
            &tauri_plugin_updater::Error::ReleaseNotFound,
            &url
        ));
    }
}

fn safe_updater_connect_failure(
    error: &tauri_plugin_updater::Error,
    url: &reqwest_updater::Url,
) -> bool {
    matches!(error, tauri_plugin_updater::Error::Reqwest(error)
        if error.is_connect() && error.url() == Some(url))
}

// The connect classifier is safe only when no previous HTTP hop can have run.
fn configure_updater_client(
    builder: reqwest_updater::ClientBuilder,
) -> reqwest_updater::ClientBuilder {
    builder
        .no_proxy()
        .redirect(reqwest_updater::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(8))
}

#[derive(Debug)]
enum UpdaterAttemptError {
    Backend(UpdateBackendError),
    Transport(tauri_plugin_updater::Error),
}
impl From<UpdateBackendError> for UpdaterAttemptError {
    fn from(error: UpdateBackendError) -> Self {
        Self::Backend(error)
    }
}

// Both real plugin operations use this loop; the attempt seam leaves their
// signature/version/artifact checks in place while making retries testable.
async fn updater_request<T, F, Fut>(
    mut url: reqwest_updater::Url,
    deadline: tokio::time::Instant,
    code: &'static str,
    mut attempt: F,
) -> Result<T, UpdateBackendError>
where
    F: FnMut(reqwest_updater::Url, Duration) -> Fut,
    Fut: std::future::Future<Output = Result<T, UpdaterAttemptError>>,
{
    let mut backup = panel_backup_url(&url);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(UpdateBackendError::new(code));
        }
        match tokio::time::timeout_at(deadline, attempt(url.clone(), remaining)).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(UpdaterAttemptError::Backend(error))) => return Err(error),
            Ok(Err(UpdaterAttemptError::Transport(error)))
                if safe_updater_connect_failure(&error, &url) =>
            {
                url = backup.take().ok_or_else(|| UpdateBackendError::new(code))?;
            }
            _ => return Err(UpdateBackendError::new(code)),
        }
    }
}
