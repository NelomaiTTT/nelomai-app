//! Android product process: no common auth store, refresh secret or installer.
use crate::*;
use nelomai_client_container::ipc::{
    ChildAdmission, PrivateRuntimeAuthClient, RuntimeRecordInventory,
};
use tauri::Manager;

pub fn setup_android(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let (descriptor, bootstrap) = android_runtime::take_bootstrap()?;
    let paths = bootstrap.runtime_paths()?;
    let selected = paths
        .iter()
        .find(|path| {
            path.slot() == bootstrap.target.runtime_slot
                && path.runtime_version() == bootstrap.target.runtime_version
        })
        .ok_or_else(|| std::io::Error::other("selected runtime storage unavailable"))?
        .clone();
    let open = |path: nelomai_client_storage::RuntimePaths| {
        let record = SystemSecretStore::new(format!("primary:{}", path.namespace()), None);
        RuntimeRecordOwner::new(ProtectedRuntimeStore::new(record, path))
    };
    let retained = paths
        .into_iter()
        .filter(|path| path != &selected)
        .map(open)
        .collect();
    let record = open(selected.clone());
    let tunnel = Arc::new(platform::tunnel_controller(app.handle().clone()));
    let local = CoreLocalStop::new(tunnel.clone());
    let admission = Arc::new(ChildAdmission::new(
        bootstrap.incarnation,
        local.runtime_writer_gates(),
        Arc::new(RuntimeRecordInventory::new(record.clone(), retained)),
    ));
    let socket = std::os::unix::net::UnixStream::from(descriptor);
    socket.set_nonblocking(true)?;
    let port = tauri::async_runtime::block_on(async {
        tokio::net::UnixStream::from_std(socket).map(|socket| {
            Arc::new(PrivateRuntimeAuthClient::new(
                socket,
                admission,
                local.clone(),
            ))
        })
    })?;
    let api = ClientApi::new(PANEL_BASE)?.with_app_version(&bootstrap.target.container_version)?;
    let diagnostics = Arc::new(diagnostics::AppDiagnostics::new(
        bootstrap.data_root.join("diagnostics"),
        resource_usage::ResourceSnapshot::capture(app.handle()),
    )?);
    diagnostics.record_named("startup.rust.private_runtime_ready", None, None, None);
    let preferences = Arc::new(preferences::AppPreferenceStore::open_runtime(
        &selected.preferences,
        &bootstrap.data_root.join("preferences.json"),
    )?);
    let application = Arc::new(ClientApplication::with_split_tunnel_store_and_preflight(
        Arc::new(api),
        Arc::new(record.operational()),
        Arc::new(record.split()),
        port.clone(),
        local,
        diagnostics.clone(),
        port.clone(),
    ));
    application.set_dns_servers(preferences.get().dns_provider.servers());
    let split = Arc::new(SplitTunnelScheduler::new());
    let push = Arc::new(PushRegistrationScheduler::new());
    let metrics = Arc::new(connection_metrics::ConnectionMetricsTracker::new());
    app.manage(port.clone());
    app.manage(Arc::new(runtime_control::RuntimeControls::new(
        port.clone(),
    )));
    app.manage(Arc::new(updates::NativeUpdater::new(port.clone())));
    app.manage(application.clone());
    app.manage(tunnel.clone());
    app.manage(diagnostics.clone());
    app.manage(preferences);
    app.manage(split.clone());
    app.manage(push.clone());
    app.manage(metrics.clone());
    let handle = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        if port
            .owner_request(nelomai_client_container::host::HostRequestV1::RuntimeReady)
            .await
            .is_err()
        {
            diagnostics.record_named("startup.runtime_recovery_required", None, None, None);
            return;
        }
        let dns = application_dns(&handle);
        let _ = handle
            .tunnel_android()
            .update_quick_dns_async(tauri_plugin_tunnel_android::DnsServersRequest {
                dns_servers: dns,
            })
            .await;
        start_split_tunnel_scheduler(application.clone(), split);
        start_physical_network_scheduler(application.clone());
        start_pending_stop_scheduler(application.clone());
        start_connection_metrics_scheduler(
            handle.clone(),
            application.clone(),
            tunnel,
            metrics,
            diagnostics,
        );
        start_push_registration_scheduler(handle, application, push);
    });
    Ok(())
}
fn application_dns(app: &tauri::AppHandle) -> Vec<String> {
    app.state::<Arc<preferences::AppPreferenceStore>>()
        .get()
        .dns_provider
        .servers()
        .iter()
        .map(ToString::to_string)
        .collect()
}
