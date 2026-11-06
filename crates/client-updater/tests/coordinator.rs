include!("support/consent.rs");
#[tokio::test]
async fn legacy_automatic_entry_point_cannot_install_without_consent() {
    let (owner, backend, barrier, _) = setup();
    assert!(owner
        .install_automatically(&access(), UpdatePreferences::default())
        .await
        .is_err());
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn legacy_manual_entry_point_cannot_install_without_offer_identity() {
    let (owner, backend, barrier, _) = setup();
    assert!(owner.install_now(&access()).await.is_err());
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn backend_cannot_mark_an_unexpected_version_as_installed() {
    let (owner, backend, barrier, id) = setup();
    *backend.result.lock().unwrap() = Some(Ok(InstallResult::Installed(InstalledUpdate {
        version: "9.0.0".into(),
    })));
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
    assert!(
        matches!(owner.phase(),UpdatePhase::Failed {code,..} if code=="installed_update_version_mismatch")
    );
}
#[tokio::test]
async fn android_installer_state_is_stable_until_the_app_is_replaced() {
    let (owner, backend, barrier, id) = setup();
    *backend.result.lock().unwrap() = Some(Ok(InstallResult::InstallerOpened(InstalledUpdate {
        version: "0.4.1".into(),
    })));
    owner.confirm(&id).unwrap();
    owner.drive(&access(), false).await.unwrap();
    owner.observe_resolved(Some((offer(), descriptor())), &access());
    owner.confirm(&id).unwrap();
    owner.drive(&access(), true).await.unwrap();
    assert!(matches!(
        owner.phase(),
        UpdatePhase::AwaitingInstallation { .. }
    ));
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn cancelled_android_install_requires_new_manual_consent() {
    let (owner, backend, barrier, id) = setup();
    *backend.result.lock().unwrap() = Some(Err(UpdateBackendError::new("apk_install_cancelled")));
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    owner.drive(&access(), true).await.unwrap();
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    assert_eq!(backend.installs.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn backend_waits_until_shutdown_barrier_reports_local_stopped() {
    let (owner, backend, barrier, id) = setup();
    barrier.block.store(true, Ordering::SeqCst);
    owner.confirm(&id).unwrap();
    let worker = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), false).await })
    };
    barrier.started.notified().await;
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
    barrier.release.notify_one();
    worker.await.unwrap().unwrap();
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn installer_error_cancels_shutdown_barrier_before_returning() {
    let (owner, backend, barrier, id) = setup();
    *backend.result.lock().unwrap() =
        Some(Err(UpdateBackendError::new("synthetic_installer_failure")));
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
    assert!(!owner.has_consent());
}
#[tokio::test]
async fn no_update_cancels_barrier_without_marking_install() {
    let (owner, backend, barrier, id) = setup();
    *backend.result.lock().unwrap() = Some(Ok(InstallResult::NoUpdate));
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn installer_journal_failure_is_reported_as_failed_phase() {
    let (owner, backend, barrier, id) = setup();
    barrier.reject_opened.store(true, Ordering::SeqCst);
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    assert!(matches!(owner.phase(),UpdatePhase::Failed{code,..} if code=="update_journal_failed"));
}
#[tokio::test]
async fn rollback_failure_replaces_backend_error_in_failed_phase() {
    let (owner, backend, barrier, id) = setup();
    *backend.result.lock().unwrap() =
        Some(Err(UpdateBackendError::new("synthetic_installer_failure")));
    barrier.reject_failed.store(true, Ordering::SeqCst);
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    assert!(matches!(owner.phase(),UpdatePhase::Failed{code,..} if code=="update_recovery_failed"));
}
#[tokio::test]
async fn cancelled_offer_stays_cancelled_when_rollback_initially_fails() {
    let (owner, backend, barrier, id) = setup();
    *backend.result.lock().unwrap() = Some(Err(UpdateBackendError::new("apk_install_cancelled")));
    barrier.reject_failed.store(true, Ordering::SeqCst);
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    barrier.reject_failed.store(false, Ordering::SeqCst);
    owner.observe_resolved(Some((offer(), descriptor())), &access());
    owner.drive(&access(), true).await.unwrap();
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    assert!(!owner.has_consent());
}
#[tokio::test]
async fn auth_change_during_stop_recovers_without_installer() {
    let (owner, backend, barrier, id) = setup();
    barrier.stale_after_stop.store(true, Ordering::SeqCst);
    owner.confirm(&id).unwrap();
    assert!(owner.drive(&access(), false).await.is_err());
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn caller_abort_keeps_native_consumer_and_recovery_gate_until_actual_completion() {
    let (owner, backend, barrier, id) = setup();
    backend.install_block.store(true, Ordering::SeqCst);
    owner.confirm(&id).unwrap();
    let caller = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), false).await })
    };
    backend.install_started.notified().await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        owner.installation_gate().try_lock().is_err(),
        "caller abort released an active installer"
    );
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 0);
    backend.install_release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !matches!(owner.phase(), UpdatePhase::ReadyToRestart { .. }) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 1);
    assert!(owner.installation_gate().try_lock().is_ok());
}
