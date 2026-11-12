include!("support/consent.rs");
#[tokio::test]
async fn prepare_never_calls_stop_or_installer() {
    let (owner, backend, barrier, _) = setup();
    owner.drive(&access(), true).await.unwrap();
    assert!(matches!(owner.phase(), UpdatePhase::ReadyToInstall { .. }));
    assert_eq!(backend.downloads.load(Ordering::SeqCst), 1);
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failure_revalidating_a_fresh_package_reports_verification() {
    let (owner, backend, barrier, id) = setup();
    owner.confirm(&id).unwrap();
    backend.remove_after_prepare.store(true, Ordering::SeqCst);
    let UpdateError::Backend(error) = owner.drive(&access(), true).await.unwrap_err() else {
        panic!("expected cache failure");
    };
    assert_eq!(error.code(), "update_cache_invalid");
    assert_eq!(error.stage(), Some("verification"));
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn automatic_off_resolves_metadata_without_artifact_get() {
    let (owner, backend, barrier, _) = setup();
    owner.drive(&access(), false).await.unwrap();
    assert!(owner.offer_id().is_some());
    assert_eq!(backend.downloads.load(Ordering::SeqCst), 0);
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn confirm_while_downloading_waits_for_verified_same_offer() {
    let (owner, backend, barrier, id) = setup();
    backend.block.store(true, Ordering::SeqCst);
    let worker = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), true).await })
    };
    backend.started.notified().await;
    owner.confirm(&id).unwrap();
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    backend.release.notify_one();
    worker.await.unwrap().unwrap();
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.opened.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn later_keeps_download_but_clears_consent() {
    let (owner, backend, barrier, id) = setup();
    backend.block.store(true, Ordering::SeqCst);
    let worker = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), true).await })
    };
    backend.started.notified().await;
    owner.confirm(&id).unwrap();
    owner.defer(&id).unwrap();
    backend.release.notify_one();
    worker.await.unwrap().unwrap();
    assert!(matches!(owner.phase(), UpdatePhase::ReadyToInstall { .. }));
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert_eq!(owner.deferred_version().as_deref(), Some("0.4.1"));
}
#[tokio::test]
async fn same_version_replacement_rejects_early_consent() {
    let (owner, backend, barrier, id) = setup();
    owner.confirm(&id).unwrap();
    backend.current.lock().unwrap().as_mut().unwrap().signature = "replacement".into();
    assert!(owner.drive(&access(), true).await.is_err());
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert!(!owner.has_consent());
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn revoked_manifest_prevents_stop_and_keeps_cache() {
    let (owner, backend, barrier, id) = setup();
    owner.drive(&access(), true).await.unwrap();
    owner.confirm(&id).unwrap();
    *backend.current.lock().unwrap() = None;
    assert!(owner.drive(&access(), true).await.is_err());
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert!(backend.dir.path().join("verified-package").exists());
    assert!(!owner.has_consent());
}
#[tokio::test]
async fn prepare_failure_clears_queued_install() {
    let (owner, backend, barrier, id) = setup();
    owner.confirm(&id).unwrap();
    backend.fail_download.store(true, Ordering::SeqCst);
    assert!(owner.drive(&access(), true).await.is_err());
    backend.fail_download.store(false, Ordering::SeqCst);
    owner.drive(&access(), true).await.unwrap();
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert!(!owner.has_consent());
}
#[tokio::test]
async fn double_confirm_installs_once() {
    let (owner, backend, barrier, id) = setup();
    owner.confirm(&id).unwrap();
    owner.confirm(&id).unwrap();
    let access = access();
    let (a, b) = tokio::join!(owner.drive(&access, false), owner.drive(&access, false));
    a.unwrap();
    b.unwrap();
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn stale_offer_confirmation_rejected() {
    let (owner, _, barrier, id) = setup();
    let mut changed = descriptor();
    changed.signature = "replacement".into();
    owner.observe_resolved(Some((offer(), changed)), &access());
    assert!(owner.confirm(&id).is_err());
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn logout_after_download_prevents_stop() {
    let (owner, backend, barrier, id) = setup();
    owner.drive(&access(), true).await.unwrap();
    owner.confirm(&id).unwrap();
    barrier.stale.store(true, Ordering::SeqCst);
    assert!(owner.drive(&access(), true).await.is_err());
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn stop_failure_prevents_install() {
    let (owner, backend, barrier, id) = setup();
    owner.confirm(&id).unwrap();
    barrier.reject.store(true, Ordering::SeqCst);
    assert!(owner.drive(&access(), false).await.is_err());
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
    assert!(!owner.has_consent());
}

#[tokio::test]
async fn auto_off_cancels_unconfirmed_download_but_not_confirmed_operation() {
    let (owner, backend, barrier, id) = setup();
    backend.block.store(true, Ordering::SeqCst);
    let worker = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), true).await })
    };
    backend.started.notified().await;
    owner.set_automatic(false);
    tokio::time::timeout(std::time::Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert!(!backend.dir.path().join("verified-package").exists());
    owner.confirm(&id).unwrap();
    let worker = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), true).await })
    };
    backend.started.notified().await;
    owner.set_automatic(false);
    backend.release.notify_one();
    worker.await.unwrap().unwrap();
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn disconnected_ui_cannot_authorize_stop_despite_stale_foreground_flag() {
    let backend = Arc::new(Backend::new());
    let barrier = Arc::new(Barrier::default());
    let owner = UpdateCoordinator::with_foreground_guard(backend.clone(), barrier.clone(), true);
    let connected = Arc::new(AtomicBool::new(true));
    let probe = connected.clone();
    owner.set_ui_connection_probe(Arc::new(move || probe.load(Ordering::SeqCst)));
    owner.set_ui_lifecycle(true, false);
    owner.observe_resolved(Some((offer(), descriptor())), &access());
    owner.present(&owner.offer_id().unwrap()).unwrap();
    owner.confirm(&owner.offer_id().unwrap()).unwrap();
    connected.store(false, Ordering::SeqCst);
    owner.drive(&access(), true).await.unwrap();
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
    assert!(!owner.has_consent());
    connected.store(true, Ordering::SeqCst);
    owner.set_ui_lifecycle(true, false);
    assert!(
        owner.prompt_pending(),
        "loss of the native peer cancels early consent too"
    );
}
#[tokio::test]
async fn ui_hidden_after_stop_cancels_through_existing_recovery() {
    let backend = Arc::new(Backend::new());
    let barrier = Arc::new(Barrier::default());
    let owner = Arc::new(UpdateCoordinator::with_foreground_guard(
        backend.clone(),
        barrier.clone(),
        true,
    ));
    owner.set_ui_connection_probe(Arc::new(|| true));
    owner.set_ui_lifecycle(true, false);
    owner.observe_resolved(Some((offer(), descriptor())), &access());
    owner.confirm(&owner.offer_id().unwrap()).unwrap();
    barrier.block.store(true, Ordering::SeqCst);
    let worker = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), false).await })
    };
    barrier.started.notified().await;
    owner.set_ui_lifecycle(false, false);
    barrier.release.notify_one();
    assert!(worker.await.unwrap().is_err());
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_ready_file_can_be_downloaded_again_without_reusing_consent() {
    for deleted in [false, true] {
        let (owner, backend, barrier, id) = setup();
        owner.drive(&access(), true).await.unwrap();
        let path = backend.dir.path().join("verified-package");
        if deleted {
            std::fs::remove_file(&path).unwrap();
        } else {
            std::fs::write(&path, b"damaged").unwrap();
        }
        owner.confirm(&id).unwrap();
        assert!(owner.drive(&access(), true).await.is_err());
        assert!(!owner.has_consent());
        assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
        owner.observe_resolved(Some((offer(), descriptor())), &access());
        owner
            .drive(&access(), true)
            .await
            .expect("same offer must redownload invalid bytes");
        assert_eq!(backend.downloads.load(Ordering::SeqCst), 2);
        assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
        assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
        owner.confirm(&owner.offer_id().unwrap()).unwrap();
        owner.drive(&access(), false).await.unwrap();
        assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn detached_consumer_releases_invalid_handle_after_post_stop_failure() {
    let (owner, backend, barrier, id) = setup();
    owner.drive(&access(), true).await.unwrap();
    owner.confirm(&id).unwrap();
    barrier.block.store(true, Ordering::SeqCst);
    let worker = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), true).await })
    };
    barrier.started.notified().await;
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    std::fs::write(backend.dir.path().join("verified-package"), b"damaged").unwrap();
    barrier.release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !matches!(owner.phase(), UpdatePhase::Failed { .. }) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
    assert!(!owner.has_consent());
    owner
        .drive(&access(), true)
        .await
        .expect("detached consumer must release unusable handle");
    assert_eq!(backend.downloads.load(Ordering::SeqCst), 2);
    assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
    assert_eq!(barrier.stops.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn interrupted_early_yes_prompts_again_on_return() {
    for previous_later in [false, true] {
        let backend = Arc::new(Backend::new());
        let barrier = Arc::new(Barrier::default());
        let owner = Arc::new(UpdateCoordinator::with_foreground_guard(
            backend.clone(),
            barrier.clone(),
            true,
        ));
        owner.set_ui_connection_probe(Arc::new(|| true));
        owner.set_ui_lifecycle(true, true);
        owner.observe_resolved(Some((offer(), descriptor())), &access());
        let id = owner.offer_id().unwrap();
        assert!(owner.prompt_pending());
        owner.present(&id).unwrap();
        if previous_later {
            owner.defer(&id).unwrap();
        }
        backend.block.store(true, Ordering::SeqCst);
        let worker = {
            let owner = owner.clone();
            tokio::spawn(async move { owner.drive(&access(), true).await })
        };
        backend.started.notified().await;
        owner.confirm(&id).unwrap();
        owner.set_ui_lifecycle(false, false);
        assert!(!owner.has_consent());
        backend.release.notify_one();
        worker.await.unwrap().unwrap();
        assert!(matches!(owner.phase(), UpdatePhase::ReadyToInstall { .. }));
        assert_eq!(barrier.stops.load(Ordering::SeqCst), 0);
        assert_eq!(backend.installs.load(Ordering::SeqCst), 0);
        owner.set_ui_lifecycle(true, false);
        owner.observe_resolved(Some((offer(), descriptor())), &access());
        assert!(
            owner.prompt_pending(),
            "cancelled early Yes must offer installation again on return"
        );
    }
}

#[tokio::test]
async fn explicit_later_remains_deferred_on_android_return() {
    let backend = Arc::new(Backend::new());
    let barrier = Arc::new(Barrier::default());
    let owner = UpdateCoordinator::with_foreground_guard(backend, barrier, true);
    owner.set_ui_connection_probe(Arc::new(|| true));
    owner.set_ui_lifecycle(true, false);
    owner.observe_resolved(Some((offer(), descriptor())), &access());
    let id = owner.offer_id().unwrap();
    owner.present(&id).unwrap();
    owner.confirm(&id).unwrap();
    owner.defer(&id).unwrap();
    owner.set_ui_lifecycle(false, false);
    owner.set_ui_lifecycle(true, false);
    assert!(!owner.prompt_pending());
    assert!(!owner.has_consent());
}

#[test]
fn notification_is_once_even_if_the_dialog_was_already_presented() {
    for action in ["present", "defer", "confirm", "none"] {
        let (owner, _, _, id) = setup();
        match action {
            "present" => owner.present(&id).unwrap(),
            "defer" => owner.defer(&id).unwrap(),
            "confirm" => owner.confirm(&id).unwrap(),
            _ => (),
        }
        assert_eq!(
            owner.take_notification().is_some(),
            matches!(action, "none" | "present"),
            "{action}"
        );
        assert!(owner.take_notification().is_none());
    }
}

#[tokio::test]
async fn android_installer_pause_does_not_rearm_prompt_even_if_native_install_fails() {
    let backend = Arc::new(Backend::new());
    let barrier = Arc::new(Barrier::default());
    let owner = Arc::new(UpdateCoordinator::with_foreground_guard(
        backend.clone(),
        barrier.clone(),
        true,
    ));
    owner.set_ui_connection_probe(Arc::new(|| true));
    owner.set_ui_lifecycle(true, false);
    owner.observe_resolved(Some((offer(), descriptor())), &access());
    let id = owner.offer_id().unwrap();
    owner.present(&id).unwrap();
    owner.confirm(&id).unwrap();
    backend.install_block.store(true, Ordering::SeqCst);
    *backend.result.lock().unwrap() = Some(Err(UpdateBackendError::new("native_install_failed")));
    let task = {
        let owner = owner.clone();
        tokio::spawn(async move { owner.drive(&access(), false).await })
    };
    backend.install_started.notified().await;
    assert!(matches!(owner.phase(), UpdatePhase::Installing { .. }));
    owner.set_ui_lifecycle(false, false);
    backend.install_release.notify_one();
    assert!(task.await.unwrap().is_err());
    owner.set_ui_lifecycle(true, false);
    assert!(!owner.has_consent());
    assert!(!owner.prompt_pending());
    assert_eq!(backend.installs.load(Ordering::SeqCst), 1);
    assert_eq!(barrier.failed.load(Ordering::SeqCst), 1);
}
