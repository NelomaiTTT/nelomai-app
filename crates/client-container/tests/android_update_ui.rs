// Exercise the shipping Android relay on the host; Android/JNI entrypoints are
// covered by Kotlin lifecycle tests and cross-target compilation separately.
#[allow(dead_code)]
#[path = "../../../src-tauri/src/android_update_ui.rs"]
mod relay;
use nelomai_client_container::ipc::PrivateError;
use relay::{forward, UiUpdate};

fn event(foreground: bool, reason: u8) -> UiUpdate {
    UiUpdate {
        foreground,
        reason,
        new_user_launch: false,
        launch_session_id: None,
    }
}

#[tokio::test]
async fn old_or_unknown_owner_receives_no_probe_or_new_command() {
    for protocol in [0, 1, 3, u32::MAX] {
        forward(protocol, event(true, 1), |_| async {
            panic!("strict V1 owner must not receive V2 frames")
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn native_lifecycle_is_acked_before_startup_check_and_launch_id_is_preserved() {
    let mut sent = Vec::new();
    let mut update = event(true, 1);
    update.new_user_launch = true;
    update.launch_session_id = Some("d65074d4-f6fe-4d7a-a7d4-0d01ac701c99".into());
    forward(2, update, |request| {
        sent.push(serde_json::to_value(request).unwrap());
        std::future::ready(Ok(()))
    })
    .await
    .unwrap();
    assert_eq!(
        sent,
        vec![
            serde_json::json!({"action":"ui_lifecycle", "foreground":true, "newUserLaunch":true, "launchSessionId":"d65074d4-f6fe-4d7a-a7d4-0d01ac701c99"}),
            serde_json::json!({"action":"check", "reason":"startup"}),
        ]
    );
}

#[tokio::test]
async fn background_and_rotation_only_update_permission_without_new_checks() {
    for (foreground, reason) in [(false, 0), (false, 2), (true, 0)] {
        let mut sent = Vec::new();
        forward(2, event(foreground, reason), |request| {
            sent.push(serde_json::to_value(request).unwrap());
            std::future::ready(Ok(()))
        })
        .await
        .unwrap();
        assert_eq!(
            sent,
            vec![
                serde_json::json!({"action":"ui_lifecycle", "foreground":foreground, "newUserLaunch":false, "launchSessionId":null})
            ]
        );
    }
}

#[tokio::test]
async fn actual_foreground_return_checks_once_and_rejected_lifecycle_does_not_check() {
    let mut sent = Vec::new();
    forward(2, event(true, 2), |request| {
        sent.push(serde_json::to_value(request).unwrap());
        std::future::ready(Ok(()))
    })
    .await
    .unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[1],
        serde_json::json!({"action":"check", "reason":"foreground"})
    );
    let mut attempts = 0;
    assert!(forward(2, event(true, 1), |_| {
        attempts += 1;
        std::future::ready(Err(PrivateError::Closed))
    })
    .await
    .is_err());
    assert_eq!(attempts, 1);
}

#[tokio::test]
async fn transient_check_failure_does_not_drop_the_following_native_pause() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(event(true, 1)).unwrap();
    tx.send(event(false, 0)).unwrap();
    drop(tx);
    let mut sent = Vec::new();
    relay::relay(2, rx, |request| {
        let value = serde_json::to_value(&request).unwrap();
        let check = value["action"] == "check";
        sent.push(value);
        std::future::ready(if check {
            Err(PrivateError::Service)
        } else {
            Ok(())
        })
    })
    .await;
    assert_eq!(
        sent.len(),
        3,
        "one failed check must not strand the owner's foreground state"
    );
    assert_eq!(sent[2]["foreground"], false);
}

#[tokio::test]
async fn terminal_channel_failure_never_sends_later_commands() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(event(true, 1)).unwrap();
    tx.send(event(false, 0)).unwrap();
    drop(tx);
    let mut calls = 0;
    relay::relay(2, rx, |_| {
        calls += 1;
        std::future::ready(Err(PrivateError::Protocol))
    })
    .await;
    assert_eq!(calls, 1);
}
