use std::mem::size_of;

const MAX_FUTURE_BYTES: usize = 4 * 1024;

// Inspect concrete return types without constructing AppHandle/State or polling
// commands: the JNI thread must only carry small futures into Tauri's wrappers.
macro_rules! return_size {
    ($name:ident, $($arg:ident),*) => {
        const fn $name<F, R, $($arg),*>(_: &F) -> usize
        where F: FnOnce($($arg),*) -> R {
            size_of::<R>()
        }
    };
}
return_size!(return_size_0,);
return_size!(return_size_1, A0);
return_size!(return_size_2, A0, A1);
return_size!(return_size_3, A0, A1, A2);
return_size!(return_size_4, A0, A1, A2, A3);
return_size!(return_size_5, A0, A1, A2, A3, A4);
return_size!(return_size_6, A0, A1, A2, A3, A4, A5);
return_size!(return_size_7, A0, A1, A2, A3, A4, A5, A6);

macro_rules! command {
    ($name:ident, $size:ident, $asynchronous:literal) => {{
        const SIZE: usize = $size(&super::$name);
        const _: () = assert!(
            !$asynchronous || SIZE <= MAX_FUTURE_BYTES,
            concat!(
                stringify!($name),
                " future exceeds4KiB before Tauri wrappers"
            )
        );
        (stringify!($name), SIZE, $asynchronous)
    }};
}

// The Android compiler evaluates every concrete type without an APK/device.
const COMMAND_SIZES: &[(&str, usize, bool)] = &[
    command!(app_state, return_size_4, true),
    command!(app_preferences, return_size_1, false),
    command!(app_set_close_to_tray, return_size_2, false),
    command!(app_set_dns_provider, return_size_4, false),
    command!(app_set_tic_egress_mode, return_size_3, false),
    command!(app_set_use_reserve_connection, return_size_3, true),
    command!(app_login, return_size_7, true),
    command!(app_bootstrap, return_size_6, true),
    command!(app_peer_options, return_size_1, true),
    command!(app_bind_peer, return_size_2, true),
    command!(app_unbind_peer, return_size_2, true),
    command!(app_refresh_probes, return_size_3, true),
    command!(app_prepare_tunnel, return_size_3, true),
    command!(app_windows_defender_status, return_size_1, true),
    command!(app_windows_defender_repair, return_size_1, true),
    command!(app_queue_start_failure_diagnostics, return_size_4, true),
    command!(app_start, return_size_5, true),
    command!(app_start_saved_stray, return_size_3, true),
    command!(app_stop, return_size_2, true),
    command!(app_wake_connection_intent, return_size_1, true),
    command!(app_pin_stray, return_size_1, true),
    command!(app_unpin_stray, return_size_2, true),
    command!(app_send_diagnostics, return_size_4, true),
    command!(app_record_startup_stage, return_size_2, false),
    command!(app_release_history, return_size_0, true),
    command!(app_update_status, return_size_1, true),
    command!(app_update_refresh, return_size_1, true),
    command!(app_update_set_automatic, return_size_2, true),
    command!(app_update_install, return_size_1, true),
    command!(app_update_restart, return_size_3, true),
    command!(app_runtime_switch_status, return_size_1, true),
    command!(app_runtime_switch_request, return_size_2, true),
    command!(app_runtime_switch_cancel, return_size_1, true),
    command!(runtime_status, return_size_2, true),
    command!(runtime_select, return_size_3, true),
    command!(runtime_restart, return_size_3, true),
    command!(app_split_tunnel_state, return_size_2, true),
    command!(
        app_split_tunnel_installed_applications,
        return_size_2,
        false
    ),
    command!(app_split_tunnel_save, return_size_3, true),
    command!(app_split_tunnel_refresh, return_size_3, true),
    command!(app_split_tunnel_add_address_rule, return_size_2, true),
    command!(app_split_tunnel_remove_address_rule, return_size_3, true),
    command!(app_notifications, return_size_2, true),
    command!(app_notification_read, return_size_2, true),
    command!(app_notifications_read_all, return_size_1, true),
    command!(app_register_push_token, return_size_4, true),
    command!(app_logout, return_size_4, true),
];

const _: () = assert!(COMMAND_SIZES.len() == 47);

#[test]
fn all_ipc_command_futures_fit_stack_budget() {
    // Retain the real product handler for native stack-frame inspection of the
    // release test executable. The pointer is never called: no UI/owner starts.
    type Setup = fn(&mut tauri::App) -> Result<(), Box<dyn std::error::Error>>;
    let product: fn(Setup) = crate::run_product;
    std::hint::black_box(product);
    let mut oversized = Vec::new();
    for &(name, size, asynchronous) in COMMAND_SIZES {
        println!(
            "{name}: {size} bytes ({})",
            if asynchronous { "future" } else { "response" }
        );
        if asynchronous && size > MAX_FUTURE_BYTES {
            oversized.push((name, size));
        }
    }
    assert!(
        oversized.is_empty(),
        "large futures enter JNI IPC wrappers: {oversized:?}"
    );
}

#[test]
fn stack_inventory_covers_registered_ipc_commands() {
    let source = include_str!("lib.rs");
    let registered = source
        .split("tauri::generate_handler![")
        .nth(1)
        .unwrap()
        .split("])")
        .next()
        .unwrap();
    let names: Vec<_> = registered
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("commands::")
                .map(|name| name.trim_end_matches(','))
        })
        .collect();
    assert_eq!(
        names,
        COMMAND_SIZES
            .iter()
            .map(|&(name, _, _)| name)
            .collect::<Vec<_>>()
    );
    assert_eq!(names.len(), 47);
}
