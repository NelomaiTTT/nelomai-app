const COMMANDS: &[&str] = &["probe", "request_vpn_permission", "tunnel_status"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
