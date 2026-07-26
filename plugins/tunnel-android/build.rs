const COMMANDS: &[&str] = &[
    "probe",
    "request_vpn_permission",
    "start_smoke_tunnel",
    "stop_smoke_tunnel",
    "smoke_tunnel_status",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
