fn main() {
    tauri_plugin::Builder::new(&["prepare", "confirm", "disable"])
        .android_path("android")
        .build();
}
