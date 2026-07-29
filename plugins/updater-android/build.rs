fn main() {
    tauri_plugin::Builder::new(&[] as &[&str])
        .android_path("android")
        .build();
}
