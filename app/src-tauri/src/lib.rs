// The `mobile_entry_point` macro generates the JNI/ObjC harness for Android/iOS.
// The desktop main() in main.rs calls run() directly.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
