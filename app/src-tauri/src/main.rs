// Desktop entry point. On mobile, tauri::mobile_entry_point in lib.rs is used instead.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    powehi_mobile_lib::run()
}
