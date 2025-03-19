use std::ptr;
use std::ffi::CString;
use std::fs::File;
use std::io::prelude::*;
use std::thread;
use std::time::Duration;
use std::sync::mpsc;
use std::ptr::null_mut;
use windows::Win32::Foundation::{HANDLE, ERROR_SUCCESS};
// use windows::Win32::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION};
use windows::Win32::System::Registry::{RegOpenKeyExA, RegNotifyChangeKeyValue, HKEY, HKEY_LOCAL_MACHINE, REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_CHANGE_LAST_SET, KEY_READ};
// use windows::Win32::Storage::FileSystem::{ReadDirectoryChangesW, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_SIZE, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, FILE_NOTIFY_INFORMATION};
use windows::Win32::System::Threading::{CreateThread, LPTHREAD_START_ROUTINE};
use windows::core::PCSTR;

fn monitor_registry() {
    unsafe {
        let mut h_key: HKEY = HKEY(null_mut());
        let subkey = CString::new("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run").unwrap();
        let subkey_pointer = subkey.as_ptr() as *const i8;

        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            PCSTR(subkey_pointer as _),
            Some(0),
            KEY_READ,
            &mut h_key,
        ).is_err() {
            println!("❌ Failed to open registry key.");
            return;
        }

        loop {
            let result = RegNotifyChangeKeyValue(
                h_key,
                false,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                Some(HANDLE(null_mut())),
                false,
            );

            if result == ERROR_SUCCESS {
                println!("🛠️ Registry change detected!");
            } else {
                println!("❌ Error monitoring registry.");
                break;
            }

            thread::sleep(Duration::from_secs(2));
        }
    }
}

fn main() {
    // Registry Monitoring Thread
    let registry_thread = thread::spawn(|| {
        monitor_registry();
    });
    registry_thread.join().unwrap();

}