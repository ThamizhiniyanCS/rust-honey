use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::prelude::*;
use std::ptr;
use std::ptr::null_mut;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
// use windows::Win32::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_PROCESS_INFORMATION};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_FLAG_BACKUP_SEMANTICS, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_NOTIFY_INFORMATION, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    ReadDirectoryChangesW,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    RegNotifyChangeKeyValue, RegOpenKeyExA,
};
use windows::Win32::System::Threading::{
    CreateThread, GetProcessId, LPTHREAD_START_ROUTINE, OpenProcess, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};
use windows::core::PCSTR;

fn get_process_info(pid: u32) -> Option<(String, u32, String)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32 {
            dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
            ..Default::default()
        };

        if Process32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    let cstr = unsafe { CStr::from_ptr(entry.szExeFile.as_ptr()) };
                    let process_name = cstr.to_string_lossy().to_string();
                    let parent_pid = entry.th32ParentProcessID;
                    return Some((
                        process_name,
                        parent_pid,
                        format!("PID: {}, PPID: {}", pid, parent_pid),
                    ));
                }
                if Process32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
    }
    None
}

/// Monitor file system changes using ReadDirectoryChangesW
fn monitor_files(directory: &str) {
    unsafe {
        let dir = CString::new(directory).unwrap();
        let handle = CreateFileA(
            PCSTR(dir.as_ptr() as *const u8), // Correct conversion
            FILE_LIST_DIRECTORY.0,            // Correct access mode
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, // Corrected security attributes
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None, // Corrected template file
        )
        .unwrap_or_else(|_| HANDLE::default()); // Handle error properly

        if handle.0.is_null() {
            println!("❌ Failed to open directory: {}", directory);
            return;
        }

        let mut buffer = [0u8; 1024];
        loop {
            let mut bytes_returned = 0;
            let success = ReadDirectoryChangesW(
                handle,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer.len() as u32,
                true.into(),
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
                Some(&mut bytes_returned),
                None,
                None,
            );

            if let Ok(_) = success {
                let pid = GetProcessId(handle); // Get process ID of last modification
                if let Some((process_name, parent_pid, details)) = get_process_info(pid) {
                    println!(
                        "📂 Change detected in {} | Process: {} | {}",
                        directory, process_name, details
                    );
                } else {
                    println!(
                        "📂 Change detected in {}, but process info unavailable",
                        directory
                    );
                }
            } else {
                println!("❌ Error monitoring directory");
            }

            thread::sleep(Duration::from_secs(2));
        }
    }
}

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
        )
        .is_err()
        {
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
    // File Monitoring Thread
    let file_thread = thread::spawn(|| {
        monitor_files("C:\\Users\\IronMan\\Desktop\\");
    });

    // Registry Monitoring Thread
    let registry_thread = thread::spawn(|| {
        monitor_registry();
    });

    registry_thread.join().unwrap();
    file_thread.join().unwrap();
}
