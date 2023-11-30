use log::{info, warn, LevelFilter};
use std::ffi::CString;
use std::ptr::{self, null_mut};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::{DWORD,};// __some_function};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx};
use winapi::um::processthreadsapi::{CreateProcessA, CreateRemoteThread, PROCESS_INFORMATION, STARTUPINFOA, ResumeThread};//, TerminateProcess };
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{CREATE_SUSPENDED, INFINITE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};

use frida_simple_exe::StderrLogger;

#[allow(dead_code)]
fn get_kernel32_base_in_target(process_id: u32) -> Option<*mut u8> {
    let snapshot = unsafe {
         CreateToolhelp32Snapshot(TH32CS_SNAPMODULE |  TH32CS_SNAPMODULE32, process_id) 
    };

    if snapshot.is_err() {
        warn!("CreateToolhelp32Snapshot failed with error {:?}", snapshot);
        return None;
    }

    let snapshot = snapshot.unwrap();
    let mut module_entry = MODULEENTRY32::default();
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

    let kernel32_base = if unsafe { Module32First(snapshot, &mut module_entry).is_ok() } {
        let mut base: Option<*mut u8> = None;
        loop {
            if CString::new(module_entry.szModule).unwrap() == CString::new("kernel32.dll").unwrap() {
                base = Some(module_entry.modBaseAddr);
                break;
            }

            if !unsafe { Module32Next(snapshot, &mut module_entry).is_ok() } {
                break;
            }
        }
        base
    } else {
        None
    };

    unsafe { CloseHandle(std::mem::transmute::<_, *mut c_void>(snapshot)) };
    kernel32_base
}


/// The main should process its arguments: 
/// exe_name, injected_dll_name, exe_arguments
/// and spawn the target process with the arguments in a suspended state,
/// inject the dll, resume the process and wait for it to finish.
pub fn main() {
    log::set_boxed_logger(Box::new(StderrLogger))
    .map(|()| log::set_max_level(LevelFilter::Info))
    .expect("Failed to set logger");

    // Process arguments
    let exe_name = std::env::args().nth(1).expect("Missing exe_name argument");
    let injected_dll_name = std::env::args().nth(2).expect("Missing injected_dll_name argument");
    let exe_arguments: Vec<String> = std::env::args().skip(3).map(|arg| arg).collect();
    info!("{}: exe_name: {}, injected_dll_name: {}, exe_arguments: {:?}", std::process::id().to_string(), exe_name, injected_dll_name, exe_arguments);


    // Create process startup info
    let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as DWORD;

    // Create process information
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Create command line arguments
    let mut command_line = format!("{} {}\0", exe_name, exe_arguments.join(" "));
    // Spawn the target process in a suspended state using CreateProcessA
    unsafe {
        let mut startup_info: STARTUPINFOA = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as DWORD;
        startup_info.hStdInput = winapi::um::processenv::GetStdHandle(STD_INPUT_HANDLE);
        startup_info.hStdOutput = winapi::um::processenv::GetStdHandle(STD_OUTPUT_HANDLE);
        startup_info.hStdError = winapi::um::processenv::GetStdHandle(STD_ERROR_HANDLE);

        let success = CreateProcessA(
            ptr::null(),
            command_line.as_mut_ptr() as *mut i8,
            ptr::null_mut(),
            ptr::null_mut(),
            1,
            CREATE_SUSPENDED,
            ptr::null_mut(),
            ptr::null(),
            &mut startup_info,
            &mut process_info,
        );
        if success == 0 {
            panic!("Failed to spawn target process");
        }
    }

    // Get the process handle
    let process_handle = process_info.hProcess;

    // Get the thread handle
    let thread_handle = process_info.hThread;

    info!("{}: CreateProcessW succeeded! PID: {}", std::process::id().to_string(), process_info.dwProcessId);

    // Inject the DLL
    // Write the name of the current DLL to the newly created process
    let dll_name_len = injected_dll_name.as_bytes().len() + 1;

    //Allocate memory in the process for the name of the DLL
    let p_memory  = 
        unsafe{ VirtualAllocEx(
            process_handle,
            null_mut(),
            dll_name_len,
            MEM_COMMIT,
            PAGE_READWRITE,
        )};

    if p_memory.is_null() {
        warn!( "{}: VirtualAllocEx failed: {}", std::process::id().to_string(), unsafe{GetLastError()});
    }
    else{
        if unsafe{ WriteProcessMemory(process_handle, p_memory, injected_dll_name.as_ptr() as *const _,
            dll_name_len, null_mut())} == 0 {
            unsafe{VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);}
        }
        else{
            let kernel32 = CString::new("kernel32.dll").expect("CString::new failed");
            let kernel32_handle = unsafe { GetModuleHandleA(kernel32.as_ptr()) };
            let load_library_addr = unsafe { GetProcAddress(kernel32_handle, b"LoadLibraryA\0".as_ptr() as *const i8) };
            // let load_library_offset = (load_library_addr as usize) - (kernel32_handle as usize);
            let /*mut*/ target_load_library_addr = load_library_addr;
            info!("{}: LoadLibraryA addr: {:p}", std::process::id().to_string(), load_library_addr);

            // This code always fails, but I'll keep it as a reference.
            // There is some magic going on with Windows process initialization
            // We create a process suspended, and in this state, it only has the exe binary and ntdll.dll
            // What I wanted to achieve is to make sure we call LoadLibrary with its real address
            // in the target, which can be different from the current process due to ASLR.
            // However, this does not work for the processes that started suspended (https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
            // So, I'll just assume that the address is the same as in the current process.
            // Two strange things bother me: 1) is that indeed it is always at the same address despite
            // ASLR is enabled; 2) I create a thread giving it an address in kernel32, which is not loaded yet. 
            // But the thread runs, and apparently, the kernel loads kernel32 to perform CreateRemoteThread
            // I will not spend more time on this now. Letting it run up to the application entry point is a more correct solution.
            // I forgot how we did that. Maybe will look it up later. Alternative - call LdrLoadDll directly
            // // Account for ASLR
            // let kernel32_base_in_target = get_kernel32_base_in_target(process_info.dwProcessId);
            // if kernel32_base_in_target.is_none() {
            //     warn!( "{}: Failed to get kernel32 base address in target process", std::process::id().to_string());
            //     // Terminate the process
            //     // unsafe {
            //     //     TerminateProcess(process_handle, 0);
            //     // }
            //     // return;
            // }
            // else {
            //     target_load_library_addr = ((kernel32_base_in_target.unwrap() as usize) + load_library_offset) as *mut __some_function;
            //     info!("{}: LoadLibraryA addr in target: {:p}", std::process::id().to_string(), target_load_library_addr);
            // }

            let h_thread = unsafe{CreateRemoteThread(process_handle, null_mut(), 0,
                Some(std::mem::transmute::<_, unsafe extern "system" fn(*mut c_void) -> u32>(target_load_library_addr as *const ())),
                p_memory, 0, null_mut())};
            if h_thread.is_null() {
                unsafe{VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE)};
                warn!( "{}: Failed to create remote thread", std::process::id().to_string());
            }
            else {
                unsafe{
                    WaitForSingleObject(h_thread, INFINITE);
                    info!("{}: Library should be injected by now!", std::process::id().to_string());
                    CloseHandle(h_thread);
                    VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
                }
            }
        }
    }
    // // Sleep for 1 minute to allow for attaching the debugger
    // info!("You have 1 minute to look round at the process!");
    // std::thread::sleep(std::time::Duration::from_secs(60));
    // info!("Continuing!");
    // Resume the process
    unsafe{
        if ResumeThread(thread_handle) == winapi::shared::minwindef::DWORD::MAX {
            warn!( "{}: ResumeThread failed: {}", std::process::id().to_string(), GetLastError());
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
        }
        else{
            info!("{}: ResumeThread succeeded!", std::process::id().to_string());
            CloseHandle(thread_handle);

            // Wait for the process to finish
            WaitForSingleObject(process_handle, INFINITE);
            info!("{}: Process finished!", std::process::id().to_string());
            CloseHandle(process_handle);
        }    
    }
    info!("{}: Done!", std::process::id().to_string());
}

