use log::{info, warn};
use winapi::ctypes::c_void;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx};
use winapi::um::processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, CreateRemoteThread, ResumeThread};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::DWORD;
use winapi::um::winbase::{CREATE_SUSPENDED, INFINITE};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE};
use winapi::um::winbase::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
use winapi::um::synchapi::WaitForSingleObject;
use std::ptr::{self, null_mut};
use std::ffi::CString;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

/// The main should process its arguments: 
/// exe_name, injected_dll_name, exe_arguments
/// and spawn the target process with the arguments in a suspended state,
/// inject the dll, resume the process and wait for it to finish.
pub fn main() {
    // Process arguments
    let exe_name = std::env::args().nth(1).expect("Missing exe_name argument");
    let injected_dll_name = std::env::args().nth(2).expect("Missing injected_dll_name argument");
    let exe_arguments: Vec<String> = std::env::args().skip(3).collect();

    // Create process startup info
    let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as DWORD;

    // Create process information
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Create command line arguments
    let mut command_line = format!("{} {}", exe_name, exe_arguments.join(" "));

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
            // // Sleep for 1 minute to allow for attaching the debugger
            // std::thread::sleep(std::time::Duration::from_secs(60));


            let kernel32 = CString::new("kernel32.dll").expect("CString::new failed");
            let kernel32_handle = unsafe { GetModuleHandleA(kernel32.as_ptr()) };
            let load_library_addr = unsafe { GetProcAddress(kernel32_handle, b"LoadLibraryA\0".as_ptr() as *const i8) };
            info!("{}: LoadLibraryA addr: {:p}", std::process::id().to_string(), load_library_addr);

            let h_thread = unsafe{CreateRemoteThread(process_handle, null_mut(), 0,
                Some(std::mem::transmute::<_, unsafe extern "system" fn(*mut c_void) -> u32>(load_library_addr as *const ())),
                p_memory, 0, null_mut())};
            if h_thread.is_null() {
                unsafe{VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE)};
                warn!( "{}: Failed to create remote thread", std::process::id().to_string());
            }
            else {
                // Wait for the remote thread to complete, omitted for brevity
                unsafe{
                    WaitForSingleObject(h_thread, winapi::um::winbase::INFINITE);
                    info!("{}: Library should be injected by now!", std::process::id().to_string());
                    CloseHandle(h_thread);
                    VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
                }
            }
        }
    }
    // Resume the process
    unsafe{
        if ResumeThread(thread_handle) == winapi::shared::minwindef::DWORD::MAX {
            warn!( "{}: ResumeThread failed: {}", std::process::id().to_string(), GetLastError());
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
        }
        else{
            info!("{}: ResumeThread succeeded!", std::process::id().to_string());
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
        }    
    }
    info!("{}: Done!", std::process::id().to_string());
}

