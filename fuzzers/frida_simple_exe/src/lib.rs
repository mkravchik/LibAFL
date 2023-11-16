// Define DllMain following Windows ABI
use winapi;

use std::ffi::{CString, c_void, c_char};
use std::ptr::{null_mut};
use winapi::um::consoleapi::WriteConsoleA;
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::STD_OUTPUT_HANDLE;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx};
use winapi::um::processthreadsapi::{CreateRemoteThread, PROCESS_INFORMATION};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, PROCESS_ALL_ACCESS};
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::shared::ntdef::HANDLE;

use frida_gum::{Gum, NativePointer, Module};
use frida_gum::interceptor::Interceptor;
use lazy_static::lazy_static;
use std::cell::UnsafeCell;
use std::sync::Mutex;

mod fuzzer;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL_FUZZ: Mutex<UnsafeCell<Option<FuzzFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL_MAIN: Mutex<UnsafeCell<Option<MainFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL_CREATE_PROCESS: Mutex<UnsafeCell<Option<CreateProcessWFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}

type MainFunc = extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type FuzzFunc = extern "C" fn(*const c_char, u32) -> ();
type CreateProcessWFunc = unsafe extern "C" fn(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *mut c_void,
    lp_thread_attributes: *mut c_void,
    b_inherit_handles: winapi::shared::minwindef::BOOL,
    dw_creation_flags: winapi::shared::minwindef::DWORD,
    lp_environment: *mut c_void,
    lp_current_directory: *mut c_void,
    lp_startup_info: *mut c_void,
    lp_process_information: *mut c_void,
) -> winapi::shared::minwindef::BOOL;


#[cfg(windows)]
pub fn write_to_console(message: &str) {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() {
            return;
        }

        let c_message = CString::new(message).unwrap();
        let mut written = 0;

        WriteConsoleA(
            handle,
            c_message.as_ptr() as *const _,
            c_message.to_bytes().len() as u32,
            &mut written,
            null_mut(),
        );
    }
}

use std::fs::OpenOptions;
use std::io::Write;

pub fn write_to_file(message: &str, file_path: &str) {
    // Create if not exists or open for appending
    let mut file = match OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(file_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(message.as_bytes()) {
        eprintln!("Failed to write to file: {}", e);
    }
}

pub fn log(message: &str) {
    write_to_console(message);
    //Append the PID to the log file name
    let pid = std::process::id();
    let log_file_name = format!("log_{}.txt", pid);
    write_to_file(message, &log_file_name);
}

#[allow(non_snake_case)]
#[cfg(windows)]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: winapi::shared::minwindef::DWORD,
    _lpv_reserved: winapi::shared::minwindef::LPVOID,
) -> winapi::shared::minwindef::BOOL {
    log(format!("fdw_reason: {}\n", fdw_reason).as_str());
    match fdw_reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            log("DLL_PROCESS_ATTACH\n");
            // Let's cheat
            let func =
                Module::find_export_by_name(Some("test.exe"), 
                "main"//"fuzz"
            );
            let func = func.unwrap();
            if !func.is_null() {
                // log(format!("main addr: {:?}\n", main).as_str());
                // set_fuzz_hook(func);
                set_main_hook(func);
            }
    
            // Hook process creation so that we can inject the fuzzer in the new process
            let mut interceptor = Interceptor::obtain(&GUM);
            let create_process = Module::find_export_by_name(Some("kernel32.dll"),
                "CreateProcessW");
            let create_process = create_process.unwrap();
            if !create_process.is_null() {
                log(format!("CreateProcessW addr: {:p}\n", create_process.0).as_str());
                set_create_process_hook(create_process);
            }
            
        }
        winapi::um::winnt::DLL_PROCESS_DETACH => {
            log("DLL_PROCESS_DETACH\n");
        }
        winapi::um::winnt::DLL_THREAD_ATTACH => {
            log("DLL_THREAD_ATTACH\n");
        }
        winapi::um::winnt::DLL_THREAD_DETACH => {
            log("DLL_THREAD_DETACH\n");
        }
        _ => {
            log("Unknown reason\n");
        }
    }
    true as winapi::shared::minwindef::BOOL
}


pub extern "C" fn set_create_process_hook(create_proc_addr_ptr: NativePointer) -> i32 {

    let create_proc_addr_raw: *mut c_void = create_proc_addr_ptr.0;
    
    //Print the pointer's value as string
    log(format!("set_create_proc_hook got the addr: {:p}\n", create_proc_addr_raw).as_str());

    let result = Interceptor::obtain(&GUM).replace(
        create_proc_addr_ptr,
        NativePointer(create_process_detour as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_create_proc) => {
            log("Successfully replaced create_proc function\n");
            unsafe{
                *ORIGINAL_CREATE_PROCESS.lock().unwrap().get_mut() = 
                    Some(std::mem::transmute(org_create_proc));
            }
            0
        },
        Err(e) => {
            log(format!("Failed to replace create_proc function: {}\n", e).as_str());
            -1
        }
    }
}
// The detour function for CreateProcessW
unsafe extern "C" fn create_process_detour(
    lp_application_name: *const u16,
    lp_command_line: *mut u16,
    lp_process_attributes: *mut c_void,
    lp_thread_attributes: *mut c_void,
    b_inherit_handles: winapi::shared::minwindef::BOOL,
    dw_creation_flags: winapi::shared::minwindef::DWORD,
    lp_environment: *mut c_void,
    lp_current_directory: *mut c_void,
    lp_startup_info: *mut c_void,
    lp_process_information: *mut c_void,
) -> winapi::shared::minwindef::BOOL {
    log("create_process_detour called!\n");

    // Change the flag so the process is created in a suspended state
    let dw_creation_flags = dw_creation_flags | winapi::um::winbase::CREATE_SUSPENDED;
    let result = ORIGINAL_CREATE_PROCESS
        .lock()
        .unwrap()
        .get()
        .as_ref()
        .unwrap()
        .unwrap()(
                lp_application_name,
                lp_command_line,
                lp_process_attributes,
                lp_thread_attributes,
                b_inherit_handles,
                dw_creation_flags,
                lp_environment,
                lp_current_directory,
                lp_startup_info,
                lp_process_information,
            );
    if result == 0 {
        log(format!("CreateProcessW failed: {}\n", winapi::um::errhandlingapi::GetLastError()).as_str());
        return result;
    }
    
    //Get the PID of the new process from the PROCESS_INFORMATION struct
    let process_info: &PROCESS_INFORMATION =  &*(lp_process_information as *mut PROCESS_INFORMATION);
    log(format!("CreateProcessW succeeded! PID: {}\n", process_info.dwProcessId).as_str());

    // Get the process handle
    let process_handle = *(lp_process_information as *mut HANDLE);

    // Write the name of the current DLL to the newly created process
    // TODO - get the actual module name, not the hardcoded string
    let module_name = CString::new("frida_simple_exe.dll").unwrap();
    let process_name_len = module_name.as_bytes().len() + 1;

    //Allocate memory in the process for the name of the DLL
    let p_memory  = VirtualAllocEx(
        process_handle,
        null_mut(),
        process_name_len,
        MEM_COMMIT,
        PAGE_READWRITE,
    );
    if p_memory.is_null() {
        log(format!("VirtualAllocEx failed: {}\n", winapi::um::errhandlingapi::GetLastError()).as_str());
    }
    else{
        log(format!("p_memory: {:p}\n", p_memory).as_str());

        if WriteProcessMemory(process_handle, p_memory, module_name.as_ptr() as *const _,
             process_name_len, null_mut()) == 0 {
            VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
        }
        else{
            log("WriteProcessMemory succeeded!\n");

            // // Sleep for 1 minute to allow for attaching the debugger
            // std::thread::sleep(std::time::Duration::from_secs(60));

            let load_library = Module::find_export_by_name(Some("kernel32.dll"),
                "LoadLibraryA");
            let load_library = load_library.unwrap();
            log(format!("LoadLibraryA addr: {:p}\n", load_library.0).as_str());

            let h_thread = CreateRemoteThread(process_handle, null_mut(), 0,
                Some(std::mem::transmute::<_, unsafe extern "system" fn(*mut c_void) -> u32>(load_library.0 as *const ())),
                p_memory, 0, null_mut());
            if h_thread.is_null() {
                VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
                log("Failed to create remote thread");
            }
            else {
                log("CreateRemoteThread succeeded!\n");
                // Wait for the remote thread to complete, omitted for brevity
                winapi::um::synchapi::WaitForSingleObject(h_thread, winapi::um::winbase::INFINITE);
                log("Library should be injected by now!\n");
                CloseHandle(h_thread);
                VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
            }
        }
    }
    // Resume the process
    if winapi::um::processthreadsapi::ResumeThread(process_info.hThread) == winapi::shared::minwindef::DWORD::MAX {
        log(format!("ResumeThread failed: {}\n", winapi::um::errhandlingapi::GetLastError()).as_str());
        return 0;
    }
    else{
        log("ResumeThread succeeded!\n");
        return result;
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_main_hook(
    argc: i32,
    argv: *const *const u8,
    _env: *const *const u8,
) -> i32 {
    log(format!("rust_main_hook called! argc {:?}\n", argc).as_str());
    //Log all the arguments
    for i in 0..argc {
        let arg = std::ffi::CStr::from_ptr(*argv.offset(i as isize) as *const c_char).to_str().unwrap();
        log(format!("arg[{}]: {}\n", i, arg).as_str());
    }

    // Let's cheat again - finding the fuzz function
    let func =
        Module::find_export_by_name(Some("test.exe"), 
        "fuzz_internal"
    );
    let func = func.unwrap();
    if !func.is_null() {
        let func_ptr: *mut c_void = func.0;
        let fuzz_func: FuzzFunc = std::mem::transmute(func_ptr);
        fuzzer::lib(fuzz_func);
        // fuzzer::simple_lib(fuzz_func);
        // set_fuzz_hook(func);
    }
    0
    // ORIGINAL_MAIN
    // .lock()
    // .unwrap()
    // .get()
    // .as_ref()
    // .unwrap()
    // .unwrap()(argc, argv, env)
}

#[no_mangle]
pub unsafe extern "C" fn rust_fuzz_hook(
    sample_bytes: *const c_char,
    sample_size: u32
) -> () {

    log(format!("rust_fuzz_hook called! {:p} {}\n",
        // std::ffi::CStr::from_ptr(sample_bytes).to_str().unwrap()).as_str()
        sample_bytes, sample_size).as_str()
    );
    
    ORIGINAL_FUZZ
        .lock()
        .unwrap()
        .get()
        .as_ref()
        .unwrap()
        .unwrap()(sample_bytes, sample_size)
}

#[no_mangle]
pub extern "C" fn set_fuzz_hook(fuzz_addr_ptr: NativePointer) -> i32 {

    let fuzz_addr_raw: *mut c_void = fuzz_addr_ptr.0;
    
    //Print the pointer's value as string
    log(format!("set_fuzz_hook got the addr: {:p}\n", fuzz_addr_raw).as_str());

    let result = Interceptor::obtain(&GUM).replace(
        fuzz_addr_ptr,
        NativePointer(rust_fuzz_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_fuzz) => {
            log("Successfully replaced fuzz function\n");
            unsafe{
                *ORIGINAL_FUZZ.lock().unwrap().get_mut() = Some(std::mem::transmute(org_fuzz));
            }
            0
        },
        Err(e) => {
            log(format!("Failed to replace fuzz function: {}\n", e).as_str());
            -1
        }
    }
}


#[no_mangle]
// pub unsafe extern "C" fn set_main_hook(main_addr: MainFunc) -> i32 {
pub extern "C" fn set_main_hook(main_addr_ptr: NativePointer) -> i32 {

    let main_addr_raw: *mut c_void = main_addr_ptr.0;
    
    //Print the pointer's value as string
    log(format!("set_fuzz_hook got the addr: {:p}\n", main_addr_raw).as_str());

    let result = Interceptor::obtain(&GUM).replace(
        main_addr_ptr,
        NativePointer(rust_main_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_main) => {
            log("Successfully replaced main function\n");
            unsafe{
                *ORIGINAL_MAIN.lock().unwrap().get_mut() = Some(std::mem::transmute(org_main));
            }
            0
        },
        Err(e) => {
            log(format!("Failed to replace main function: {}\n", e).as_str());
            -1
        }
    }
}


pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
