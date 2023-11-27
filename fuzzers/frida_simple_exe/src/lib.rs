// Define DllMain following Windows ABI
use winapi;

use std::ffi::{CString, c_void, c_char};
use std::ptr::{null_mut};
use winapi::um::consoleapi::WriteConsoleA;
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::STD_OUTPUT_HANDLE;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualFreeEx};
use winapi::um::processthreadsapi::{CreateRemoteThread, PROCESS_INFORMATION};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, 
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::ntdef::HANDLE;

use frida_gum::{Gum, NativePointer, Module};
use frida_gum::interceptor::Interceptor;
use lazy_static::lazy_static;
use std::cell::UnsafeCell;
use std::sync::Mutex;
use std::env;
use log::{
    Record, Level, Metadata, LevelFilter, SetLoggerError,
    info, warn
};

struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

mod fuzzer;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL_ENTRY_POINT: Mutex<UnsafeCell<Option<EntryPoint>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL_FUZZ: Mutex<UnsafeCell<Option<FuzzFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL_MAIN: Mutex<UnsafeCell<Option<MainFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    static ref ORIGINAL_CREATE_PROCESS: Mutex<UnsafeCell<Option<CreateProcessWFunc>>> =
        Mutex::new(UnsafeCell::new(None));
    }

type EntryPoint = extern "C" fn() -> ();
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

// Replacing with proper Rust logging
// pub fn log(message: &str) {
//     write_to_console(message);
//     //Append the PID to the log file name
//     let pid = std::process::id();
//     let log_file_name = format!("log_{}.txt", pid);
//     write_to_file(message, &log_file_name);
// }

#[allow(non_snake_case)]
#[cfg(windows)]
#[no_mangle]
pub extern "system" fn DllMain(
    _hinst_dll: winapi::shared::minwindef::HINSTANCE,
    fdw_reason: winapi::shared::minwindef::DWORD,
    _lpv_reserved: winapi::shared::minwindef::LPVOID,
) -> winapi::shared::minwindef::BOOL {
    info!("{}: DllMain fdw_reason: {}", std::process::id().to_string(), fdw_reason.to_string());
    match fdw_reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            // Initialize a logger so that all messages created by LibAFL 
            // will be printed to stderr
            log::set_boxed_logger(Box::new(StderrLogger))
            .map(|()| log::set_max_level(LevelFilter::Info))
            .expect("Failed to set logger");


            info!("{}: DLL_PROCESS_ATTACH", std::process::id().to_string(),);

            hook_trigger_func();

            // Hook process creation so that we can inject the fuzzer in the new process
            let create_process = Module::find_export_by_name(Some("kernel32.dll"),
                "CreateProcessW");
            let create_process = create_process.unwrap();
            if !create_process.is_null() {
                info!("{}: CreateProcessW addr: {:p}", std::process::id().to_string(), create_process.0);
                set_create_process_hook(create_process);
            }
        }
        winapi::um::winnt::DLL_PROCESS_DETACH => {
            info!("{}: DLL_PROCESS_DETACH", std::process::id().to_string());
        }
        winapi::um::winnt::DLL_THREAD_ATTACH => {
            info!("{}: DLL_THREAD_ATTACH", std::process::id().to_string());
        }
        winapi::um::winnt::DLL_THREAD_DETACH => {
            info!("{}: DLL_THREAD_DETACH", std::process::id().to_string());
        }
        _ => {
            info!("{}: Unknown reason", std::process::id().to_string());
        }
    }
    true as winapi::shared::minwindef::BOOL
}

/// Hooking the fuzzing starting trigger point
/// We can start fuzzing process either when the exe entry point is called
/// or when the main function is called
/// or when the fuzz function is called
/// We distinguish between the cases by checking the value of the 
/// FUZZ_TRIGGER environment variable
/// You can set it before the injection as SET FUZZ_TRIGGER=main@0x1270
/// If it is set to "entry_point" we hook the exe entry point
/// If it is set to "main" we hook the main function
/// If it is set to anything else we hook the specified function, 
/// but it should conform to the fuzz function signature
/// In either option, we support providing the offset of the function to hook
/// as specified in the FUZZ_TRIGGER environment variable after the @ sign
/// If the offset is not provided, the function must be exported
fn hook_trigger_func() -> () {
    info!("{}: hook_trigger_func called!", std::process::id().to_string());
    let trigger_func = env::var("FUZZ_TRIGGER").unwrap_or_else(|_| "main".to_owned());
    info!("{}: FUZZ_TRIGGER: {}", std::process::id().to_string(), trigger_func);
    let trigger_func_offset = trigger_func.find("@");
    let trigger_func_name = match trigger_func_offset {
        Some(offset) => &trigger_func[..offset],
        None => &trigger_func[..]
    };
    let trigger_func_offset = match trigger_func_offset {
        Some(offset) => {
            let offset_str = &trigger_func[offset+1..];
            let offset = u64::from_str_radix(offset_str, 16);
            match offset {
                Ok(offset) => offset,
                Err(e) => {
                    warn!( "{}: Failed to parse offset: {}", std::process::id().to_string(), e);
                    0
                }
            }
        },
        None => 0
    };
    // Now call the appropriate set_XXX_hook function based on the trigger_func_name
    let exe_base = Module::find_base_address("test.exe");
    if exe_base.is_null(){
        warn!("{}: Failed to get the exe's base address", std::process::id().to_string());
    }
    match trigger_func_name {
        "entry_point" => {
            if !exe_base.is_null() {
                set_entry_point_hook(NativePointer((exe_base.0 as u64 + trigger_func_offset) as *mut c_void));
            }
        },
        "main" => {
            // if the offset is provided, we need to add it to the exe base address
            if trigger_func_offset != 0 {
                if !exe_base.is_null() {
                    set_main_hook(NativePointer((exe_base.0 as u64 + trigger_func_offset) as *mut c_void));
                }
            }
            else{
                let func =
                    Module::find_export_by_name(Some("test.exe"),
                    "main"
                );
                let func = func.unwrap();
                if !func.is_null() {
                    // log(format!("main addr: {:?}", std::process::id().to_string(), main).as_str());
                    // set_fuzz_hook(func);
                    set_main_hook(NativePointer((func.0 as u64 + trigger_func_offset) as *mut c_void));
                }
            }
        },
        _ => {
            if trigger_func_offset != 0 {
                if !exe_base.is_null() {
                    set_fuzz_hook(NativePointer((exe_base.0 as u64 + trigger_func_offset) as *mut c_void));
                }
            }
            else{
                let func =
                    Module::find_export_by_name(Some("test.exe"),
                    trigger_func_name
                );
                let func = func.unwrap();
                if !func.is_null() {
                    info!("{}: {} addr: {:p}", std::process::id().to_string(), trigger_func_name, func.0);
                    set_fuzz_hook(func);
                }
            }
        }
    }
}

//TODO - clean from the unnecessary definition parts 
#[no_mangle]
pub fn entry_point_hook(
) -> () {
    info!("{}: entry_point_hook called!", std::process::id().to_string());

    unsafe{
        start_fuzzing();

        ORIGINAL_ENTRY_POINT
        .lock()
        .unwrap()
        .get()
        .as_ref()
        .unwrap()
        .unwrap()()
    }
}

unsafe fn start_fuzzing() -> (){
    // Let's cheat again - finding the fuzz function
    // But this is not a big deal, we can work with offset as well
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
}

fn set_entry_point_hook(exe_base_addr_ptr: NativePointer) -> i32 {

    let module_base = exe_base_addr_ptr.0 as *const u8;
    
    //Print the pointer's value as string
    info!("{}: set_entry_point_hook got the addr: {:p}", std::process::id().to_string(), module_base);
    let mut entry_point_address : *const u8 = null_mut();

    unsafe{
        // The module base is a pointer to the IMAGE_DOS_HEADER
        let dos_header: &IMAGE_DOS_HEADER = &*(module_base as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != winapi::um::winnt::IMAGE_DOS_SIGNATURE {
            panic!("Invalid DOS signature");
        }

        // Calculate the address of the IMAGE_NT_HEADERS
        let nt_headers: &IMAGE_NT_HEADERS = &*(module_base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS);
        if nt_headers.Signature != winapi::um::winnt::IMAGE_NT_SIGNATURE {
            panic!("Invalid NT signature");
        }

        // The AddressOfEntryPoint is in the optional header
        entry_point_address = module_base.offset(nt_headers.OptionalHeader.AddressOfEntryPoint as isize);
    }

    info!("{}: Exe entrypoint at: {:p}", std::process::id().to_string(), entry_point_address as *const c_void);

    let result = Interceptor::obtain(&GUM).replace(
        NativePointer(entry_point_address as *mut c_void),
        NativePointer(entry_point_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_fn) => {
            info!("{}: Successfully replaced Exe entry point", std::process::id().to_string());
            unsafe{
                *ORIGINAL_ENTRY_POINT.lock().unwrap().get_mut() = 
                    Some(std::mem::transmute(org_fn));
            }
            0
        },
        Err(e) => {
            warn!( "{}: Failed to replace Exe entry point: {}", std::process::id().to_string(), e);
            -1
        }
    }
}

fn set_create_process_hook(create_proc_addr_ptr: NativePointer) -> i32 {

    let create_proc_addr_raw: *mut c_void = create_proc_addr_ptr.0;
    
    //Print the pointer's value as string
    info!("{}: set_create_proc_hook got the addr: {:p}", std::process::id().to_string(), create_proc_addr_raw);

    let result = Interceptor::obtain(&GUM).replace(
        create_proc_addr_ptr,
        NativePointer(create_process_detour as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_create_proc) => {
            info!("{}: Successfully replaced create_proc function", std::process::id().to_string());
            unsafe{
                *ORIGINAL_CREATE_PROCESS.lock().unwrap().get_mut() = 
                    Some(std::mem::transmute(org_create_proc));
            }
            0
        },
        Err(e) => {
            warn!( "{}: Failed to replace create_proc function: {}", std::process::id().to_string(), e);
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
    info!("{}: create_process_detour called!", std::process::id().to_string());

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
        warn!( "{}: CreateProcessW failed: {}", std::process::id().to_string(), winapi::um::errhandlingapi::GetLastError());
        return result;
    }
    
    //Get the PID of the new process from the PROCESS_INFORMATION struct
    let process_info: &PROCESS_INFORMATION =  &*(lp_process_information as *mut PROCESS_INFORMATION);
    info!("{}: CreateProcessW succeeded! PID: {}", std::process::id().to_string(), process_info.dwProcessId);

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
        warn!( "{}: VirtualAllocEx failed: {}", std::process::id().to_string(), winapi::um::errhandlingapi::GetLastError());
    }
    else{
        if WriteProcessMemory(process_handle, p_memory, module_name.as_ptr() as *const _,
             process_name_len, null_mut()) == 0 {
            VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
        }
        else{
            // // Sleep for 1 minute to allow for attaching the debugger
            // std::thread::sleep(std::time::Duration::from_secs(60));

            let load_library = Module::find_export_by_name(Some("kernel32.dll"),
                "LoadLibraryA");
            let load_library = load_library.unwrap();
            info!("{}: LoadLibraryA addr: {:p}", std::process::id().to_string(), load_library.0);

            let h_thread = CreateRemoteThread(process_handle, null_mut(), 0,
                Some(std::mem::transmute::<_, unsafe extern "system" fn(*mut c_void) -> u32>(load_library.0 as *const ())),
                p_memory, 0, null_mut());
            if h_thread.is_null() {
                VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
                warn!( "{}: Failed to create remote thread", std::process::id().to_string());
            }
            else {
                // Wait for the remote thread to complete, omitted for brevity
                winapi::um::synchapi::WaitForSingleObject(h_thread, winapi::um::winbase::INFINITE);
                info!("{}: Library should be injected by now!", std::process::id().to_string());
                CloseHandle(h_thread);
                VirtualFreeEx(process_handle, p_memory, 0, MEM_RELEASE);
            }
        }
    }
    // Resume the process
    if winapi::um::processthreadsapi::ResumeThread(process_info.hThread) == winapi::shared::minwindef::DWORD::MAX {
        warn!( "{}: ResumeThread failed: {}", std::process::id().to_string(), winapi::um::errhandlingapi::GetLastError());
        return 0;
    }
    else{
        info!("{}: ResumeThread succeeded!", std::process::id().to_string());
        return result;
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_main_hook(
    argc: i32,
    argv: *const *const u8,
    _env: *const *const u8,
) -> i32 {
    info!("{}: rust_main_hook called! argc {:?}", std::process::id().to_string(), argc);
    //Log all the arguments
    for i in 0..argc {
        let arg = std::ffi::CStr::from_ptr(*argv.offset(i as isize) as *const c_char).to_str().unwrap();
        info!("{}: arg[{}]: {}", std::process::id().to_string(), i, arg);
    }

    start_fuzzing();
    0
    
    // We don't call main. We start fuzzing instead
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

    info!("{}: rust_fuzz_hook called! {:p} {}", std::process::id().to_string(),
        // std::ffi::CStr::from_ptr(sample_bytes).to_str().unwrap()).as_str()
        sample_bytes, sample_size
    );
    
    start_fuzzing()
    // We don't call the original fuzz function. We start fuzzing instead    
    // ORIGINAL_FUZZ
    //     .lock()
    //     .unwrap()
    //     .get()
    //     .as_ref()
    //     .unwrap()
    //     .unwrap()(sample_bytes, sample_size)
}

#[no_mangle]
pub extern "C" fn set_fuzz_hook(fuzz_addr_ptr: NativePointer) -> i32 {

    let fuzz_addr_raw: *mut c_void = fuzz_addr_ptr.0;
    
    //Print the pointer's value as string
    info!("{}: set_fuzz_hook got the addr: {:p}", std::process::id().to_string(), fuzz_addr_raw);

    let result = Interceptor::obtain(&GUM).replace(
        fuzz_addr_ptr,
        NativePointer(rust_fuzz_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_fuzz) => {
            info!("{}: Successfully replaced fuzz function", std::process::id().to_string());
            unsafe{
                *ORIGINAL_FUZZ.lock().unwrap().get_mut() = Some(std::mem::transmute(org_fuzz));
            }
            0
        },
        Err(e) => {
            warn!( "{}: Failed to replace fuzz function: {}", std::process::id().to_string(), e);
            -1
        }
    }
}


#[no_mangle]
// pub unsafe extern "C" fn set_main_hook(main_addr: MainFunc) -> i32 {
pub extern "C" fn set_main_hook(main_addr_ptr: NativePointer) -> i32 {

    let main_addr_raw: *mut c_void = main_addr_ptr.0;
    
    //Print the pointer's value as string
    info!("{}: set_main_hook got the addr: {:p}", std::process::id().to_string(), main_addr_raw);

    let result = Interceptor::obtain(&GUM).replace(
        main_addr_ptr,
        NativePointer(rust_main_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_main) => {
            info!("{}: Successfully replaced main function", std::process::id().to_string());
            unsafe{
                *ORIGINAL_MAIN.lock().unwrap().get_mut() = Some(std::mem::transmute(org_main));
            }
            0
        },
        Err(e) => {
            warn!( "{}: Failed to replace main function: {}", std::process::id().to_string(), e);
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
