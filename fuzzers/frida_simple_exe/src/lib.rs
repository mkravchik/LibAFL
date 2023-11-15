// Define DllMain following Windows ABI
use winapi;

use std::ffi::{CString, c_void, c_char};
use std::ptr::{null_mut};
use winapi::um::consoleapi::WriteConsoleA;
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::STD_OUTPUT_HANDLE;

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
}

type MainFunc = extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;
type FuzzFunc = extern "C" fn(*const c_char, u32) -> ();

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
    write_to_file(message, "log.txt");
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
        fuzzer::simple_lib(fuzz_func);
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
