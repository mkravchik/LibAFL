// Define DllMain following Windows ABI
use winapi;

use std::ffi::{CString, c_void, c_char};
use std::mem::transmute;

use std::ptr::{null, null_mut};
use winapi::um::consoleapi::WriteConsoleA;
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::STD_OUTPUT_HANDLE;

use frida_gum::{Gum, NativePointer, Module};
use frida_gum::interceptor::Interceptor;
// mod fuzzer;
use lazy_static::lazy_static;
use std::cell::UnsafeCell;
use std::sync::Mutex;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
    static ref ORIGINAL_FUZZ: Mutex<UnsafeCell<Option<FuzzFunc>>> =
        Mutex::new(UnsafeCell::new(None));
}
type FuzzFunc = extern "C" fn(*const c_char) -> ();

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
                "fuzz"
            );
            let func = func.unwrap();
            if !func.is_null() {
                // log(format!("main addr: {:?}\n", main).as_str());
                unsafe{
                    // set_main_hook(main);
                    set_fuzz_hook(func);
                }
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

type MainFunc = extern "C" fn(i32, *const *const u8, *const *const u8) -> i32;

#[no_mangle]
pub unsafe extern "C" fn main_hook(main_addr: MainFunc) -> i32 {
    // fuzzer::lib(ORIG_MAIN);
    log(format!("main_hook got the main addr: {:?}\n", main_addr).as_str());
    let arg0 = CString::new("test.exe").unwrap();
    let arg1 = CString::new("-f").unwrap();
    let arg2 = CString::new("@@").unwrap();

    let argv: [*const u8; 3] = [
        arg0.as_ptr().cast(), 
        arg1.as_ptr().cast(),
        arg2.as_ptr().cast(),
    ];

    let env: [*const u8; 2] = [
        null(), // dummy value
        null(), // dummy value
    ];

    log(format!(">>>> Inside main_hook, calling main at {:?}\n", main_addr).as_str());
    let res = main_addr(3, argv.as_ptr(), env.as_ptr());
    log(format!("<<<< Inside main_hook, main returned {:?}\n", res).as_str());

    // fuzzer::lib(main_addr);
    42
}

extern "C" fn _dummy_main(_argc: i32, _argv: *const *const u8, _env: *const *const u8) -> i32 {
    0
}

static mut ORIG_MAIN: MainFunc = _dummy_main;

#[no_mangle]
pub unsafe extern "C" fn rust_main_hook(
    argc: i32,
    argv: *const *const u8,
    env: *const *const u8,
) -> i32 {
    // fuzzer::lib(ORIG_MAIN);
    log(format!("rust_main_hook called! argc {:?}\n", argc).as_str());
    ORIG_MAIN(argc, argv, env)
}

#[no_mangle]
pub unsafe extern "C" fn rust_fuzz_hook(
    name: *const c_char,
) -> () {

    log(format!("rust_fuzz_hook called! {}\n",
        std::ffi::CStr::from_ptr(name).to_str().unwrap()).as_str());
    ORIGINAL_FUZZ
        .lock()
        .unwrap()
        .get()
        .as_ref()
        .unwrap()
        .unwrap()(name)
}

#[no_mangle]
pub unsafe extern "C" fn set_fuzz_hook(fuzz_addr_ptr: NativePointer) -> i32 {

    let fuzz_addr_raw: *mut c_void = fuzz_addr_ptr.0;
    let fuzz_addr: FuzzFunc = transmute(fuzz_addr_raw);

    log(format!("set_fuzz_hook got the addr: {:?}\n", fuzz_addr).as_str());
 
    
    let result = Interceptor::obtain(&GUM).replace(
        fuzz_addr_ptr,
        NativePointer(rust_fuzz_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(org_fuzz) => {
            log("Successfully replaced fuzz function\n");
            *ORIGINAL_FUZZ.lock().unwrap().get_mut() = Some(std::mem::transmute(org_fuzz));
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
pub unsafe extern "C" fn set_main_hook(main_addr_ptr: NativePointer) -> i32 {
    // fuzzer::lib(ORIG_MAIN);

    let main_addr_raw: *mut c_void = main_addr_ptr.0;
    let main_addr: MainFunc = transmute(main_addr_raw);

    log(format!("set_main_hook got the main addr: {:?}\n", main_addr).as_str());
    
    ORIG_MAIN = main_addr; // I should undo it is the hook failed

    let gum = unsafe { Gum::obtain() };

    let result = Interceptor::obtain(&gum).replace(
        NativePointer(main_addr as *mut c_void),
        NativePointer(rust_main_hook as *mut c_void),
        NativePointer(std::ptr::null_mut()),
    );

    match result {
        Ok(_) => {
            log("Successfully replaced function\n");
            0
        },
        Err(e) => {
            log(format!("Failed to replace function: {}\n", e).as_str());
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
