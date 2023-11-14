// Define DllMain following Windows ABI
use winapi;

use std::ffi::CString;
use std::ptr::{null, null_mut};
use winapi::um::consoleapi::WriteConsoleA;
use winapi::um::processenv::GetStdHandle;
use winapi::um::winbase::STD_OUTPUT_HANDLE;

// mod fuzzer;

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
