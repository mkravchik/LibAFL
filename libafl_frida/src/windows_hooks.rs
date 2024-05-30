
// Based on the example of setting hooks: Https://github.com/frida/frida-rust/blob/main/examples/gum/hook_open/src/lib.rs
use frida_gum::{
    interceptor::{Interceptor, InvocationContext, InvocationListener},
     Gum, Module, NativePointer};
use libafl_bolts::os::windows_exceptions::{
    handle_exception, IsProcessorFeaturePresent, UnhandledExceptionFilter, EXCEPTION_POINTERS,
    PROCESSOR_FEATURE_ID,
};






struct NtAllocateVirtualMemoryListener;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref LISTENER: Mutex<NtAllocateVirtualMemoryListener> = Mutex::new(NtAllocateVirtualMemoryListener {});
}

impl InvocationListener for NtAllocateVirtualMemoryListener {
    fn on_enter(&mut self, _context: InvocationContext) {
        println!("Enter: NtAllocateVirtualMemory()");
    }

    fn on_leave(&mut self, context: InvocationContext) {
        unsafe {
            println!("Leave: NtAllocateVirtualMemory(). Args {:x} {:x} {:x} {:x} Returned {:x} to {:x}",
            context.arg(0), context.arg(1), *(context.arg(2) as *mut usize), *(context.arg(3) as *mut usize), context.return_value(), context.return_addr());
        }
    }
}

/// Initialize the hooks
pub fn initialize(gum: &Gum) {
    let is_processor_feature_present =
        Module::find_export_by_name(Some("kernel32.dll"), "IsProcessorFeaturePresent");
    let is_processor_feature_present = is_processor_feature_present.unwrap();
    if is_processor_feature_present.is_null() {
        panic!("IsProcessorFeaturePresent not found");
    }
    let unhandled_exception_filter =
        Module::find_export_by_name(Some("kernel32.dll"), "UnhandledExceptionFilter");
    let unhandled_exception_filter = unhandled_exception_filter.unwrap();
    if unhandled_exception_filter.is_null() {
        panic!("UnhandledExceptionFilter not found");
    }

    let mut interceptor = Interceptor::obtain(&gum);
    use std::ffi::c_void;

    interceptor
        .replace(
            is_processor_feature_present,
            NativePointer(is_processor_feature_present_detour as *mut c_void),
            NativePointer(std::ptr::null_mut()),
        )
        .unwrap();

    interceptor
        .replace(
            unhandled_exception_filter,
            NativePointer(unhandled_exception_filter_detour as *mut c_void),
            NativePointer(std::ptr::null_mut()),
        )
        .unwrap();


    // let memset_hook_res = interceptor.replace(
    //     Module::find_export_by_name(None, "memset").expect("Failed to find function"),
    //     NativePointer(memset_detour as *mut c_void),
    //     NativePointer(std::ptr::null_mut())
    //     );
    // match memset_hook_res {
    //     Ok(_) => {
    //         log::info!("{}: Successfully replaced memset function", std::process::id().to_string());
    //     },
    //     Err(e) => {
    //         log::warn!( "{}: Failed to replace memset function: {}", std::process::id().to_string(), e);
    //     }
    // }
        

    unsafe extern "C" fn is_processor_feature_present_detour(feature: u32) -> bool {
        let result = match feature {
            0x17 => false,
            _ => IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(feature)).as_bool(),
        };
        result
    }

    unsafe extern "C" fn unhandled_exception_filter_detour(
        exception_pointers: *mut EXCEPTION_POINTERS,
    ) -> i32 {
        handle_exception(exception_pointers);
        UnhandledExceptionFilter(exception_pointers)
    }

    // // I want to hook the following functions: memset
    // unsafe extern "C" fn  memset_detour(dest: *mut c_void, c: i32, n: usize) -> *mut c_void {
    //     log::info!("hook_memset, dest {:x}, stack: {:?}", dest as usize, Backtrace::new());
    //     extern "system" {
    //         fn memset(dest: *mut c_void, c: i32, n: usize) -> *mut c_void;
    //     }
    //     unsafe { memset(dest, c, n) }
    // }

    // unsafe extern "C" fn  virtual_alloc_detour(lp_address: *mut c_void, dw_size: usize, fl_allocation_type: u32, fl_protect: u32) -> *mut c_void {
    //     log::info!("hook_virtual_alloc, dest {:x}", lp_address as usize);
    //     // extern "system" {
    //     //     fn VirtualAlloc(lp_address: *mut c_void, dw_size: usize, fl_allocation_type: u32, fl_protect: u32) -> *mut c_void;
    //     // }
    //     let res = unsafe { VirtualAlloc(lp_address, dw_size, fl_allocation_type, fl_protect) };
    //     log::info!("hook_virtual_alloc, returned dest {:x}", res as usize);
    //     res
    // }

    // NTSTATUS (__stdcall *NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

    // #[allow(non_snake_case)]
    // unsafe extern "C" fn  nt_allocate_virtual_memory_detour(
    //     ProcessHandle: HANDLE,
    //     BaseAddress: *mut PVOID,
    //     ZeroBits: ULONG_PTR,
    //     RegionSize: *mut SIZE_T,
    //     AllocationType: ULONG,
    //     Protect: ULONG,
    // ) -> NTSTATUS {
    //     log::info!("nt_allocate_virtual_memory_detour for base {:x} and size {:x}", *BaseAddress as usize,
    //     *RegionSize);
    //     // if ((*BaseAddress as usize) < 0x160000000000) && (*RegionSize == 0x2000) {
    //     //     log::error!(" ATTACH A DEBUGGER WITHING A MINUTE to pid {}", std::process::id());
    //     //     std::thread::sleep(std::time::Duration::from_secs(60));
    //     // }
    //     extern "system" {
    //         fn NtAllocateVirtualMemory(
    //             ProcessHandle: HANDLE,
    //             BaseAddress: *mut PVOID,
    //             ZeroBits: ULONG_PTR,
    //             RegionSize: *mut SIZE_T,
    //             AllocationType: ULONG,
    //             Protect: ULONG,
    //         ) -> NTSTATUS;
    //     }
    //     let res = unsafe { NtAllocateVirtualMemory(ProcessHandle, BaseAddress,
    //         ZeroBits, RegionSize, AllocationType, Protect) };
    //     log::info!("nt_allocate_virtual_memory_detour, returned {:x}", *BaseAddress as usize);
    //     res
    // }


    // #[allow(non_snake_case)]
    // unsafe extern "C" fn  map_view_of_file_ex_detour(
    //     hFileMappingObject: HANDLE,
    //     dwDesiredAccess: DWORD,
    //     dwFileOffsetHigh: DWORD,
    //     dwFileOffsetLow: DWORD,
    //     dwNumberOfBytesToMap: SIZE_T,
    //     lpBaseAddress: LPVOID,
    // ) -> *mut c_void {
    //     log::info!("hook_map_view_of_file_ex {:p}", lpBaseAddress);
    //     let res = unsafe { MapViewOfFileEx( hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress) };
    //     log::info!("hook_map_view_of_file_ex, returned dest {:x}", res as usize);
    //     res
    // }

    // #[allow(non_snake_case)]
    // unsafe extern "C" fn  map_view_of_file_detour(
    //     hFileMappingObject: HANDLE,
    //     dwDesiredAccess: DWORD,
    //     dwFileOffsetHigh: DWORD,
    //     dwFileOffsetLow: DWORD,
    //     dwNumberOfBytesToMap: SIZE_T,
    // ) -> *mut c_void {
    //     log::info!("hook_map_view_of_file");
    //     let res = unsafe { MapViewOfFile( hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap) };
    //     log::info!("hook_map_view_of_file, returned dest {:x}", res as usize);
    //     res
    // }
 
    // pub fn heap_alloc_detour(
    //     handle: *mut c_void,
    //     flags: u32,
    //     ptr: *mut c_void,
    //     size: usize,
    // ) -> *mut c_void {
    //         log::info!("{:?}: HeapAlloc({:?}, {:}, {:?}, {:x})", std::thread::current().id(), handle, flags, ptr, size);
    //         extern "system" {
    //             fn HeapAlloc(
    //                 handle: *mut c_void,
    //                 flags: u32,
    //                 ptr: *mut c_void,
    //                 size: usize,
    //             ) -> *mut c_void;
    //         }
    //         let res = unsafe { HeapAlloc(handle, flags, ptr, size) };
    //         log::info!("HeapAlloc, returned dest {:x}", res as usize);
    //         res
    //     }

    // // Hook VirtualAlloc
    // let hook_res = interceptor.replace(
    //     Module::find_export_by_name(None, "VirtualAlloc").expect("Failed to find function"),
    //     NativePointer(virtual_alloc_detour as *mut c_void),
    //     NativePointer(std::ptr::null_mut())
    //     );
    // match hook_res {
    //     Ok(_) => {
    //         log::info!("{}: Successfully replaced VirtualAlloc function", std::process::id().to_string());
    //     },
    //     Err(e) => {
    //         log::warn!( "{}: Failed to replace VirtualAlloc function: {}", std::process::id().to_string(), e);
    //     }
    // }

    // //Hook MapViewOfFileEx
    // let hook_res = interceptor.replace(
    //     Module::find_export_by_name(Some("kernel32"), "MapViewOfFileEx").expect("Failed to find function"),
    //     NativePointer(map_view_of_file_ex_detour as *mut c_void),
    //     NativePointer(std::ptr::null_mut())
    //     );
    // match hook_res {
    //     Ok(_) => {
    //         log::info!("{}: Successfully replaced MapViewOfFileEx function", std::process::id().to_string());
    //     },
    //     Err(e) => {
    //         log::warn!( "{}: Failed to replace MapViewOfFileEx function: {}", std::process::id().to_string(), e);
    //     }
    // }

    // //Hook MapViewOfFileEx
    // let hook_res = interceptor.replace(
    //     Module::find_export_by_name(Some("kernel32"), "MapViewOfFile").expect("Failed to find function"),
    //     NativePointer(map_view_of_file_detour as *mut c_void),
    //     NativePointer(std::ptr::null_mut())
    //     );
    // match hook_res {
    //     Ok(_) => {
    //         log::info!("{}: Successfully replaced MapViewOfFile function", std::process::id().to_string());
    //     },
    //     Err(e) => {
    //         log::warn!( "{}: Failed to replace MapViewOfFile function: {}", std::process::id().to_string(), e);
    //     }
    // }

    // //Hook NtAllocateVirtualMemory
    // let hook_res = interceptor.replace(
    //     Module::find_export_by_name(Some("ntdll"), "NtAllocateVirtualMemory").expect("Failed to find function"),
    //     NativePointer(nt_allocate_virtual_memory_detour as *mut c_void),
    //     NativePointer(std::ptr::null_mut())
    //     );
    // match hook_res {
    //     Ok(_) => {
    //         log::info!("{}: Successfully replaced NtAllocateVirtualMemory function", std::process::id().to_string());
    //     },
    //     Err(e) => {
    //         log::warn!( "{}: Failed to replace NtAllocateVirtualMemory function: {}", std::process::id().to_string(), e);
    //     }
    // }

    // Hook HeapAlloc
    // let hook_res = interceptor.replace(
    //     Module::find_export_by_name(Some("kernel32"), "HeapAlloc").expect("Failed to find function"),
    //     NativePointer(heap_alloc_detour as *mut c_void),
    //     NativePointer(std::ptr::null_mut())
    //     );
    // match hook_res {
    //     Ok(_) => {
    //         log::info!("{}: Successfully replaced HeapAlloc function", std::process::id().to_string());
    //     },
    //     Err(e) => {
    //         log::warn!( "{}: Failed to replace HeapAlloc function: {}", std::process::id().to_string(), e);
    //     }
    // }
    // interceptor.attach(
    //     Module::find_export_by_name(Some("kernel32"), "HeapAlloc").expect("Failed to find function"),
    //     &mut *LISTENER.lock().unwrap());
    // interceptor.attach(
    //     Module::find_export_by_name(Some("ntdll"), "NtAllocateVirtualMemory").expect("Failed to find function"),
    //     &mut *LISTENER.lock().unwrap());

}
