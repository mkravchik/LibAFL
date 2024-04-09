use libafl_frida::helper::FridaRuntime;
use frida_gum::{Gum, interceptor::Interceptor, ModuleMap, NativePointer};
use rangemap::RangeMap;
use std::os::raw::c_void;
use libafl::inputs::{Input, HasTargetBytes};
use libafl::Error;

use std::{
    cell::RefCell,
    marker::PhantomPinned,
    pin::Pin,
    rc::Rc,
};
use hashbrown::HashMap;
//use std::os::windows::ffi::OsStringExt;

/// (Default) map size for reachability (TODO - convert to Vector)
pub const MAP_SIZE: usize = 256; // I'm actually using each byte as a bit

#[derive(Debug)]
struct ReachabilityRuntimeInner {
    map: [u8; MAP_SIZE],
    hooks_cnt: u32,
    hook_indices: HashMap<String, u32>,
    _pinned: PhantomPinned,
}

#[derive(Debug, Clone)]
/// Tracks whether the locations of interest were reached
pub struct ReachabilityRuntime {
    inner: Pin<Rc<RefCell<ReachabilityRuntimeInner>>>,
}

#[derive(Debug, Clone)]
struct FunctionToHook{
    module: String,
    name: String,
    params_cnt: u8,
}

struct HookCtx{
    rt: *mut ReachabilityRuntime,
    org_fn: NativePointer,
    hook_idx: u32,    
}

impl ReachabilityRuntime {
    /// Creates a new `ReachabilityRuntime`
    pub fn new() -> Self {
        Self {
            inner: Rc::pin(RefCell::new(ReachabilityRuntimeInner {
                map: [0_u8; MAP_SIZE],
                hooks_cnt: 0,
                hook_indices: HashMap::new(),
                _pinned: PhantomPinned,
            })),
        }
    }

    /// Retrieve the reachability map pointer
    pub fn map_mut_ptr(&mut self) -> *mut u8 {
        self.inner.borrow_mut().map.as_mut_ptr()
    }
    
    unsafe fn replacement_prolog() -> *mut c_void {
        // Set the execution in the map
        let mut invocation = Interceptor::current_invocation();

        // I need to update the map
        let ctx = &*(invocation.replacement_data().unwrap().0 as *const HookCtx);
        let this = &*ctx.rt;
        let cur_hook_idx = ctx.hook_idx;
        this.inner.borrow_mut().map[cur_hook_idx as usize] += 1;
        log::trace!("Calling hook idx {}", cur_hook_idx);
        ctx.org_fn.into()
    }

    unsafe fn replacement_one(param1: *mut c_void) -> *mut c_void {

        // // Log the passed parameter as a wide char string
        // let len = (0..).take_while(|&i| *(param1 as *const u16).offset(i) != 0).count();
        // let param1_str = std::ffi::OsString::from_wide(std::slice::from_raw_parts(param1 as *const u16, len))
        //     .into_string()
        //     .unwrap_or_else(|_| String::from("Invalid wide char string"));
        // log::trace!("Param1: {}", param1_str);

        let org_fn = Self::replacement_prolog();
        // I need to call the original function
        let org_fn: unsafe fn(*mut c_void) -> *mut c_void = std::mem::transmute(org_fn);
        org_fn(param1)
    }

    unsafe fn replacement_two(param1: *mut c_void, param2: *mut c_void) -> *mut c_void {
        let org_fn = Self::replacement_prolog();
        let org_fn: unsafe fn(*mut c_void, *mut c_void) -> *mut c_void = std::mem::transmute(org_fn);
        org_fn(param1, param2)
    }

    unsafe fn replacement_three(param1: *mut c_void, param2: *mut c_void, param3: *mut c_void) -> *mut c_void {
        let org_fn = Self::replacement_prolog();
        let org_fn: unsafe fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void = std::mem::transmute(org_fn);
        org_fn(param1, param2, param3)
    }

    
    fn hook_with_replacement(&mut self, interceptor: &mut Interceptor, lib: &str, name: &str, replacement: *mut c_void) {
        log::trace!("Hooking {}", name);
        let hook_idx = self.inner.borrow().hooks_cnt;
        self.inner.borrow_mut().hook_indices.insert(name.to_string(), hook_idx);
        let hook_ctx = HookCtx {
            rt: self,
            org_fn: frida_gum::Module::find_export_by_name(Some(&lib), &name).expect("Failed to find function"),
            hook_idx: hook_idx,
        };
        let hook_ctx_ptr = Box::into_raw(Box::new(hook_ctx));
    
        interceptor.replace(
            frida_gum::Module::find_export_by_name(Some(&lib), &name).expect("Failed to find function"),
            NativePointer(replacement as *mut c_void),
            NativePointer(hook_ctx_ptr as *mut c_void)
        ).ok();
    
        self.inner.borrow_mut().hooks_cnt += 1;
        log::trace!("Hooked {}", name);
    }
    
    fn hook_function(&mut self, gum: &Gum, fn2hook: FunctionToHook) {
        let mut interceptor = Interceptor::obtain(gum);
        let lib = fn2hook.module;
        let name = fn2hook.name;
        let params_cnt = fn2hook.params_cnt;        
        match params_cnt {
            1 => self.hook_with_replacement(&mut interceptor, &lib, &name, Self::replacement_one as *mut c_void),
            2 => self.hook_with_replacement(&mut interceptor, &lib, &name, Self::replacement_two as *mut c_void),
            3 => self.hook_with_replacement(&mut interceptor, &lib, &name, Self::replacement_three as *mut c_void),
            _ => {
                log::error!("Unsupported number of parameters for function {}", name);
                return;
            }
        }
    }

    fn hook_functions(&mut self, gum: &Gum) {
        // let mut interceptor = Interceptor::obtain(gum);

        // macro_rules! hook_func {
        //     ($lib:expr, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
        //         paste::paste! {
        //             log::trace!("Hooking {}", stringify!($name));
        //             extern "C" {
        //                 fn $name($($param: $param_type),*) -> $return_type;
        //             }
        //             let hook_idx = self.inner.borrow().hooks_cnt;
        //             self.inner.borrow_mut().hook_indices.insert(stringify!($name).to_string(), hook_idx);
        //             #[allow(non_snake_case)]
        //             unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
        //                 // Set the execution in the map
        //                 let mut invocation = Interceptor::current_invocation();
        //                 let this = &mut *(invocation.replacement_data().unwrap().0 as *mut ReachabilityRuntime);
        //                 let cur_hook_idx = *this.inner.borrow().hook_indices.get(stringify!($name)).unwrap();
        //                 this.inner.borrow_mut().map[cur_hook_idx as usize] += 1;
        //                 log::trace!("Calling {}, hook idx {}", stringify!($name), cur_hook_idx);
        //                 $name($($param),*)
        //             }
        //             interceptor.replace(
        //                 frida_gum::Module::find_export_by_name($lib, stringify!($name)).expect("Failed to find function"),
        //                 NativePointer([<replacement_ $name>] as *mut c_void),
        //                 NativePointer(core::ptr::from_mut(self) as *mut c_void)
        //             ).ok();
        //             self.inner.borrow_mut().hooks_cnt += 1;
        //         }
        //     }
        // }

        #[cfg(target_os = "windows")]
        {
            let functions_to_hook = vec![
                FunctionToHook {
                    module: "kernel32.dll".to_string(),
                    name: "LoadLibraryW".to_string(),
                    params_cnt: 1,
                },
                FunctionToHook {
                    module: "kernel32.dll".to_string(),
                    name: "LoadLibraryExW".to_string(),
                    params_cnt: 3,
                },
            ];    
            for to_hook in functions_to_hook {
                self.hook_function(gum, to_hook);
            }

            // hook_func!(Some("kernel32.dll"), LoadLibraryW, (lpLibFileName: *const u16), *mut c_void);
            // hook_func!(Some("kernel32.dll"), LoadLibraryExW, (lpLibFileName: *const u16, hFile: *mut c_void, dwFlags: c_int), *mut c_void);
        }
        log::info!("Hooked {} functions", self.inner.borrow().hooks_cnt);
    }
}

impl FridaRuntime for ReachabilityRuntime {    
    /// initializes this runtime with the list of places to hook
    fn init(
        &mut self,
        gum: &Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
        log::info!("ReachabilityRuntime created");
        self.hook_functions(gum);
    }

    /// Called before execution, does nothing
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called after execution, does nothing
    fn post_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }
    
}