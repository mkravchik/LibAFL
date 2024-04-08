use libafl_frida::helper::FridaRuntime;
use frida_gum::{Gum, interceptor::Interceptor, ModuleMap, NativePointer};
use rangemap::RangeMap;
use std::os::raw::c_void;
use libafl::inputs::{Input, HasTargetBytes};
use libafl::Error;
// Temporary, I need to make this generic
use libc::c_int;

use std::{
    cell::RefCell,
    marker::PhantomPinned,
    pin::Pin,
    rc::Rc,
};
use hashbrown::HashMap;

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
    
    fn hook_functions(&mut self, gum: &Gum) {
        let mut interceptor = Interceptor::obtain(gum);

        macro_rules! hook_func {
            ($lib:expr, $name:ident, ($($param:ident : $param_type:ty),*), $return_type:ty) => {
                paste::paste! {
                    log::trace!("Hooking {}", stringify!($name));
                    extern "C" {
                        fn $name($($param: $param_type),*) -> $return_type;
                    }
                    let hook_idx = self.inner.borrow().hooks_cnt;
                    self.inner.borrow_mut().hook_indices.insert(stringify!($name).to_string(), hook_idx);
                    #[allow(non_snake_case)]
                    unsafe extern "C" fn [<replacement_ $name>]($($param: $param_type),*) -> $return_type {
                        // Set the execution in the map
                        let mut invocation = Interceptor::current_invocation();
                        let this = &mut *(invocation.replacement_data().unwrap().0 as *mut ReachabilityRuntime);
                        let cur_hook_idx = *this.inner.borrow().hook_indices.get(stringify!($name)).unwrap();
                        this.inner.borrow_mut().map[cur_hook_idx as usize] += 1;
                        log::trace!("Calling {}, hook idx {}", stringify!($name), cur_hook_idx);
                        $name($($param),*)
                    }
                    interceptor.replace(
                        frida_gum::Module::find_export_by_name($lib, stringify!($name)).expect("Failed to find function"),
                        NativePointer([<replacement_ $name>] as *mut c_void),
                        NativePointer(core::ptr::from_mut(self) as *mut c_void)
                    ).ok();
                    self.inner.borrow_mut().hooks_cnt += 1;
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            hook_func!(Some("kernel32.dll"), LoadLibraryW, (lpLibFileName: *const u16), *mut c_void);
            hook_func!(Some("kernel32.dll"), LoadLibraryExW, (lpLibFileName: *const u16, hFile: *mut c_void, dwFlags: c_int), *mut c_void);
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