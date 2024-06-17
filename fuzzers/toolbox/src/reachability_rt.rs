use alloc::borrow::Cow;
use std::{
    cell::RefCell, fmt::Display, fs, marker::PhantomPinned, os::raw::c_void, path::Path, pin::Pin,
    rc::Rc,
};

use frida_gum::{interceptor::Interceptor, Gum, ModuleMap, NativePointer};
use hashbrown::HashMap;
use libafl::{
    common::{HasMetadata, HasNamedMetadata},
    corpus::Testcase,
    events::EventFirer,
    feedbacks::{Feedback, HasObserverHandle},
    inputs::{HasTargetBytes, Input},
    observers::{MapObserver, Observer, ObserversTuple, StdMapObserver},
    state::State,
    Error,
};
use libafl::{
    executors::ExitKind,
    inputs::UsesInput,
    // state::HasMetadata,
    // Error,
};
use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    HasLen, Named,
};
use libafl_frida::helper::FridaRuntime;
use rangemap::RangeMap;
//use std::os::windows::ffi::OsStringExt;
use serde::{Deserialize, Serialize};

/// The prefix of the metadata names
pub const REACHABILITYFEEDBACK_PREFIX: &str = "reachability_metadata_";

#[derive(Debug, Deserialize)]
pub struct Hooks {
    hooks: Vec<Hook>,
}

#[derive(Debug, Deserialize, Clone)]
struct Hook {
    module: String,
    api_name: String,
    #[allow(dead_code)]
    signature: String,
    num_params: u8,
    #[allow(dead_code)]
    conditions: Vec<Condition>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
struct Condition {
    logic: String,
    #[serde(rename = "type")]
    condition_type: String,
    param_index: u8,
    options_offset: Option<u8>,
    value: serde_yaml::Value,
    operator: String,
}

/// (Default) map size for reachability (TODO - convert to Vector)
pub const MAP_SIZE: usize = 256; // I'm actually using each byte as a bit

#[derive(Debug)]
struct ReachabilityRuntimeInner {
    map: [u8; MAP_SIZE],
    hooks_cnt: u32,
    hook_indices: HashMap<String, u32>,
    _pinned: PhantomPinned,
    hooks: Hooks,
}

#[derive(Debug, Clone)]
/// Tracks whether the locations of interest were reached
pub struct ReachabilityRuntime {
    inner: Pin<Rc<RefCell<ReachabilityRuntimeInner>>>,
}

// #[derive(Debug, Clone)]
// struct FunctionToHook{
//     module: String,
//     name: String,
//     params_cnt: u8,
// }

struct HookCtx {
    rt: *mut ReachabilityRuntime,
    org_fn: NativePointer,
    hook_idx: u32,
}

/// Parses `hooks.yaml`
fn parse_yaml<P: AsRef<Path> + Display>(path: P) -> Result<Hooks, Error> {
    if let Ok(content) = fs::read_to_string(&path) {
        serde_yaml::from_str(&content)
            .map_err(|e| Error::serialize(format!("Failed to deserialize yaml at {}: {}", path, e)))
    } else {
        log::warn!("File {} does not exist", path);
        Ok(Hooks { hooks: vec![] })
    }
}

impl ReachabilityRuntime {
    /// Creates a new `ReachabilityRuntime`
    pub fn new(hooks_file: Option<&str>) -> Self {
        let hooks = match hooks_file {
            Some(file) => parse_yaml(file).expect("Failed to parse hooks.yaml"),
            None => Hooks { hooks: vec![] }, // Empty hooks if no file provided
        };

        Self {
            inner: Rc::pin(RefCell::new(ReachabilityRuntimeInner {
                map: [0_u8; MAP_SIZE],
                hooks_cnt: 0,
                hook_indices: HashMap::new(),
                _pinned: PhantomPinned,
                hooks,
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
        let org_fn: unsafe fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(org_fn);
        org_fn(param1, param2)
    }

    unsafe fn replacement_three(
        param1: *mut c_void,
        param2: *mut c_void,
        param3: *mut c_void,
    ) -> *mut c_void {
        let org_fn = Self::replacement_prolog();
        let org_fn: unsafe fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(org_fn);
        org_fn(param1, param2, param3)
    }

    fn hook_with_replacement(
        &mut self,
        interceptor: &mut Interceptor,
        lib: &str,
        name: &str,
        replacement: *mut c_void,
    ) {
        log::trace!("Hooking {}", name);
        let hook_idx = self.inner.borrow().hooks_cnt;
        self.inner
            .borrow_mut()
            .hook_indices
            .insert(name.to_string(), hook_idx);
        let hook_ctx = HookCtx {
            rt: self,
            org_fn: frida_gum::Module::find_export_by_name(Some(lib), name)
                .expect("Failed to find function"),
            hook_idx,
        };
        let hook_ctx_ptr = Box::into_raw(Box::new(hook_ctx));

        interceptor
            .replace(
                frida_gum::Module::find_export_by_name(Some(lib), name)
                    .expect("Failed to find function"),
                NativePointer(replacement as *mut c_void),
                NativePointer(hook_ctx_ptr as *mut c_void),
            )
            .ok();

        self.inner.borrow_mut().hooks_cnt += 1;
        log::trace!("Hooked {}", name);
    }

    fn hook_function(&mut self, gum: &Gum, fn2hook: Hook) {
        let mut interceptor = Interceptor::obtain(gum);
        let lib = fn2hook.module;
        let name = fn2hook.api_name;
        let params_cnt = fn2hook.num_params;
        match params_cnt {
            1 => self.hook_with_replacement(
                &mut interceptor,
                &lib,
                &name,
                Self::replacement_one as *mut c_void,
            ),
            2 => self.hook_with_replacement(
                &mut interceptor,
                &lib,
                &name,
                Self::replacement_two as *mut c_void,
            ),
            3 => self.hook_with_replacement(
                &mut interceptor,
                &lib,
                &name,
                Self::replacement_three as *mut c_void,
            ),
            _ => {
                log::error!("Unsupported number of parameters for function {}", name);
            }
        }
    }

    fn hook_functions(&mut self, gum: &Gum) {
        let hooks = self.inner.borrow().hooks.hooks.clone();
        for hook in hooks {
            self.hook_function(gum, hook);
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
    fn deinit(&mut self, _gum: &Gum) {
        //TODO: remove hooks
    }
}

// Custom feedback to keep the metadata in the test case
// In order to do that I'll need:
// 1. Feedback checks with observers what's new therefore I need a new observer
// 2. This new observer needs to be familiar with the Runtime and get out of
// the APIs called during the execution on post_exec. Maybe I should add this to the state...
// 3. So the Runtime should keep the invocation information, the map is good for the API only

/// The reachability observer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReachabilityObserver {
    observer_name: Cow<'static, str>,
    base: StdMapObserver<'static, u8, false>,
    hooks: HashMap<usize, String>, // idx -> name
    invocations: Vec<String>,
}

impl ReachabilityObserver {
    /// Creates a new [`ReachabilityObserver`] with the given name.
    #[must_use]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn new<S>(observer_name: S, map: *mut u8, hooks_file: Option<&str>) -> Self
    where
        S: Into<Cow<'static, str>> + Clone,
    {
        log::info!("ReachabilityObserver created");
        let hooks = match hooks_file {
            Some(file) => parse_yaml(file).expect("Failed to parse hooks.yaml"),
            None => Hooks { hooks: vec![] }, // Empty hooks if no file provided
        };
        // let hooks_map = [
        //     (0, "LoadLibraryW"),
        //     (1, "LoadLibraryExW"),
        // ];
        // let hooks: HashMap<usize, String> = hooks_map.iter().map(|&(k, v)| (k, v.to_string())).collect();
        let hooks: HashMap<usize, String> = hooks
            .hooks
            .iter()
            .enumerate()
            .map(|(idx, hook)| (idx, hook.api_name.clone()))
            .collect();

        Self {
            observer_name: observer_name.clone().into(),
            base: unsafe { StdMapObserver::from_mut_ptr(observer_name, map, MAP_SIZE) },
            hooks,
            invocations: Vec::new(),
        }
    }

    #[must_use]
    pub fn get_invocations(&self) -> &Vec<String> {
        &self.invocations
    }
}

impl<S> Observer<S> for ReachabilityObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        // reset the invocations
        self.invocations.clear();
        // Not sure I need to do it here, all it does is to reset the map
        let _ = self.base.pre_exec(_state, _input);
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // iterate over the base items and for all set items
        // keep the names of the hooks in the invocations
        let len = self.base.len();
        for i in 0..len {
            if self.base.get(i) != 0 {
                log::info!("Detected hook {} invocation!", i);
                self.invocations.push(self.hooks.get(&i).unwrap().clone());
            }
        }
        let _ = self.base.post_exec(state, input, exit_kind);
        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for ReachabilityObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.observer_name
    }
}

/// Metadata for the reachability feedback

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReachabilityMetadata {
    name: String,
    invocations: Vec<String>,
}

impl ReachabilityMetadata {
    #[must_use]
    pub fn new(invocations: Vec<String>) -> Self {
        Self {
            name: std::any::type_name::<Self>().to_string(),
            invocations,
        }
    }
}

libafl_bolts::impl_serdeany!(ReachabilityMetadata);

/// ReachabilityFeedback
/// This feedback is used to keep the metadata in the test case
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReachabilityFeedback {
    name: Cow<'static, str>,
    o_ref: Handle<ReachabilityObserver>,
}

impl<S> Feedback<S> for ReachabilityFeedback
where
    S: State + HasNamedMetadata,
{
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        // let observer = observers
        //     .match_name::<ReachabilityObserver>(self.observer_name())
        //     .expect("A ReachabilityFeedback needs a ReachabilityObserver");

        let observer = observers
            .get(&self.o_ref)
            .expect("A ReachabilityFeedback needs a ReachabilityObserver");

        let invocations = observer.get_invocations();
        if invocations.is_empty() {
            log::info!("is not interesting");
            return Ok(false);
        }
        log::info!("is VERY interesting");
        Ok(true)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        log::info!(
            "{}: append_metadata called!",
            std::process::id().to_string()
        );
        // let observer = observers
        //     .match_name::<ReachabilityObserver>(self.observer_name())
        //     .expect("A ReachabilityFeedback needs a ReachabilityObserver");
        let observer = observers
            .get(&self.o_ref)
            .expect("A ReachabilityFeedback needs a ReachabilityObserver");

        let invocations = observer.get_invocations();
        if !invocations.is_empty() {
            testcase.add_metadata(ReachabilityMetadata::new(invocations.clone()));
        }

        Ok(())
    }
}

impl Named for ReachabilityFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl HasObserverHandle for ReachabilityFeedback {
    type Observer = ReachabilityObserver;
    #[inline]
    fn observer_handle(&self) -> &Handle<ReachabilityObserver> {
        &self.o_ref
    }
}

impl ReachabilityFeedback {
    /// Returns a new [`ReachabilityFeedback`].
    #[must_use]
    pub fn new(observer: &ReachabilityObserver) -> Self {
        Self {
            name: Cow::from(REACHABILITYFEEDBACK_PREFIX.to_string() + observer.name()),
            o_ref: observer.handle(),
        }
    }
}
