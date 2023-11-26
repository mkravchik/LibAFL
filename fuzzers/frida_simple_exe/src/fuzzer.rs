//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use backtrace::Backtrace;
use mimalloc::MiMalloc;
use serde::{Deserialize, Serialize, Serializer, de::{self, Visitor}, Deserializer};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{path::PathBuf, fmt};

use frida_gum::Gum;
use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::{SimpleEventManager, launcher::Launcher, llmp::LlmpRestartingEventManager, EventConfig, EventRestarter, EventFirer},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback, NewHashFeedback, Feedback, HasObserverName},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes, UsesInput},
    monitors::{SimpleMonitor, MultiMonitor},
    mutators::{
        scheduled::{havoc_mutations, StdScheduledMutator},
        // token_mutations::{I2SRandReplace, Tokens},
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver, BacktraceObserver, ObserverWithHashField, ObserversTuple, HarnessType, Observer},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{StdMutationalStage},
    state::{HasCorpus, StdState, HasNamedMetadata, HasClientPerfMonitor, HasMetadata},
    Error, feedback_and,    
};
#[cfg(unix)]
use libafl::{feedback_and_fast, feedbacks::ConstFeedback};
use libafl_bolts::{
    cli::{parse_args, FuzzerOptions},
    current_nanos,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list},
    AsSlice, Named, impl_serdeany,
};
#[cfg(unix)]
use libafl_frida::asan::{
    asan_rt::AsanRuntime,
    errors::{AsanErrorsFeedback, AsanErrorsObserver, ASAN_ERRORS},
};
use libafl_frida::{
    coverage_rt::{CoverageRuntime, MAP_SIZE},
    executor::FridaInProcessExecutor,
    helper::FridaInstrumentationHelper,
};
use std::ffi::c_char;

use log::{info, warn};

/// BacktraceMetadata
/// If we use out-of-the-bix implementations for Serialize and Deserialize,
/// The stack is printed in decimal. Leave it if it is OK with you.
/// The custome serialization below shows how to serialize in hex
#[derive(Debug)]
pub struct BacktraceMetadata(Backtrace);

impl Serialize for BacktraceMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let frames = self.0.frames();
        let hex_frames: Vec<String> = frames
            .iter()
            .map(|frame| 
                {
                    let base_address = frame.module_base_address()
                        .map(|addr| format!("{:?}", addr))
                        .unwrap_or_else(|| "unknown".to_string());
                    format!("base {} ip {:?}", base_address, frame.ip())
                })
            .collect();
        let hex_string = hex_frames.join(", ");
        serializer.serialize_str(&hex_string)
    }
}

// The implementation below is not correct, as it does not actually parses 
// The string and creates frames out of it.
// However, I don't think this function is needed.
// BUT, whithout it, I get weird crashes.
struct BacktraceMetadataVisitor;

impl<'de> Visitor<'de> for BacktraceMetadataVisitor {
    type Value = BacktraceMetadata;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string representing a Backtrace")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        // Here you need to convert the string back to a Backtrace.
        // This is a placeholder implementation.
        Ok(BacktraceMetadata(Backtrace::new()))
    }
}

impl<'de> Deserialize<'de> for BacktraceMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BacktraceMetadataVisitor)
    }
}
// TODO - Can I implement Deserialize for this? I don't think i need it though
impl_serdeany!(BacktraceMetadata);

/// My custom backtrace observer wrapping BacktraceObserver
/// Keeps the backtrace and returns it to the Feedback
/// I guess I need to create a special trate for this functionality
/// I did not find any more elegant way of implementing this

#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Serialize, Deserialize, Debug)]
pub struct BacktraceObserverWithStack<'a> {
    inner: BacktraceObserver<'a> ,
    harness_type: HarnessType,
    b: Option<Backtrace>,
}

impl<'a> BacktraceObserverWithStack<'a> {
    /// Creates a new [`BacktraceObserverWithStack`] with the given name.
    #[must_use]
    pub fn new(
        observer_name: &str,
        backtrace_hash: &'a mut Option<u64>,
        harness_type: HarnessType,
    ) -> Self {
        Self {
            inner: BacktraceObserver::new(observer_name, backtrace_hash, harness_type.clone()),
            harness_type: harness_type,
            b: None
        }
    }

    //add a method that returns the backtrace
    pub fn get_backtrace(&self) -> Option<&Backtrace> {
        self.b.as_ref()
    }
}

impl<'a> ObserverWithHashField for BacktraceObserverWithStack<'a> {
    /// Gets the hash value of this observer.
    #[must_use]
    fn hash(&self) -> Option<u64> {
        self.inner.hash()
    }
}

impl<'a, S> Observer<S> for BacktraceObserverWithStack<'a>
where
    S: UsesInput,
{
    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.inner.post_exec(state, input, exit_kind)?;

        // Rest of your code...
        if self.harness_type == HarnessType::InProcess {
            if *exit_kind == ExitKind::Crash {
                self.b = Some(Backtrace::new_unresolved());
            } else {
                self.b = None;
            }
        }

        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.inner.post_exec_child(_state, _input, exit_kind)?;
        if self.harness_type == HarnessType::Child {
            if *exit_kind == ExitKind::Crash {
                self.b = Some(Backtrace::new_unresolved());
            } else {
                self.b = None;
            }
        }
        Ok(())
    }
}

impl<'a> Named for BacktraceObserverWithStack<'a> {
    fn name(&self) -> &str {
        self.inner.name()
    }
}

/// 
/// My custom feedback wrapping NewHashFeedback
/// I did not find any more elegant way of implementing this
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewHashFeedbackWithStack<O, S> (NewHashFeedback<O, S>);

impl<O, S> Feedback<S> for NewHashFeedbackWithStack<O, S>
where
    O: ObserverWithHashField + Named,
    S: UsesInput + HasNamedMetadata + HasClientPerfMonitor,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.0.init_state(state)
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &<S as UsesInput>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        //Delegate to the self.0
        self.0.is_interesting(state, _manager, _input, observers, _exit_kind)
    }

    fn append_metadata<OT>(
        &mut self,
        _state: &mut S,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
        info!( "{}: append_metadata called!", 
            std::process::id().to_string());
        let observer = observers
            .match_name::<BacktraceObserverWithStack>(&self.0.observer_name())
            .expect("A NewHashFeedbackWithStack needs a BacktraceObserverWithStack");

        match observer.get_backtrace(){
            // Performance problem here!
            Some(b)=>testcase.add_metadata(BacktraceMetadata(b.clone())),
            None=>warn!{"{}: append_metadata did not find backtrace!", 
                std::process::id().to_string()},
        }
        


        Ok(())
    }
    
}

impl<O, S> Named for NewHashFeedbackWithStack<O, S> {
    #[inline]
    fn name(&self) -> &str {
        self.0.name()
    }
}

impl<O, S> HasObserverName for NewHashFeedbackWithStack<O, S> {
    #[inline]
    fn observer_name(&self) -> &str {
        self.0.observer_name()
    }
}

impl<O, S> NewHashFeedbackWithStack<O, S>
where
    O: ObserverWithHashField + Named,
{
    /// Returns a new [`NewHashFeedbackWithStack`].
    /// Setting an observer name that doesn't exist would eventually trigger a panic.
    #[must_use]
    pub fn with_names(name: &str, observer_name: &str) -> Self {
        Self(NewHashFeedback::with_names(name, observer_name))
    }

    /// Returns a new [`NewHashFeedbackWithStack`].
    #[must_use]
    pub fn new(observer: &O) -> Self {
        Self(NewHashFeedback::new(observer))
    }

    /// Returns a new [`NewHashFeedback`] that will create a hash set with the
    /// given initial capacity.
    #[must_use]
    pub fn with_capacity(observer: &O, capacity: usize) -> Self {
        Self(NewHashFeedback::with_capacity(observer, capacity))
    }
}


/////////////////////////////////////////////////////////////
pub unsafe fn lib(target_fuzz: extern "C" fn(*const c_char, u32) -> ()) {
    color_backtrace::install();

    let options = parse_args();

    // Define the harness function
    let frida_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        // println!("Inside frida_harness, calling fuzz at {:?}", fuzz);
        target_fuzz(buf.as_ptr().cast(), buf.len() as u32);
        ExitKind::Ok
    };

    unsafe {
        match fuzz(&options, &frida_harness) {
            Ok(()) | Err(Error::ShuttingDown) => println!("\nFinished fuzzing. Good bye."),
            Err(e) => panic!("Error during fuzzing: {e:?}"),
        }
    }
}

/// The actual fuzzer
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
unsafe fn fuzz(
    options: &FuzzerOptions,
    mut frida_harness: &dyn Fn(&BytesInput) -> ExitKind,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    let shmem_provider = StdShMemProvider::new()?;

    let mut run_client = |state: Option<_>, mgr: LlmpRestartingEventManager<_, _>, core_id| {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.

        // println!("{:?}", mgr.mgr_id());
        (|state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
            let gum = Gum::obtain();

            let coverage = CoverageRuntime::new();

            let mut frida_helper =
                FridaInstrumentationHelper::new(&gum, options, tuple_list!(coverage));

            // Create an observation channel using the coverage map
            let edges_observer = HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
                "edges",
                frida_helper.map_mut_ptr().unwrap(),
                MAP_SIZE,
            ));

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_or!(
                // New maximization map feedback linked to the edges observer and the feedback state
                // pub fn tracking(map_observer: &O, track_indexes: bool, track_novelties: bool) -> Self {
                MaxMapFeedback::tracking(&edges_observer, true, false),
                // Time feedback, this one does not need a feedback state
                TimeFeedback::with_observer(&time_observer)
            );

            let mut bt = None;
            let bt_observer = BacktraceObserverWithStack::new(
                "BacktraceObserver",//TODO - change?
                &mut bt,
                libafl::observers::HarnessType::InProcess,
            );
        
            // A feedback to choose if an input is a solution or not
            #[cfg(windows)]
            // let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
            let mut objective = 
                feedback_or_fast!(TimeoutFeedback::new(),
                feedback_and!(CrashFeedback::new(), NewHashFeedbackWithStack::new(&bt_observer))
            );

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    // RNG
                    StdRand::with_seed(current_nanos()),
                    // Corpus that will be evolved, we keep it in memory for performance
                    CachedOnDiskCorpus::new(PathBuf::from("./corpus_discovered"), 64)
                        .unwrap(),
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(options.output.clone()).unwrap(),
                    &mut feedback,
                    &mut objective,
                )
                .unwrap()
            });

            println!("We're a client, let's fuzz :)");

            // Setup a basic mutator with a mutational stage
            let mutator = StdScheduledMutator::new(havoc_mutations());//.merge(tokens_mutations()));

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            #[cfg(windows)]
            let observers = tuple_list!(edges_observer, time_observer, bt_observer);

            // Create the executor for an in-process function with just one observer for edge coverage
            let mut executor = FridaInProcessExecutor::new(
                &gum,
                InProcessExecutor::new(
                    &mut frida_harness,
                    observers,
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                )?,
                &mut frida_helper,
            );

            // Generator of printable bytearrays of max size 32
            let mut generator = RandPrintablesGenerator::new(32);

            // In case the corpus is empty (on first run), reset
            if state.must_load_initial_inputs() {
                // TODO - check this!
                // state
                //     .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &options.input)
                //     .unwrap_or_else(|_| {
                //         panic!("Failed to load initial corpus at {:?}", &options.input)
                //     });
                // println!("We imported {} inputs from disk.", state.corpus().count());
                state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
                .expect("Failed to generate the initial corpus");
            }

            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            // If the number of iterations was provided, call fuzz_loop_iterations
            // otherwise call fuzz_loop indefinitely
            info!( "{}: Starting the fuzzer on core {:?} for {} iterations\n",
                std::process::id().to_string(), 
                core_id, options.iterations);
            if options.iterations > 0 {
                fuzzer.fuzz_loop_for(
                    &mut stages,
                    &mut executor,
                    &mut state,
                    &mut mgr,
                    options.iterations.try_into().unwrap(),
                )?;
                mgr.on_restart(&mut state)?;
                info!( "{}: Restarting the fuzzer", std::process::id().to_string());
            } else {
                fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
            }

            Ok(())
        })(state, mgr, core_id)
    };

    Launcher::builder()
        .configuration(EventConfig::AlwaysUnique)
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&options.cores)
        .broker_port(options.broker_port)
        .stdout_file(Some(&options.stdout))
        .remote_broker_addr(options.remote_broker_addr)
        .build()
        .launch()
}


// Simplest possible fuzzer based on baby-fuzzer and frida_executable_libpng
pub unsafe fn simple_lib(fuzz: extern "C" fn(*const c_char, u32) -> ()) {
    println!("simple_lib !!!");
    
    let options = parse_args();

    // Define the harness function
    let mut frida_harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        // println!("Inside frida_harness, calling fuzz at {:?}", fuzz);
        fuzz(buf.as_ptr().cast(), buf.len() as u32);
        ExitKind::Ok
    };

    // Create the state. For the state we need feedbacks and objectives
    // Instead of the ones used in baby_fuzzer, use the ones from frida_executable_libpng
    let gum = Gum::obtain();

    let coverage = CoverageRuntime::new();

    let mut frida_helper =
        FridaInstrumentationHelper::new(&gum, &options, tuple_list!(coverage));

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
        "edges",
        frida_helper.map_mut_ptr().unwrap(),
        MAP_SIZE,
    ));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::tracking(&edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::with_observer(&time_observer)
    );

    #[cfg(windows)]
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // If not restarting, create a State from scratch
    let mut state = StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            CachedOnDiskCorpus::no_meta(PathBuf::from("./corpus_discovered"), 64)
                .unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(options.output.clone()).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();


    // // A queue policy to get testcasess from the corpus
    // let scheduler = QueueScheduler::new();
    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    #[cfg(windows)]
    let observers = tuple_list!(edges_observer, time_observer,);

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = FridaInProcessExecutor::new(
        &gum,
        InProcessExecutor::new(
            &mut frida_harness,
            observers,
            &mut fuzzer,
            &mut state,
            &mut mgr,
        ).expect("Failed to create the InProcessExecutor"),
        &mut frida_helper,
    );

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    // TODO - load from disk
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}