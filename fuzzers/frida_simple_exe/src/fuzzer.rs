//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use std::{path::PathBuf};

use frida_gum::Gum;
use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{SimpleEventManager, launcher::Launcher, llmp::LlmpRestartingEventManager, EventConfig, EventRestarter},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback, NewHashFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::{SimpleMonitor, MultiMonitor},
    mutators::{
        scheduled::{havoc_mutations, StdScheduledMutator},
        // token_mutations::{I2SRandReplace, Tokens},
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver, BacktraceObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::{StdMutationalStage},
    state::{HasCorpus, StdState},
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
    AsSlice,
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

use log::info;

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
            let bt_observer = BacktraceObserver::new(
                "BacktraceObserver",
                &mut bt,
                libafl::observers::HarnessType::InProcess,
            );
        
            // A feedback to choose if an input is a solution or not
            #[cfg(windows)]
            // let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());
            let mut objective = 
                feedback_or_fast!(TimeoutFeedback::new(),
                feedback_and!(CrashFeedback::new(), NewHashFeedback::new(&bt_observer))
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