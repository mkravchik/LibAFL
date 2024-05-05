# Toolbox crate 
Contains a number of useful objects to be used in fuzzers that were not common enough to make it to the upstream.

## accum_observer and AccMapObserver
Allows for accumulating coverage infromation in memory across multiple target runs and dumping them to the storage in DrCov format once in a set number of executions. See the example of usage and instructions in the `fuzzers/libfuzzer_libpng` project.
Tested on Linux only.

## crash_stack and NewHashFeedbackWithStack
Allows for collecting the crash stack and saving it into the solution's metadata.
See the example of usage in the `fuzzers/frida_gdiplus` project. 
Tested on Windows only.

## reachability_rt and ReachabilityRuntime
Allows for defining an API invocation as an objective. 
See the example of usage in the `fuzzers/frida_gdiplus` project.
Tested on Windows only.

