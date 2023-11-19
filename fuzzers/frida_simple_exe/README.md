# Fuzzing closed-source binary with frida

This folder contains an example fuzzer for a closed-source binary using crash detection. It is based upon frida_executable_libpng and baby_fuzzer.

Supports multi-core execution with restart.

It has been tested on Windows.

## Build

The initial injection is done by frida-tools. Install them with
`pip install frida-tools`
This will change and the entire thing will be done in Rust.

Build the target with `cl test\test.cpp`
Build the fuzzer with `cargo build --release`
Copy the fuzzer to the current directory: `copy /Y target\release\frida_simple_exe.dll .`

## Run
`python frida_inject.py test.exe -H test.exe`

To run on multiple CPUs use -c option, you can specify the list or cores to use or just `all`:
`python frida_inject.py test.exe -H test.exe -c 0,1,2,3`

To restart the fuzzer after the certain number of iterations use -I option:
`python frida_inject.py test.exe -H test.exe -I 10000`

Fuzzing starts when the *trigger function* is called by the application. In future, we may add
an explicit API call to start fuzzing. The trigger function should be chosen wisely, so that
all application initialization required for fuzzing is over.
You can specify the trigger function via environment variable FUZZ_TRIGGER in the format 
NAME[@OFFSET], e.g., SET FUZZ_TRIGGER=main@0x1270. See the comment at hook_trigger_func for more details.
