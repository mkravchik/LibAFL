# Fuzzing closed-source binary with frida

This folder contains an example fuzzer for a closed-source binary using crash detection. It is based upon frida_executable_libpng and baby_fuzzer.

Current version is single-process.

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
