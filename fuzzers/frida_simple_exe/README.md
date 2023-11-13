# Fuzzing closed-source binary with frida

This folder contains an example fuzzer for a closed-source binary, using LLMP for fast multi-process fuzzing and crash detection. It is based upon frida_executable_libpng.

It has been tested on Windows.

## Build

The initial injection is done by frida-tools. Install them with
`pip install frida-tools`

## Run

