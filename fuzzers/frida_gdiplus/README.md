## Build

To build this example, run `cargo build --release` in this folder.

Then compile the harness `cl.exe /LD harness.cc /link /dll gdiplus.lib ole32.lib`

## Run

To run the example `target\release\frida_gdiplus.exe -H harness.dll -i corpus -o output --libs-to-instrument gdi32.dll --libs-to-instrument gdi32full.dll --libs-to-instrument gdiplus.dll --libs-to-instrument WindowsCodecs.dll --disable-excludes`

## API hooking
This fuzzer illustrates an ability to hook system APIs and to define their invocation as an objective.
All the code resides in reachability_rt.rs.
No special command line was added yet, the code is active by default. However, if the hooks.yaml (explained below) is missing - no overhead is imposed.
The hooks are defined in the hooks.yaml which should be found in the current directory (PATH will work as well). Current implementation is very limited:
1. Only 1, 2, or 3 parameters functions are supported. It is very easy to extend, but must be done in the code.
2. Conditions are not supported. 
3. Only Windows is supported as of now.

Comments and recommendations are welcome.