# Simple Forkserver Fuzzer

This is a simple example fuzzer to fuzz an executable instrumented by libafl_cc.

## Usage

You can build this example by running `cargo make fuzzer`.  
This compiles, libafl_cc, the fuzzer and the example harness program in
`src/program.c` with libafl_cc.  

## Run

You can run this example by running `cargo make run`. 

To run it with collecting coverage information in DrCov format do `cargo make drcov`
In order to convert the drcov data to html follow the same instructions as for libfuzzer_libpng
```shell
python3 ../../utils/drcov/merge_drcov.py -d ./coverage -c -f
~/Downloads/DynamoRIO-Linux-10.0.19798/tools/bin64/drcov2lcov -input ./coverage/merged.drcov -output ./coverage.info 
~/Downloads/DynamoRIO-Linux-10.0.19798/tools/bin64/drcov2lcov -input ./coverage/merged.drcov -output ./coverage.info -src_filter program
python3 ../../utils/drcov/merge_drcov.py symbolize -i ./coverage/merged.drcov.json -s /usr/lib/llvm-17/bin/llvm-symbolizer -c ./coverage.info -co ./coverage.cnt.info
perl ~/dynamorio/third_party/lcov/genhtml --ignore-errors=source ./coverage.cnt.info -o /tmp/cov
```
