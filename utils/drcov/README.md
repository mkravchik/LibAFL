# About
This directory contains utilities for collecting and processing coverage information in DrCov format with additional capabilities.

Capabilities:
1. Counting the number of times each block was executed
1. Aggregating coverage information over time
1. Extracting BB addresses and size from PCTable 
1. Symbolization using the debug_line info

Original DrCov files have a rigid format that does not include the counters, thus the counters are contained in a companion drcov.cnt files in a binary format. On the other hand, DrCov comes with a number of useful utilities that visualise coverage and thus we keep the original format. To be precise, `drcov2lcov` converts drcov files to the lcov-formatted files, which can be converted to HTML using `genhtml`. 

# Collecting coverage
DynamoRio collects DrCov using its runtime instrumentation. In LibAFL, we support collecting it using both compile-time and runtime instrumentation. This allows for a unified backend processing and analytics.

## Static instrumentation
LibAFL uses llvm coverage instrumentation when compiling form sources. This is done by using a compiler wrapper libafl_cc that adds the needed options to the clang's command line. While regular LibAFL coverage adds just `-fsanitize-coverage=trace-pc-guard`, for DrCov coverage the libafl_cc should add `-fsanitize-coverage=pc-table,bb,trace-pc-guard`.
The meaning of the additions is: 
 - `bb` causes the compiler to instrument each basic block (the default is 'edge' which introduces artificial BBs to track the edges that are known statically).
  - `pc-table` adds to the result ELF file a section that holds offsets of each BB. Without it, trace-pc-guard instrumentation does not provide any address information, just inserts callbacks to thecoverage instrumentation.

It is also important to compile the source with the debug information (`-g`) to be able to map the addresses to the source code lines.

The accumulated counters files are created by the `AccMapObserver` that collectes the data from the same in-memory map the regular coverage uses.
See the `fuzzers/libfuzzer_libpng` in this repo for an example of how to use static DrCov collection and look into its README for more information.
See also the `fuzzers/forkserver_libafl_cc` for an example of collecting coverage from a forked process with static instrumentation.

The static instrumentation flow:
```puml
    file foo.c as src #yellow
    node libafl_cc
    file foo_exe
    folder coverage{
        artifact id_from_to.drcov
        artifact id_from_to.drcov.cnt
    }
    note as foo_exe_note
        Contains PCGuard callbacks
        and PCTable
    end note
    src -d-> libafl_cc
    libafl_cc -> foo_exe : Compilation
    foo_exe .. foo_exe_note
    foo_exe -> coverage : Created during execution
```
## Dynamic instrumentation
LibAFL uses Frida to instrument and collect coverage information. This is done by the `CoverageRuntime`. It this repo, I extended the original `CoverageRuntime` so that it can accumulate the coverage info between runs and save the counter files alongside the original DrCov files.

See the `fuzzers\frida_gdiplus` for how to use this. Most of what you need is to pass two additional parameters:
```
let coverage = CoverageRuntime::new()
    .save_dr_cov(options.save_bb_coverage)
    .max_cnt(options.drcov_max_execution_cnt);
```

The dynamic instrumentation flow:

```puml
    file foo.c as src #yellow
    component FridaCoverageRuntime #purple
    node compiler
    file foo_exe
    folder coverage{
        artifact id_from_to.drcov
        artifact id_from_to.drcov.cnt
    }
    src -d-> compiler
    compiler -> foo_exe : Compilation
    foo_exe <-d- FridaCoverageRuntime : Embedded/Injected
    foo_exe -> coverage : Created during execution
```

## Post processing
Once the .drcov and .drcov.cnt are created they can be processed to extract and analyze the coverage information.

The main utility for the post processing is merge_drcov.py:
```
usage: merge_drcov.py [-h] [-d DIRECTORY] [-od OUTPUT_DIRECTORY] [-a {s,m,h,d}] [-k] [-v] [-c] [-f] {convert,symbolize,pc-table} ...

Utility to merge files in DrCov format

positional arguments:
  {convert,symbolize,pc-table}

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Directory to process
  -od OUTPUT_DIRECTORY, --output-directory OUTPUT_DIRECTORY
                        Output directory
  -a {s,m,h,d}, --aggregate {s,m,h,d}
                        Aggregate per second|minute|hour|day
  -k, --keep            Keep the original files
  -v, --verbose         Verbose output
  -c, --counters        Generate block counters for a merged file
  -f, --fix-sizes       Disassembles the .text section of the module and fixes the basic block sizes in the drcov file
  -co, --counters-only  Generate merged files from .cnt files only. A single .drcov file must be present in the directory as a source for the modules
```
Post processing contains the following steps:
1. Merge drcov files. The files are written every X executions. We might be interested to see the total coverage, or its aggregation over time.
The simplest way to merge the files:
`python3 ../../utils/drcov/merge_drcov.py -d ./coverage`
**Notes:** 
   1. Merging will produce a `merged.drcov`, that can be processed by DrCov utilities. The produced files are in the old, version 2 format, thus some utilitites can warn about it. 
   1. In order to maintain the counters data and to be able to process it and to display it in HTML, one needs to specify `-c`. This will produce a `merged.drcov.json` file that contains the counters for each executed basic block.
   1. When using static instrumentation, the sizes of the basic blocks are unknown. This will result in wrong line coverage displayed in HTML, as only the first file of each block will have the correct counter.The `-f` option fixes the problem by extracting the BB infromation from the binary. Thus it is recommened to use `-f` option when working with static instrumentation. 
   1. By default, the original .drcov and .drcov.cnt files are deleted. `-k` will keep them after the merge.
   1. It is possible to create `merged.drcov` and `drcov.cnt` based on the `drcov.cnt` files only providing a single `.drcov` file (for the modules infromation missing from the .cnt files). This allows for more efficient distributed flow, so that you can send less files. Use `-co` for this mode, just make sure that at least one correct ``.drcov` is present. 
1. Convert Drcov to lcov. Use DynamoRio utility for that. 
**Notes:**: 
   1. make sure to use the 64 bit utility for 64 bit targets. Example: `~/DynamoRIO-Linux-10.0.19798/tools/bin64/drcov2lcov -input ./coverage/merged.drcov -output ./coverage.info -src_filter libpng-1.6.37`
   1. Version 10.0 has a bug, use a newer version
1. Correct the counters in the generated .info file. Use the `symbolize` command of the merge_drcov. This requires llvm-symbolizer installed and should be done with the `coverage.info`` produced by drcov2lcov.
`python3 ../../utils/drcov/merge_drcov.py symbolize -i ./coverage/merged.drcov.json -s /usr/lib/llvm-17/bin/llvm-symbolizer -c ./coverage.info -co ./coverage.cnt.info `
**Notes**: Use the symbolizer from new llvm. Old ones (e.g.10) will not work. Tested with llvm-17.
1. Generate the html with lines coverage. Example: `perl ~/dynamorio/third_party/lcov/genhtml --ignore-errors=source ./coverage.cnt.info -o /tmp/cov`. Browse to `/tmp/cov/index.html` to view the files.
**Notes**: Make sure the source files are accessible at the same path as they where during the collection. Look for error messages that will list the missing files, e.g. `genhtml: WARNING: cannot read /libafl-fuzz/fuzz/fuzz.c!`

The post processing flow:

```puml
    file merged.drcov
    file merged.drcov.json #lightgreen
    file coverage.info as info
    file coverage_cnt.info as info_cnt
    cloud HTML
    node merge_drcov.py as merge_drcov
    node "merge_drcov symbolize" as merge_drcov_sym    
    node drcov2lcov #lightblue
    node genhtml #lightblue

    folder coverage{
        artifact "id_from_to.drcov" as drcov
        artifact "id_from_to.drcov.cnt" as drcov_cnt
    }
    drcov --> merge_drcov
    drcov_cnt --> merge_drcov
    merge_drcov --> merged.drcov
    merge_drcov --> merged.drcov.json
    merged.drcov --> drcov2lcov
    drcov2lcov -> info
    info --> merge_drcov_sym
    merged.drcov.json --> merge_drcov_sym
    merge_drcov_sym -> info_cnt
    info_cnt --> genhtml
    genhtml -> HTML
```