# Libfuzzer for libpng

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection.

In contrast to other fuzzer examples, this setup uses `fuzz_loop_for`, to occasionally respawn the fuzzer executor.
While this costs performance, it can be useful for targets with memory leaks or other instabilities.
If your target is really instable, however, consider exchanging the `InProcessExecutor` for a `ForkserverExecutor` instead.

It also uses the `introspection` feature, printing fuzzer stats during execution.

To show off crash detection, we added a `ud2` instruction to the harness, edit harness.cc if you want a non-crashing example.
It has been tested on Linux.

## Build

To build this example, run

```bash
cargo build --release
```

This will build the library with the fuzzer (src/lib.rs) with the libfuzzer compatibility layer and the SanitizerCoverage runtime functions for coverage feedback.
In addition, it will also build two C and C++ compiler wrappers (bin/libafl_c(libafl_c/xx).rs) that you must use to compile the target.

The compiler wrappers, `libafl_cc` and `libafl_cxx`, will end up in `./target/release/` (or `./target/debug`, in case you did not build with the `--release` flag).

Then download libpng, and unpack the archive:
```bash
wget https://github.com/glennrp/libpng/archive/refs/tags/v1.6.37.tar.gz
tar -xvf v1.6.37.tar.gz
```

Now compile libpng, using the libafl_cc compiler wrapper:

```bash
cd libpng-1.6.37
./configure --enable-shared=no --with-pic=yes --enable-hardware-optimizations=yes
make CC="$(pwd)/../target/release/libafl_cc" CXX="$(pwd)/../target/release/libafl_cxx" -j `nproc`
```

You can find the static lib at `libpng-1.6.37/.libs/libpng16.a`.

Now, we have to build the libfuzzer harness and link all together to create our fuzzer binary.

```
cd ..
./target/release/libafl_cxx ./harness.cc libpng-1.6.37/.libs/libpng16.a -I libpng-1.6.37/ -o fuzzer_libpng -lz -lm
```

Afterward, the fuzzer will be ready to run.
Note that, unless you use the `launcher`, you will have to run the binary multiple times to actually start the fuzz process, see `Run` in the following.
This allows you to run multiple different builds of the same fuzzer alongside, for example, with and without ASAN (`-fsanitize=address`) or with different mutators.

## Run

The first time you run the binary, the broker will open a tcp port (currently on port `1337`), waiting for fuzzer clients to connect. This port is local and only used for the initial handshake. All further communication happens via shared map, to be independent of the kernel. Currently, you must run the clients from the libfuzzer_libpng directory for them to be able to access the PNG corpus.

```
./fuzzer_libpng

[libafl/src/bolts/llmp.rs:407] "We're the broker" = "We\'re the broker"
Doing broker things. Run this tool again to start fuzzing in a client.
```

And after running the above again in a separate terminal:

```
[libafl/src/bolts/llmp.rs:1464] "New connection" = "New connection"
[libafl/src/bolts/llmp.rs:1464] addr = 127.0.0.1:33500
[libafl/src/bolts/llmp.rs:1464] stream.peer_addr().unwrap() = 127.0.0.1:33500
[LOG Debug]: Loaded 4 initial testcases.
[New Testcase #2] clients: 3, corpus: 6, objectives: 0, executions: 5, exec/sec: 0
< fuzzing stats >
```

As this example uses in-process fuzzing, we added a Restarting Event Manager (`setup_restarting_mgr`).
This means each client will start itself again to listen for crashes and timeouts.
By restarting the actual fuzzer, it can recover from these exit conditions.

In any real-world scenario, you should use `taskset` to pin each client to an empty CPU core, the lib does not pick an empty core automatically (yet).

## Saving precise BB hitcounts in DrCov format
The sample illustrates how can one save the precise number of hitcounts during fuzzing campain.
The counters are saved in the `coverage` directory in the standard format of drcov. 
As DrCov usually keeps a BB once regardless of how many times it was hit, we augment .drcov files with drcov.cnt files 
that keep the counters for each BB.
In order to keep the performance penalty low, the files can be saved once in X iteration, controlled by a command line option.
The accumulated counters are created by the `AccMapObserver` that collectes the data from the same in-memory map the regular coverage uses.
In order to enable the collection, set the following compilation options (see `libafl_cc.rs`): `-fsanitize-coverage=pc-table,bb,trace-pc-guard`
In order to turn the collection on use the `--save-bb-coverage` option.
The `--drcov-max-execution-cnt` sets the saving threshold:
`./fuzzer_libpng --save-bb-coverage --drcov-max-execution-cnt 100000 2>/dev/null`

In order to get the counters per BB, use the merge_drcov tool:
`python3 ../../utils/drcov/merge_drcov.py -d ./coverage -c`

### Notes:
1. As of now, the coverage map keeps 1 byte per BB. So if a BB was hit more than 256 times per input, this will not be reflected correctly.
2. The code was tested on Linux only
3. The `DrCov` files produced by the `merge_drcov` are valid and can be processed by tools such as `drcov2lcov`. Please use the latest
version of drcov2lcov, release `10.0.0` has bugs. Specifically, the release `10.0.19798` was tested and works. It is recommended to run it as below in order to focus only on the libpng sources:
`~/Downloads/DynamoRIO-Linux-10.0.19798/tools/bin64/drcov2lcov -input ./coverage/merged.drcov -output ./coverage.old.info -src_filter libpng-1.6.37`
