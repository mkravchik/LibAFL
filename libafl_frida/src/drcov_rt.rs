//! Generates `DrCov` traces
use std::{
    hash::{BuildHasher, Hasher},
    path::{Path, PathBuf},
    rc::Rc,
};

use ahash::RandomState;
use frida_gum::ModuleMap;
use libafl::{
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_bolts::AsSlice;
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;

use crate::helper::FridaRuntime;

/// Generates `DrCov` traces
#[derive(Debug, Clone)]
pub struct DrCovRuntime {
    /// The basic blocks of this execution
    pub drcov_basic_blocks: Vec<DrCovBasicBlock>,
    /// The memory ranges of this target
    ranges: RangeMap<usize, (u16, String)>,
    coverage_directory: PathBuf,
    cnt: usize,
    max_cnt: usize,
    stored_cnt: usize,
}

impl FridaRuntime for DrCovRuntime {
    /// initializes this runtime with the given `ranges`
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
        self.ranges = ranges.clone();
        std::fs::create_dir_all(&self.coverage_directory)
            .expect("failed to create directory for coverage files");
    }

    /// Called before execution, does nothing
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    /// Called after execution, writes the trace to a unique `DrCov` file for this trace
    /// into `./coverage/<input_hash>_<coverage_hash>.drcov`. Empty coverages will be skipped.
    fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        self.cnt += 1;
        if self.max_cnt > 0 && self.cnt < self.max_cnt {
            return Ok(());
        }
        // We don't need empty coverage files
        if self.drcov_basic_blocks.is_empty() {
            return Ok(());
        }

        let mut input_hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        input_hasher.write(input.target_bytes().as_slice());
        let input_hash = input_hasher.finish();

        let mut coverage_hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
        for bb in &self.drcov_basic_blocks {
            coverage_hasher.write_usize(bb.start);
            coverage_hasher.write_usize(bb.end);
        }
        let coverage_hash = coverage_hasher.finish();

        let filename = if self.max_cnt > 0 {
            self.coverage_directory.join(format!(
                "{input_hash:016x}_{coverage_hash:016x}_{}-{}.drcov",
                self.stored_cnt,
                self.stored_cnt + self.cnt
            ))
        } else {
            self.coverage_directory
                .join(format!("{input_hash:016x}_{coverage_hash:016x}.drcov"))
        };

        log::info!("Writing coverage to {}", filename.display());
        DrCovWriter::new(&self.ranges).write(filename, &self.drcov_basic_blocks)?;
        self.drcov_basic_blocks.clear();

        if self.max_cnt > 0 {
            self.stored_cnt += self.cnt;
            self.cnt = 0;
        }

        Ok(())
    }
}

impl DrCovRuntime {
    /// Creates a new [`DrCovRuntime`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`DrCovRuntime`] that writes coverage to the specified directory
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            coverage_directory: path.as_ref().into(),
            ..Self::default()
        }
    }

    /// Create a new [`DrCovRuntime`] that accumulates coverage up to `max_cnt` and then writes it to the specified directory
    /// This is useful for reducing the number of files written to disk
    /// The `max_cnt` is the number of executions that will be accumulated before writing the coverage to disk
    /// The `stored_cnt` is the number of executions that have been accumulated so far
    /// The `cnt` is the number of executions that have been accumulated since the last write
    /// Note that the accumulated coverage files might not be compatible with the `DrCov` format
    /// as the same block will appear multiple times in the same file.
    /// It is possible to use the `merge_drcov.py` tool to convert to the canonical `DrCov` format
    pub fn with_max_cnt(max_cnt: usize) -> Self {
        Self {
            max_cnt,
            ..Self::default()
        }
    }
}

impl Default for DrCovRuntime {
    fn default() -> Self {
        Self {
            drcov_basic_blocks: vec![],
            ranges: RangeMap::new(),
            coverage_directory: PathBuf::from("./coverage"),
            max_cnt: 0,
            cnt: 0,
            stored_cnt: 0,
        }
    }
}
