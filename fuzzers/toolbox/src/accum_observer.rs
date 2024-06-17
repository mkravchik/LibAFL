use alloc::borrow::Cow;
#[cfg(unix)]
use std::fs;
use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash, Hasher},
    num::ParseIntError,
    path::PathBuf,
};

use ahash::RandomState;
#[cfg(unix)]
use goblin::elf::Elf;
use libafl::{
    executors::ExitKind,
    inputs::{Input, UsesInput},
    observers::{MapObserver, Observer},
    Error,
};
use libafl_bolts::{AsSliceMut, HasLen, Named};
use libafl_targets::{
    drcov::{DrCovBasicBlock, DrCovWriterWithCounter},
    sancov_pcguard::sanitizer_cov_pc_table,
};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
/// Map observer that accumulates hitcounts and saves them in DrCov format.
///
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct AccMapObserver<M>
where
    M: Serialize,
{
    base: M,
    save_dr_cov: bool,
    acc: Vec<u32>,
    coverage_directory: PathBuf,
    cnt: usize,
    max_cnt: usize,
    stored_cnt: usize,
    #[serde(skip)]
    // I'm not sure when the observers are serialized, but I don't want to serialize this
    ranges: RangeMap<usize, (u16, String)>,
    curr_mod_offset: usize,
    curr_mod_addr: usize,
    use_pc_table: bool,
    target_pid: u32,
}

impl<M> Hash for AccMapObserver<M>
where
    M: Hash + Serialize,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.base.hash(state);
        self.save_dr_cov.hash(state);
        self.acc.hash(state);
        self.coverage_directory.hash(state);
        self.cnt.hash(state);
        self.max_cnt.hash(state);
        self.stored_cnt.hash(state);
        self.curr_mod_offset.hash(state);
        self.curr_mod_addr.hash(state);
        self.use_pc_table.hash(state);
        self.target_pid.hash(state);
    }
}

impl<S, M> Observer<S> for AccMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S> + for<'a> AsSliceMut<'a, Entry = u8>,
    S: UsesInput,
{
    #[inline]
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        if !self.save_dr_cov {
            return Ok(());
        }
        // Here the map is reset
        self.base.pre_exec(state, input)
    }

    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    fn post_exec(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        if !self.save_dr_cov {
            return Ok(());
        }
        {
            let map = self.base.as_slice();
            let len = map.len();

            for i in 0..len {
                self.acc[i] += map[i] as u32;
            }

            // // Count the hitcounts in the map - DEBUG LOG
            // let hitcount = self.count_hits();
            // log::info!("AccMapObserver: post_exec, hitcount: {}", hitcount);

            self.cnt += 1;
            if self.max_cnt == 0 || self.cnt >= self.max_cnt {
                // Create basic blocks
                let mut drcov_basic_blocks: Vec<DrCovBasicBlock> = vec![];
                let mut bb_counters: Vec<u32> = vec![];

                // access the PC Table
                // TODO - check if copying it over makes any difference in performance
                let pc_table = if self.use_pc_table {
                    sanitizer_cov_pc_table()
                } else {
                    None
                };
                if self.use_pc_table {
                    if pc_table.is_none() {
                        log::warn!("PC Table not found, can't create drcov file");
                    } else {
                        log::debug!("PC Table: len: {}", pc_table.unwrap().len());
                    }
                }

                for i in 0..len {
                    if self.acc[i] == 0 {
                        continue;
                    }
                    if let Some(pc_table) = pc_table {
                        // The addresses from PCTable are real memory addresses
                        // The module is mapped starting from the beginning of the .init section
                        drcov_basic_blocks.push(DrCovBasicBlock {
                            start: pc_table[i].addr() + self.curr_mod_offset,
                            end: pc_table[i].addr() + self.curr_mod_offset + 1, // this is fixed in the script
                        });
                    } else {
                        drcov_basic_blocks.push(DrCovBasicBlock {
                            // I need the address to point to real memory addresses
                            start: self.curr_mod_addr + i, // this is fixed in the script
                            end: self.curr_mod_addr + i, // this is fixed in the script start == end indicates to fix the start as well
                        });
                    }

                    bb_counters.push(self.acc[i]);
                }

                let mut coverage_hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
                for bb in &drcov_basic_blocks {
                    log::debug!("BB: 0x{:x} - 0x{:x}", bb.start, bb.end);
                    coverage_hasher.write_usize(bb.start);
                    coverage_hasher.write_usize(bb.end);
                }
                let coverage_hash = coverage_hasher.finish();
                let input_name = input.generate_name(0); // The input index is not known at this point, but is not used in the filename
                let filename = if self.max_cnt > 0 {
                    self.coverage_directory.join(format!(
                        "{}_{coverage_hash:016x}_{}-{}.drcov",
                        &input_name,
                        self.stored_cnt,
                        self.stored_cnt + self.cnt
                    ))
                } else {
                    self.coverage_directory
                        .join(format!("{}_{coverage_hash:016x}.drcov", &input_name))
                };

                DrCovWriterWithCounter::new(&self.ranges).write(
                    filename,
                    &drcov_basic_blocks,
                    &bb_counters,
                )?;

                if self.max_cnt > 0 {
                    self.stored_cnt += self.cnt;
                    self.cnt = 0;
                }

                //reset the accumulated counts
                self.acc = vec![0; len];
            }
        }

        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for AccMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.base.name()
    }
}

impl<M> HasLen for AccMapObserver<M>
where
    M: MapObserver,
{
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<M> AsMut<Self> for AccMapObserver<M>
where
    M: MapObserver,
{
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<M> AsRef<Self> for AccMapObserver<M>
where
    M: MapObserver,
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<M> MapObserver for AccMapObserver<M>
where
    M: MapObserver<Entry = u8>,
{
    type Entry = u8;

    #[inline]
    fn initial(&self) -> u8 {
        self.base.initial()
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.base.usable_count()
    }

    #[inline]
    fn get(&self, idx: usize) -> u8 {
        self.base.get(idx)
    }

    #[inline]
    fn set(&mut self, idx: usize, val: u8) {
        self.base.set(idx, val);
    }

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        self.base.count_bytes()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        self.base.reset_map()
    }

    fn hash_simple(&self) -> u64 {
        self.base.hash_simple()
    }
    fn to_vec(&self) -> Vec<u8> {
        self.base.to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.base.how_many_set(indexes)
    }
}

#[cfg(unix)]
fn get_pid_name(pid: Option<u32>) -> String {
    match pid {
        Some(pid) => format!("/proc/{}/maps", pid),
        None => "/proc/self/maps".to_string(),
    }
}

#[derive(Debug)]
pub enum CollectModulesError {
    IoError(std::io::Error),
    ParseError(std::num::ParseIntError),
}
impl From<ParseIntError> for CollectModulesError {
    fn from(err: ParseIntError) -> Self {
        CollectModulesError::ParseError(err)
    }
}
/// A utility function to collect the modules of the current process and their ranges in memory
#[allow(unused_mut)]
pub fn collect_modules(pid: Option<u32>) -> Result<RangeMap<usize, (u16, String)>, CollectModulesError> {
    let mut ranges = RangeMap::new();
    #[cfg(windows)]
    {
        // Windows-specific implementation here
        let _pid = pid;
    }

    #[cfg(unix)]
    {
        // Unix-specific implementation here
        use std::{
            fs::File,
            io::{BufRead, BufReader},
        };

        let file = File::open(get_pid_name(pid));
        if let Err(file_err) = file {
            return Err(CollectModulesError::IoError(file_err));
        }
        let reader = BufReader::new(file.unwrap());
        let mut module_id = 0;

        for line in reader.lines() {
            if line.is_err() {
                continue
            }
            let line = line.unwrap();
            log::info!("Line: {}", line);
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 6 {
                continue;
            }

            let range_parts: Vec<&str> = parts[0].split('-').collect();
            if range_parts.len() != 2 {
                continue;
            }

            // Ignore the module if it is not executable
            if !parts[1].contains('x') {
                continue;
            }
            let start = usize::from_str_radix(range_parts[0], 16)?;
            let end = usize::from_str_radix(range_parts[1], 16)?;
            let name = parts[5].to_string();

            log::info!("Module: {} - 0x{:x} - 0x{:x}", name, start, end);
            ranges.insert(start..end, (module_id, name));
            module_id += 1;
        }
    }

    Ok(ranges)
}

// Reads the .init section offset of each module in the process.
// This is used to calculate the real memory address of the basic blocks
fn collect_module_offsets(pid: Option<u32>) -> Result<HashMap<String, usize>, ()> {
    let mut offsets = HashMap::new();
    #[cfg(windows)]
    {
        // Windows-specific implementation here
    }

    #[cfg(unix)]
    {
        // Unix-specific implementation here
        use std::{
            fs::File,
            io::{BufRead, BufReader},
        };

        let file = File::open(get_pid_name(pid));
        if file.is_err() {
            return Err(());
        }
        let reader = BufReader::new(file.unwrap());

        for line in reader.lines() {
            if line.is_err() {
                continue;
            }
            let line = line.unwrap();
            log::info!("Line: {}", line);
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 6 {
                continue;
            }

            let range_parts: Vec<&str> = parts[0].split('-').collect();
            if range_parts.len() != 2 {
                continue;
            }

            // Ignore the module if it is not executable
            if !parts[1].contains('x') {
                continue;
            }
            let start = usize::from_str_radix(range_parts[0], 16).map_err(|_| ())?;
            let name = parts[5].to_string();

            log::info!("Module: {} - 0x{:x}", name, start);

            // The offset of the `.init` section as specified in the ELF header
            // Read the binary file into a byte array
            if let Ok(buffer) = fs::read(name.clone()) {
                // Parse the buffer as an ELF binary
                if let Ok(elf) = Elf::parse(&buffer) {
                    // Iterate over section headers to find the .init section
                    for sh in elf.section_headers {
                        let offset = sh.sh_offset as usize;
                        if let Some(section_name) = elf.shdr_strtab.get_at(sh.sh_name) {
                            if section_name == ".init" {
                                log::info!(
                                    "Module: {} - 0x{:x} - 0x{:x}",
                                    name.clone(),
                                    start,
                                    offset
                                );
                                offsets.insert(name.clone(), offset);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(offsets)
}

// Finds the start address and the .init section offset of the module
// Can be used for the current module (useful when the fuzzer is linked into the target binary)
// of for the first module in the process (useful when the fuzzer is a separate process)
fn find_module_params(
    pid: Option<u32>,
    ranges: &RangeMap<usize, (u16, String)>,
    find_current: bool,
) -> (usize, usize) {
    let mod_offsets = collect_module_offsets(pid).unwrap();
    let curr_mod_id: u16;
    let mut curr_mod_name: String = String::new();
    if find_current {
        // Find the current function address
        let curr_mod_func_addr = collect_module_offsets as *const () as usize;
        // Find the module name of the current function in ranges

        (curr_mod_id, curr_mod_name) = (*ranges.get(&curr_mod_func_addr).unwrap()).clone();
        // Find the offset of .text section of the current module, if it exists
    } else {
        curr_mod_id = 0; // use the first module. Is this always correct?
                         // curr_mod_name = ranges.get(&0).unwrap().1.clone();
        for (_, val) in ranges.iter() {
            if val.0 == curr_mod_id {
                curr_mod_name.clone_from(&val.1);
                break;
            }
        }
    }
    let mod_offset = mod_offsets.get(&curr_mod_name as &str).unwrap_or(&0);
    log::info!(
        "Current module {} {} offset: 0x{:x}",
        curr_mod_id,
        curr_mod_name,
        mod_offset.clone()
    );

    let mut mod_addr: usize = 0;
    for (key, val) in ranges.iter() {
        log::info!("Module: {}{} - 0x{:x}", val.0, val.1, key.start);
        if val.0 == curr_mod_id {
            mod_addr = key.start;
            break;
        }
    }
    (*mod_offset, mod_addr)
}

impl<M> AccMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned + for<'a> AsSliceMut<'a, Entry = u8> + HasLen,
{
    /// Creates a new [`AccMapObserver`]
    pub fn new(base: M) -> Self {
        let len = base.len();

        let coverage_directory = PathBuf::from("./coverage");
        std::fs::create_dir_all(&coverage_directory)
            .expect("failed to create directory for coverage files");

        let ranges = collect_modules(None).unwrap();
        let (curr_mod_offset, curr_mod_addr) = find_module_params(None, &ranges, true);

        Self {
            base,
            save_dr_cov: false,
            acc: vec![0; len],
            coverage_directory,
            cnt: 0,
            max_cnt: 0,
            stored_cnt: 0,
            ranges,
            curr_mod_offset,
            curr_mod_addr,
            use_pc_table: false,
            target_pid: 0,
        }
    }

    // /// Set the coverage directory
    // #[must_use]
    // pub fn coverage_directory(mut self, coverage_directory: &str) -> Self {
    //     self.coverage_directory = PathBuf::from(coverage_directory);
    //     self
    // }

    /// Set whether to save `DrCov` files
    #[must_use]
    pub fn save_dr_cov(mut self, save_dr_cov: bool) -> Self {
        log::info!("Setting save_dr_cov: {}", save_dr_cov);
        self.save_dr_cov = save_dr_cov;
        self
    }

    /// Set the maximum number of executions to accumulate before writing the coverage to disk
    #[must_use]
    pub fn max_cnt(mut self, max_cnt: usize) -> Self {
        log::info!("Setting max_cnt: {}", max_cnt);
        self.max_cnt = max_cnt;
        self
    }

    #[must_use]
    pub fn use_pc_table(mut self, use_pc_table: bool) -> Self {
        log::info!("Setting use_pc_table: {}", use_pc_table);
        self.use_pc_table = use_pc_table;
        self
    }

    pub fn read_pid_modules(&mut self, target: u32) {
        self.target_pid = target;
        log::info!("Reading modules for pid: {}", target);
        self.ranges = collect_modules(Some(target)).unwrap();
        let (curr_mod_offset, curr_mod_addr) =
            find_module_params(Some(target), &self.ranges, false);
        self.curr_mod_offset = curr_mod_offset;
        self.curr_mod_addr = curr_mod_addr;
    }
    // /// Sums the hitcounts in the map
    // fn count_hits(&mut self) -> u32 {
    //     let map = self.base.as_slice_mut();
    //     let len = map.len();

    //     // TODO - Accumulate the hitcounts in the map
    //     // Count the hitcounts in the map
    //     let mut hitcount = 0;
    //     for i in 0..len {
    //         hitcount += map[i] as u32;
    //     }
    //     hitcount
    // }
}
