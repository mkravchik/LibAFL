use std::{
    collections::HashMap,
    fs,
    hash::{BuildHasher, Hasher},
    path::PathBuf,
};

use ahash::RandomState;
use goblin::elf::Elf;
use libafl::{
    executors::ExitKind,
    inputs::{Input, UsesInput},
    observers::{MapObserver, Observer},
    Error,
};
use libafl_bolts::{AsMutSlice, HasLen, Named};
use libafl_targets::{
    drcov::{DrCovBasicBlock, DrCovWriterWithCounter},
    sancov_cmp::sanitizer_cov_pc_table,
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
}

impl<S, M> Observer<S> for AccMapObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S> + AsMutSlice<Entry = u8>,
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

        let map = self.base.as_mut_slice();
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
            let pc_table = sanitizer_cov_pc_table();
            if pc_table.is_none() {
                log::warn!("PC Table not found, can't create drcov file");
            } else {
                let pc_table = pc_table.unwrap();
                log::debug!("PC Table: len: {}", pc_table.len());

                for i in 0..len {
                    if self.acc[i] == 0 {
                        continue;
                    }
                    // The addresses from PCTable are off by the address of the .init section
                    drcov_basic_blocks.push(DrCovBasicBlock {
                        start: pc_table[i].addr() + self.curr_mod_offset,
                        end: pc_table[i].addr() + self.curr_mod_offset + 1, // TODO - this is not correct, but it's just a placeholder
                    });

                    bb_counters.push(self.acc[i]);
                }

                let mut coverage_hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
                for bb in &drcov_basic_blocks {
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
            }

            if self.max_cnt > 0 {
                self.stored_cnt += self.cnt;
                self.cnt = 0;
            }

            //reset the accumulated counts
            self.acc = vec![0; len];
        }

        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for AccMapObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
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
    fn get(&self, idx: usize) -> &u8 {
        self.base.get(idx)
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut u8 {
        self.base.get_mut(idx)
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

    fn hash(&self) -> u64 {
        self.base.hash()
    }
    fn to_vec(&self) -> Vec<u8> {
        self.base.to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.base.how_many_set(indexes)
    }
}

/// A utility function to collect the modules of the current process and their ranges in memory
pub fn collect_modules() -> Result<RangeMap<usize, (u16, String)>, ()> {
    let mut ranges = RangeMap::new();
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

        let file = File::open("/proc/self/maps");
        if file.is_err() {
            return Err(());
        }
        let reader = BufReader::new(file.unwrap());
        let mut module_id = 0;

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
            let end = usize::from_str_radix(range_parts[1], 16).map_err(|_| ())?;
            let name = parts[5].to_string();

            log::info!("Module: {} - 0x{:x} - 0x{:x}", name, start, end);
            ranges.insert(start..end, (module_id, name));
            module_id += 1;
        }
    }

    Ok(ranges)
}

// fn get_string_table_entry(elf: &Elf, index: usize) -> Option<String> {
//     if let Some(section_header) = elf.section_headers.get(index) {
//         if section_header.sh_type == goblin::elf::section_header::SHT_STRTAB {
//             let string_table_offset = section_header.sh_offset as usize;
//             let string_table_size = section_header.sh_size as usize;
//             if let Ok(name) = std::str::from_utf8(string_table) {
//                 return Some(name.to_string());
//             }
//             if let Ok(name) = std::str::from_utf8(string_table) {
//                 return Some(name.to_string());
//             }
//         }
//     }
//     None
// }

fn collect_module_offsets() -> Result<HashMap<String, usize>, ()> {
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

        let file = File::open("/proc/self/maps");
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
                        if let Some(section_name) = elf.shdr_strtab.get_at(sh.sh_name as usize) {
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

impl<M> AccMapObserver<M>
where
    M: Serialize + serde::de::DeserializeOwned + AsMutSlice<Entry = u8> + HasLen,
{
    /// Creates a new [`AccMapObserver`]
    pub fn new(base: M) -> Self {
        let len = base.len();

        let coverage_directory = PathBuf::from("./coverage");
        std::fs::create_dir_all(&coverage_directory)
            .expect("failed to create directory for coverage files");

        let ranges = collect_modules().unwrap();
        let mod_offsets = collect_module_offsets().unwrap();
        // Find the current function address
        let curr_mod_func_addr = collect_module_offsets as *const () as usize;
        // Find the module name of the current function in ranges
        let curr_mod_name = &ranges.get(&curr_mod_func_addr).unwrap().1;
        // Find the offset of the current module, if it exists
        let curr_mod_offset = mod_offsets.get(&curr_mod_name as &str).unwrap_or(&0);
        log::info!(
            "Current module {} offset: 0x{:x}",
            curr_mod_name,
            curr_mod_offset.clone()
        );
        // I'm not sure this is the correct place to initialize the ranges
        // I guess the case of a out-of-proc-server is not handled here,
        // but I will get to it later.
        Self {
            base,
            save_dr_cov: false,
            acc: vec![0; len],
            coverage_directory,
            cnt: 0,
            max_cnt: 0,
            stored_cnt: 0,
            ranges: ranges,
            curr_mod_offset: curr_mod_offset.clone(),
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

    // /// Sums the hitcounts in the map
    // fn count_hits(&mut self) -> u32 {
    //     let map = self.base.as_mut_slice();
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
