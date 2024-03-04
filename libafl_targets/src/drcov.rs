//! [`DrCov`](https://dynamorio.org/page_drcov.html) support for `LibAFL` frida mode,
//! writing basic-block trace files to be read by coverage analysis tools, such as [Lighthouse](https://github.com/gaasedelen/lighthouse),
//! [bncov](https://github.com/ForAllSecure/bncov), [dragondance](https://github.com/0ffffffffh/dragondance), etc.

use alloc::{string::String, vec::Vec};
use core::ptr::addr_of;
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use libafl::Error;
use rangemap::RangeMap;

/// A basic block struct
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrCovBasicBlock {
    /// Start of this basic block
    pub start: usize,
    /// End of this basic block
    pub end: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct DrCovBasicBlockEntry {
    start: u32,
    size: u16,
    mod_id: u16,
}

/// A writer for `DrCov` files
#[derive(Debug)]
pub struct DrCovWriter<'a> {
    module_mapping: &'a RangeMap<usize, (u16, String)>,
}

impl DrCovBasicBlock {
    /// Create a new [`DrCovBasicBlock`] with the given `start` and `end` addresses.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Create a new [`DrCovBasicBlock`] with a given `start` address and a block size.
    #[must_use]
    pub fn with_size(start: usize, size: usize) -> Self {
        Self::new(start, start + size)
    }
}

impl<'a> DrCovWriter<'a> {
    /// Create a new [`DrCovWriter`]
    #[must_use]
    pub fn new(module_mapping: &'a RangeMap<usize, (u16, String)>) -> Self {
        Self { module_mapping }
    }

    /// Write the list of basic blocks to a `DrCov` file.
    pub fn write<P>(&mut self, path: P, basic_blocks: &[DrCovBasicBlock]) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let mut writer = BufWriter::new(File::create(path)?);

        writer
            .write_all(b"DRCOV VERSION: 2\nDRCOV FLAVOR: libafl\n")
            .unwrap();

        let modules: Vec<(&std::ops::Range<usize>, &(u16, String))> =
            self.module_mapping.iter().collect();
        writer
            .write_all(format!("Module Table: version 2, count {}\n", modules.len()).as_bytes())
            .unwrap();
        writer
            .write_all(b"Columns: id, base, end, entry, checksum, timestamp, path\n")
            .unwrap();
        for module in modules {
            let (range, (id, path)) = module;
            writer
                .write_all(
                    format!(
                        "{:03}, 0x{:x}, 0x{:x}, 0x00000000, 0x00000000, 0x00000000, {}\n",
                        id, range.start, range.end, path
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        writer
            .write_all(format!("BB Table: {} bbs\n", basic_blocks.len()).as_bytes())
            .unwrap();
        for block in basic_blocks {
            // Try finding the module for this basic block
            // If we can't find it, at least log a warning
            if self.module_mapping.get_key_value(&block.start).is_none() {
                log::warn!(
                    "Basic block at 0x{:x} not found in module mapping",
                    block.start
                );
            } else {
                let (range, (id, _)) = self.module_mapping.get_key_value(&block.start).unwrap();
                let basic_block = DrCovBasicBlockEntry {
                    start: (block.start - range.start) as u32,
                    size: (block.end - block.start) as u16,
                    mod_id: *id,
                };
                writer
                    .write_all(unsafe {
                        std::slice::from_raw_parts(addr_of!(basic_block) as *const u8, 8)
                    })
                    .unwrap();
            }
        }

        writer.flush()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct DrCovBasicBlockEntryWithCounter {
    start: u32,
    size: u16,
    mod_id: u16,
    count: u32,
}

/// A writer for `DrCov` files with counters
/// This is used for aggregated BB traces
#[derive(Debug)]
pub struct DrCovWriterWithCounter<'a> {
    module_mapping: &'a RangeMap<usize, (u16, String)>,
}

impl<'a> DrCovWriterWithCounter<'a> {
    /// Create a new [`DrCovWriterWithCounter`]
    #[must_use]
    pub fn new(module_mapping: &'a RangeMap<usize, (u16, String)>) -> Self {
        Self { module_mapping }
    }

    /// Write the list of basic blocks to a `DrCov` file.
    pub fn write<P>(
        &mut self,
        path: P,
        basic_blocks: &[DrCovBasicBlock],
        counters: &[u32],
    ) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        // If the length of the basic blocks and the counters is not the same, we can't write the file
        if basic_blocks.len() != counters.len() {
            return Err(Error::illegal_argument(
                "The length of the basic blocks and the counters is not the same",
            ));
        }

        // Use the original writer to write the basic blocks
        DrCovWriter::new(self.module_mapping).write(path.as_ref(), basic_blocks)?;

        // Now write the counters
        // Append the .cnt suffix to the file
        let mut path = path.as_ref().to_path_buf();
        let old_extension = path.extension().unwrap_or_default();
        let new_extension = format!("{}.cnt", old_extension.to_string_lossy());
        path.set_extension(new_extension);

        let mut writer = BufWriter::new(File::create(path)?);

        // Write the counters, all modules info is contained in the original file
        // I don't like it, but I don't like unnecessary parsing either
        for (index, block) in basic_blocks.iter().enumerate() {
            // Try finding the module for this basic block
            // If we can't find it, at least log a warning
            if self.module_mapping.get_key_value(&block.start).is_none() {
                log::warn!(
                    "Basic block at 0x{:x} not found in module mapping",
                    block.start
                );
            } else {
                let (range, (id, _)) = self.module_mapping.get_key_value(&block.start).unwrap();
                let basic_block = DrCovBasicBlockEntryWithCounter {
                    start: (block.start - range.start) as u32,
                    size: (block.end - block.start) as u16,
                    mod_id: *id,
                    count: counters[index],
                };
                writer
                    .write_all(unsafe {
                        std::slice::from_raw_parts(
                            addr_of!(basic_block) as *const u8,
                            std::mem::size_of::<DrCovBasicBlockEntryWithCounter>(),
                        )
                    })
                    .unwrap();
            }
        }

        writer.flush()?;

        Ok(())
    }
}
