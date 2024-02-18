//! Functionality regarding binary-only coverage collection.
use core::ptr::addr_of_mut;
use std::{
    cell::RefCell,
    collections::HashMap,
    hash::{BuildHasher, Hasher},
    marker::PhantomPinned,
    path::PathBuf,
    pin::Pin,
    rc::Rc,
};

use ahash::RandomState;
#[cfg(target_arch = "aarch64")]
use dynasmrt::DynasmLabelApi;
use dynasmrt::{dynasm, DynasmApi};
use frida_gum::{instruction_writer::InstructionWriter, stalker::StalkerOutput, ModuleMap};
use libafl_bolts::{hash_std, AsSlice};
use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};
use rangemap::RangeMap;

use crate::helper::FridaRuntime;

/// (Default) map size for frida coverage reporting
pub const MAP_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct CoverageRuntimeInner {
    map: [u8; MAP_SIZE],
    previous_pc: u64,
    _pinned: PhantomPinned,
}

/// Frida binary-only coverage
#[derive(Debug)]
pub struct CoverageRuntime {
    inner: Pin<Rc<RefCell<CoverageRuntimeInner>>>,
    block_mode: bool,
    /// The memory ranges of this target
    ranges: RangeMap<usize, (u16, String)>,
    save_dr_cov: bool,
    coverage_directory: PathBuf,
    basic_blocks: HashMap<u64, DrCovBasicBlock>,
    cnt: usize,
    max_cnt: usize,
    stored_cnt: usize,
}

impl Default for CoverageRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl FridaRuntime for CoverageRuntime {
    /// Initialize the coverage runtime
    /// The struct MUST NOT be moved after this function is called, as the generated assembly references it
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

    fn deinit(&mut self, _gum: &frida_gum::Gum) {}

    fn pre_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        _input: &I,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }

    fn post_exec<I: libafl::inputs::Input + libafl::inputs::HasTargetBytes>(
        &mut self,
        input: &I,
    ) -> Result<(), libafl::Error> {
        if self.block_mode && self.save_dr_cov {
            self.cnt += 1;
            if self.max_cnt > 0 && self.cnt < self.max_cnt {
                return Ok(());
            }

            // Create basic blocks
            let mut drcov_basic_blocks: Vec<DrCovBasicBlock> = vec![];

            for (key, value) in &self.basic_blocks {
                log::trace!(
                    "Covered BB key: {:x}, value: {:016x} - {:016x}",
                    key,
                    value.start,
                    value.end
                );
                drcov_basic_blocks.push(*value);
            }

            let mut input_hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
            input_hasher.write(input.target_bytes().as_slice());
            let input_hash = input_hasher.finish();

            let mut coverage_hasher = RandomState::with_seeds(0, 0, 0, 0).build_hasher();
            for bb in &drcov_basic_blocks {
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

            DrCovWriter::new(&self.ranges).write(filename, &drcov_basic_blocks)?;
            if self.max_cnt > 0 {
                self.stored_cnt += self.cnt;
                self.cnt = 0;
            }

            return Ok(());
        }
        Ok(())
    }
}

impl CoverageRuntime {
    /// Create a new coverage runtime
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Rc::pin(RefCell::new(CoverageRuntimeInner {
                map: [0_u8; MAP_SIZE],
                previous_pc: 0,
                _pinned: PhantomPinned,
            })),
            block_mode: false,
            ranges: RangeMap::new(),
            save_dr_cov: false,
            coverage_directory: PathBuf::from("./coverage"),
            basic_blocks: HashMap::new(),
            cnt: 0,
            max_cnt: 0,
            stored_cnt: 0,
        }
    }

    /// Set the block mode
    #[must_use]
    pub fn block_mode(mut self, block_mode: bool) -> Self {
        log::info!("Setting block mode to {}", block_mode);
        self.block_mode = block_mode;
        self
    }

    /// Set whether to save `DrCov` files
    #[must_use]
    pub fn save_dr_cov(mut self, save_dr_cov: bool) -> Self {
        self.save_dr_cov = save_dr_cov;
        self
    }

    /// Set the coverage directory
    #[must_use]
    pub fn coverage_directory(mut self, coverage_directory: &str) -> Self {
        self.coverage_directory = PathBuf::from(coverage_directory);
        self
    }

    /// Set the maximum number of executions to accumulate before writing the coverage to disk
    #[must_use]
    pub fn max_cnt(mut self, max_cnt: usize) -> Self {
        self.max_cnt = max_cnt;
        self
    }

    /// Builder pattern
    #[must_use]
    pub fn build(self) -> CoverageRuntime {
        CoverageRuntime {
            inner: Rc::pin(RefCell::new(CoverageRuntimeInner {
                map: [0_u8; MAP_SIZE],
                previous_pc: 0,
                _pinned: PhantomPinned,
            })),
            block_mode: self.block_mode,
            ranges: self.ranges,
            save_dr_cov: self.save_dr_cov,
            coverage_directory: self.coverage_directory,
            basic_blocks: self.basic_blocks,
            cnt: self.cnt,
            max_cnt: self.max_cnt,
            stored_cnt: self.stored_cnt,
        }
    }

    /// Retrieve the coverage map pointer
    pub fn map_mut_ptr(&mut self) -> *mut u8 {
        self.inner.borrow_mut().map.as_mut_ptr()
    }

    /// A minimal `maybe_log` implementation. We insert this into the transformed instruction stream
    /// every time we need a copy that is within a direct branch of the start of the transformed basic
    /// block.
    #[cfg(target_arch = "aarch64")]
    #[allow(clippy::cast_possible_wrap)]
    pub fn generate_inline_code(&mut self, h64: u64) -> Box<[u8]> {
        let mut borrow = self.inner.borrow_mut();
        let prev_loc_ptr = addr_of_mut!(borrow.previous_pc);
        let map_addr_ptr = addr_of_mut!(borrow.map);
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        if block_mode {
            dynasm!(ops
                ;   .arch aarch64
                // Store the context
                ;   b >start

                ;   stp x16, x17, [sp, -0x90]!
                ; start:

                // Load the block id
                ;   ldr x16, >loc

                // Load the map byte address
                ;   ldr x17, >map_addr
                ;   add x16, x17, x16

                // Update the map byte
                ;   ldrb w17, [x16]
                ;   add w17, w17, #1
                ;   add x17, x17, x17, lsr #8
                ;   strb w17, [x16]

                // Restore the context
                ;   ldp x16, x17, [sp], #0x90

                // Skip the data
                ;   b >end

                ;map_addr:
                ;.qword map_addr_ptr as i64
                ;previous_loc:
                ;.qword prev_loc_ptr as i64
                ;loc:
                ;.qword h64 as i64
                ;loc_shr:
                ;.qword (h64 >> 1) as i64
                ;end:
            );
        } else {
            dynasm!(ops
                ;   .arch aarch64
                // Store the context
                ;   b >start

                ;   stp x16, x17, [sp, -0x90]!
                ; start:

                // Load the previous_pc
                ;   ldr x17, >previous_loc
                ;   ldr x17, [x17]

                // Caltulate the edge id
                ;   ldr x16, >loc
                ;   eor x16, x17, x16

                // Load the map byte address
                ;   ldr x17, >map_addr
                ;   add x16, x17, x16

                // Update the map byte
                ;   ldrb w17, [x16]
                ;   add w17, w17, #1
                ;   add x17, x17, x17, lsr #8
                ;   strb w17, [x16]

                // Update the previous_pc value
                ;   ldr x16, >loc_shr
                ;   ldr x17, >previous_loc
                ;   str x16, [x17]

                // Restore the context
                ;   ldp x16, x17, [sp], #0x90

                // Skip the data
                ;   b >end

                ;map_addr:
                ;.qword map_addr_ptr as i64
                ;previous_loc:
                ;.qword prev_loc_ptr as i64
                ;loc:
                ;.qword h64 as i64
                ;loc_shr:
                ;.qword (h64 >> 1) as i64
                ;end:
            );
        }
        let ops_vec = ops.finalize().unwrap();
        ops_vec[..ops_vec.len()].to_vec().into_boxed_slice()
    }

    /// Write inline instrumentation for coverage
    #[cfg(target_arch = "x86_64")]
    pub fn generate_inline_code(&mut self, h64: u64, block_mode: bool) -> Box<[u8]> {
        let mut borrow = self.inner.borrow_mut();
        let prev_loc_ptr = addr_of_mut!(borrow.previous_pc);
        let map_addr_ptr = addr_of_mut!(borrow.map);
        let mut ops = dynasmrt::VecAssembler::<dynasmrt::x64::X64Relocation>::new(0);
        if block_mode {
            dynasm!(ops
                ;   .arch x64
                // Store the context
                ; mov    QWORD [rsp-0x88], rax
                ; lahf
                ; mov    QWORD [rsp-0x90], rax
                ; mov    QWORD [rsp-0x98], rbx

                // Load the block id
                ; mov eax, WORD h64 as i32

                // Load the map byte address
                ; mov rbx, QWORD map_addr_ptr as _
                ; add rax, rbx

                // Update the map byte
                ; mov bl, BYTE [rax]
                ; add bl,0x1
                ; adc bl,0x0
                ; mov BYTE [rax],bl

                // Restore the context
                ; mov    rbx, QWORD [rsp-0x98]
                ; mov    rax, QWORD [rsp-0x90]
                ; sahf
                ; mov    rax, QWORD [rsp-0x88]
            );
        } else {
            dynasm!(ops
                ;   .arch x64
                // Store the context
                ; mov    QWORD [rsp-0x88], rax
                ; lahf
                ; mov    QWORD [rsp-0x90], rax
                ; mov    QWORD [rsp-0x98], rbx

                // Load the previous_pc
                ; mov rax, QWORD prev_loc_ptr as _
                ; mov rax, QWORD [rax]

                // Calculate the edge id
                ; mov ebx, WORD h64 as i32
                ; xor rax, rbx

                // Load the map byte address
                ; mov rbx, QWORD map_addr_ptr as _
                ; add rax, rbx

                // Update the map byte
                ; mov bl, BYTE [rax]
                ; add bl,0x1
                ; adc bl,0x0
                ; mov BYTE [rax],bl

                // Update the previous_pc value
                ; mov rax, QWORD prev_loc_ptr as _
                ; mov ebx, WORD (h64 >> 1) as i32
                ; mov QWORD [rax], rbx

                // Restore the context
                ; mov    rbx, QWORD [rsp-0x98]
                ; mov    rax, QWORD [rsp-0x90]
                ; sahf
                ; mov    rax, QWORD [rsp-0x88]
            );
        }
        let ops_vec = ops.finalize().unwrap();

        ops_vec[..ops_vec.len()].to_vec().into_boxed_slice()
    }

    /// Keeps track of the basic block in the map
    #[inline]
    pub fn set_bb_size(&mut self, address: u64, size: usize) {
        if self.save_dr_cov {
            let h64 = hash_std(&address.to_le_bytes());
            let map_idx: u64 = h64 & (MAP_SIZE as u64 - 1);
            let basic_block = DrCovBasicBlock::with_size(address as usize, size);
            self.basic_blocks.insert(map_idx, basic_block);
        }
    }

    /// Emits coverage mapping into the current basic block.
    #[inline]
    pub fn emit_coverage_mapping(&mut self, address: u64, output: &StalkerOutput) {
        let h64 = hash_std(&address.to_le_bytes());
        let writer = output.writer();

        // Since the AARCH64 instruction set requires that a register be used if
        // performing a long branch, if the Stalker engine is unable to use a near
        // branch to transition between branches, then it spills some registers
        // into the stack beyond the red-zone so that it can use them to perform
        // the branch. Accordingly each block is transparently prefixed with an
        // instruction to restore these registers. If however a near branch can
        // be used, then this instruction is simply skipped and Stalker simply
        // branches to the second instruction in the block.
        //
        // Since we also need to spill some registers in order to update our
        // coverage map, in the event of a long branch, we can simply re-use
        // these spilt registers. This, however, means we need to retard the
        // code writer so that we can overwrite the so-called "restoration
        // prologue".
        #[cfg(target_arch = "aarch64")]
        {
            let pc = writer.pc();
            writer.reset(pc - 4);
        }

        let code = self.generate_inline_code(h64 & (MAP_SIZE as u64 - 1), self.block_mode);
        writer.put_bytes(&code);
    }
}
