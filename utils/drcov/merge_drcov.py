import argparse
import os
import glob
import time
import drcov
import platform
import json
import tqdm
from ctypes import *
from collections import defaultdict
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_EI_CLASS

from typing import List, Tuple
import bisect
from copy import copy

verbose = False
# DrCov file writer based on 
# https://github.com/gaasedelen/lighthouse/blob/f4642e8b4b4347b11ccb25a79ec4f490c9ad901d/coverage/frida/frida-drcov.py

class HashableDrcovBasicBlock(drcov.DrcovBasicBlock):
    def __init__(self, block):
        self.mod_id = block.mod_id
        self.start = block.start
        self.size = block.size

    def __hash__(self):
        # I remove the size from the hash, because we don't know it when using PCTable and fix later
        return hash((self.start, self.mod_id))

    def __eq__(self, other):
        if isinstance(other, HashableDrcovBasicBlock) or isinstance(other, drcov.DrcovBasicBlock):
            return self.start == other.start and self.mod_id == other.mod_id
        return False

class DrcovBasicBlockWithCounter(Structure):
    """
    Parser & wrapper for basic block with counter details as found in the drcov.cnt files.

    NOTE:

      Based off the following Rust structure

    #[repr(C)]
    struct DrCovBasicBlockEntryWithCounter {
        start: u32,
        size: u16,
        mod_id: u16,
        count: u32,
    }

    """
    _pack_   = 1
    _fields_ = [
        ('start',  c_uint32),
        ('size',   c_uint16),
        ('mod_id', c_uint16),
        ('count', c_uint32)
    ]

# A class that reads serialized DrcovBasicBlockWithCounter
class DrcovBasicBlockWithCounterReader:
    def __init__(self, file_name):
        self.file = open(file_name, "rb")
        self.bbs = {}
        self._read_bbs()

    def _read_bbs(self):
        while True:
            bb = DrcovBasicBlockWithCounter()
            read = self.file.readinto(bb)
            if read == 0:
                break
            self.bbs[HashableDrcovBasicBlock(drcov.DrcovBasicBlock(bb.start, bb.size, bb.mod_id))] = (bb.size, bb.count)

    def close(self):
        self.file.close()

    def __len__(self):
        return len(self.bbs)

    def __getitem__(self, key):
        return self.bbs[HashableDrcovBasicBlock(key)]

    def __contains__(self, item):
        return HashableDrcovBasicBlock(item) in self.bbs


# A class that creates a DrCov file
class DrcovFile:
    def __init__(self, file_name, allow_duplicates=False):
        self.file_name = file_name
        self.allow_duplicates = allow_duplicates
        # Each module is a dictionary with the following keys
        # m = {
        # 'id': idx,
        # 'path': path,
        # 'base': base,
        # 'end': end,
        # 'size': size}
        self.mods = dict() # A dictionary of modules id -> {path, base, end, size}
        if self.allow_duplicates:
            self.bbs = []
        else:
            self.bbs = set() # A set HashableDrcovBasicBlock


    def _write_header(self):
        header = ''
        header += 'DRCOV VERSION: 2\n'
        header += 'DRCOV FLAVOR: drcov-64\n'
        header += 'Module Table: version 2, count %d\n' % len(self.mods)

        #     DynamoRIO v7.0.0-RC1, table version 2:
        #    Windows:
        #      'Columns: id, base, end, entry, checksum, timestamp, path'
        #    Mac/Linux:
        #      'Columns: id, base, end, entry, path'
        if platform.system() == 'Windows':
            have_checksum = True
        else:
            have_checksum = False
        
        if have_checksum:
            header += 'Columns: id, base, end, entry, checksum, timestamp, path\n'
        else:
            header += 'Columns: id, base, end, entry, path\n'

        entries = []

        # Sort the modules by ID in ascending order
        sorted_modules = sorted(self.mods.items(), key=lambda x: x[0])

        for m_id, m in sorted_modules:
            # drcov: id, base, end, entry, checksum, timestamp, path
            # drcov expects the size to be page aligned
            # align the m['end'] to the next page
            m['end'] = (m['end'] + 0xfff) & ~0xfff
            if have_checksum:
                entry = '%3d, %#016x, %#016x, %#016x, %#08x, %#08x, %s' % (
                    m_id, m['base'], m['end'], 0, 0, 0, m['path'])
            else:
                entry = '%3d, %#016x, %#016x, %#016x, %s' % (
                    m_id, m['base'], m['end'], 0, m['path'])

            entries.append(entry)

        header_modules = '\n'.join(entries)

        self.file.write(("%s%s\n" % (header, header_modules)).encode("utf-8"))


    def _write_bbs(self):
        bb_header = b'BB Table: %d bbs\n' % len(self.bbs)
        self.file.write(bb_header)

        for bb in self.bbs:
            # self.file.write(struct.pack("<IHH", bb["start"], bb["size"], bb["module_id"]))
            print("bb:", bb.mod_id, hex(bb.start), bb.size)
            self.file.write(bb)

    def check_module_compatible(self, id, path, base, end):
        if id in self.mods:
            m = self.mods[id]
            if m['path'] != path or m['base'] != base or m['end'] != end:
                return False
        return True
            
        self.mods[id] = {'path': path, 'base': base, 'end': end, 'size': end - base}
    def add_module(self, id, path, base, end):
        # Is there a module with this ID 
        if id in self.mods:
            m = self.mods[id]
            # Check if the module has the same attributes
            if m['path'] != path or m['base'] != base or m['end'] != end:
                raise ValueError("Module with ID %d already exists with different attributes" % id)
            else:
                return
        self.mods[id] = {'path': path, 'base': base, 'end': end, 'size': end - base}
    
    
    # Add a basic block to the file
    # Returns True if the basic block already exists
    def add_bb(self, drcov_bb) -> bool:
        hbb = HashableDrcovBasicBlock(drcov_bb)
        if hbb.mod_id not in self.mods:
            raise ValueError("Module ID %d not found" % hbb.mod_id)
        if self.allow_duplicates:
            if hbb in self.bbs:
                if verbose:
                    print("Duplicate basic block found:", hbb)
            self.bbs.append(hbb)
        else:
            if hbb in self.bbs:
                if verbose:
                    print("Duplicate basic block found:", hbb)
                return True
            self.bbs.add(hbb)
        return False
    
    def write(self):
        if self.mods is None or len(self.mods) == 0:
            raise ValueError("No modules to write")
        
        self.file = open(self.file_name, "wb")
        self._write_header()
        self._write_bbs()
        self.file.close()

# A class that can return the basic block size in a given module
class DrcovBasicBlockSizeCalculator:
    def __init__(self, file_name, verbose=False):
        self.file = file_name
        # read the ELF header, find the address of the .text section and read it into memory
        self.code_offset, self.text_data, self.trace_address = self._read_text_section()
        self.bbs = {}
        self.disasm = Cs(CS_ARCH_X86, CS_MODE_64)
        self.verbose = verbose
        # alternatively, read the PCTable from the ELF file, if present
        self.pcs = parsePCTable(file_name, self.verbose)
        if self.pcs is not None:
            # The PC table is NOT sorted, and we are getting the index into it
            # However, in order to know the size of the basic block, we need to know the next address
            # So we need to sort it and keep the dictionary of sizes
            sorted_pcs = sorted(self.pcs, key=lambda x: x[0])
            self.pc_sizes = {sorted_pcs[i][0]: sorted_pcs[i+1][0] - sorted_pcs[i][0] for i in range(len(sorted_pcs) - 1)}
            self.pc_sizes[sorted_pcs[-1][0]] = -1 # the last one is a special case

    def _find_section_offset(self, elffile, section_name):
        for section in elffile.iter_sections():
            if section.name == section_name:
                return section.header.sh_offset
        return None
    
    def _read_text_section(self) -> Tuple[int, bytes, int]:
        with open(self.file, 'rb') as f:
            elffile = ELFFile(f)

            # Find the .init section
            init_section_offset = self._find_section_offset(elffile, '.init')
            if init_section_offset is None:
                print(f"No .init section found in {self.file}")                
                return 0, None, 0
            
            # Find the .text section
            text_section = None
            for section in elffile.iter_sections():
                if section.name == '.text':
                    text_section = section
                    break

            if text_section is None:
                print(f"No .text section found in {self.file}")
                return 0, None, 0

            # Read the .text section into memory
            text_data = text_section.data()

            trace_address = 0
            # find the address of the `__sanitizer_cov_trace_pc_guard`
            symtab = elffile.get_section_by_name('.symtab')  # Get the symbol table
            if not symtab:
                print("Symbol table not found.")
                return 0, None, 0
            
            for symbol in symtab.iter_symbols():
                # print(symbol.name)
                if symbol.name == '__sanitizer_cov_trace_pc_guard':
                    trace_address = symbol['st_value']
                    break

            return text_section.header.sh_offset - init_section_offset, text_data, trace_address

    def find_basic_block_size(self, data, address):

        # If we have the PCTable, we can use it to find the size of the basic block
        pc_table_bb_size = None
        if self.pcs is not None:
            # # Find the index of the first item greater than address
            # i = bisect.bisect_right(self.pcs, (address,))

            # if i != len(self.pcs):
            #     if i < len(self.pcs) - 1:
            #         pc_table_bb_size = self.pcs[i + 1][0] - address
            #         return pc_table_bb_size
            #     else:
            #         # we are in trouble, we are at the last item and I have no idea how to find the size of the BB
            #         print(f"Address {hex(address)} is the last in PCTable, calculating size from disassembly")
            # else:
            #     print(f"Address {hex(address)} not found in PCTable")
            if address in self.pc_sizes:
                pc_table_bb_size = self.pc_sizes[address]
                if pc_table_bb_size == -1:
                    print(f"Address {hex(address)} is the last in PCTable, calculating size from disassembly")
                else:
                    return pc_table_bb_size
            else:
                print(f"Address {hex(address)} not found in PCTable")                
        """
        Determine the size of a basic block given its start address using Capstone.
        
        data: The binary data as bytes.
        address: The starting address of the basic block.
        """
        def is_end_of_basic_block(instr, ignore_calls_addr) -> bool:
            """
            Determines if an instruction is typically the end of a basic block.
            """
            # Examples of instructions that could signify the end of a basic block
            # This is a simplified check; more complex logic might be needed for a comprehensive analysis
            # Moreover, we are insterested in the BBs as PCGuard sees them, so we need to ignore calls to the PCGuard
            # PCGuard, seem to considers the BB as something other code can jump to
            # Thus, code after a conditional jump is considered a continuation of the BB
            # Therefore, this simplified logic in unadequate and I'll leave it here a underapproximation
            if instr.mnemonic == 'call':
                try:
                    if int(instr.op_str, 16) == ignore_calls_addr:
                        return False
                except ValueError:
                    # Keep going
                    pass
            return instr.mnemonic in ('ret', 'jmp', 'call', 'jne', 'je', 'jg', 'jl', 'jo', 'jno',
                                       'jp', 'jnp', 'jz', 'jnz', 'jb', 'jc', 'js', 'jns', 'ja', 'jbe',
                                       'jl', 'jle', 'jg', 'jge', 'jae', 'jnb', 'jnc', 'jns', 'jno', 'jnp',)

        offset = 0
        size = 0
        
        for instr in self.disasm.disasm(data, address):
            # print(f"0x{instr.address:x}:\t{instr.mnemonic}\t{instr.op_str}")
            size += instr.size
            offset += instr.size
            if is_end_of_basic_block(instr, self.trace_address):
                break

        # if size != pc_table_bb_size:
        #     print(f"Size of basic block at {hex(address)}: {size}, {pc_table_bb_size if pc_table_bb_size is not None else ''}")                
        return size

    def get_bb_start(self, bb_start):
        if self.pcs is not None:
            bb_index = bb_start
            if bb_index >= 0 and bb_index < len(self.pcs):
                return self.pcs[bb_index][0]
        print(f"Basic block {hex(bb_index)} not found in PCTable")
        return 0

    def get_bb_size(self, bb_start):
        if bb_start in self.bbs:
            return self.bbs[bb_start]

        bb_size = self.find_basic_block_size(
            memoryview(self.text_data)[bb_start - self.code_offset:],
            bb_start
        )

        self.bbs[bb_start] = bb_size
        return bb_size

def generate_merged_file_name(base_file, aggregate, base_dir=None):
    if base_dir is None:
        # Get the base file directory
        base_dir = os.path.dirname(base_file)
    if aggregate is None:
        merged_name = "merged.drcov"
    else:
        # Get the creation time of the base file
        creation_time = os.path.getctime(base_file)
        # Convert the creation time to a string based on the aggregate
        if aggregate == "s":
            creation_time_str = time.strftime("%Y%m%d%H%M%S", time.gmtime(creation_time))
        elif aggregate == "m":
            creation_time_str = time.strftime("%Y%m%d%H%M", time.gmtime(creation_time))
        elif aggregate == "h":
            creation_time_str = time.strftime("%Y%m%d%H", time.gmtime(creation_time))
        elif aggregate == "d":
            creation_time_str = time.strftime("%Y%m%d", time.gmtime(creation_time))
        else:
            raise ValueError("Invalid aggregate value")
        merged_name = "merged_" + creation_time_str + ".drcov"
    return os.path.join(base_dir, merged_name)

def create_merged_drcov_writer(base_file_name, aggregate, base_dir=None):
    # Generate the output file name. 
    output_file = generate_merged_file_name(base_file_name, aggregate, base_dir)
    if verbose:
        print("Output file:", output_file)
    return DrcovFile(output_file)

def merge_drcov(directory, aggregate, keep=False, output_directory=None, counters=False, fix_sizes=False, 
                counters_only=False):
    # Start measuring the time
    start_time = time.time()

    files_pattern = "*.drcov.cnt" if counters_only else "*.drcov"

    # List all files in the directory with .drcov extension, sorted by time, in ascending order
    files = sorted(glob.glob(os.path.join(directory, files_pattern)), key=os.path.getmtime)

    if files is None or len(files) == 0:
        print("No files to process")
        return
    
    writer = create_merged_drcov_writer(files[0], aggregate, output_directory)
    bb_counters = defaultdict(dict)
    modules = {}
    bb_size_calcs = {}
    common_modules = {}

    def write_results():
        # use the outer scope variables
        nonlocal writer
        nonlocal bb_counters
        nonlocal modules
        nonlocal counters
        writer.write()
        if counters:
            with open(writer.file_name + ".json", "w") as f:
                md = {"modules": modules, "bb_counters": bb_counters}
                json.dump(md, f)
        writer = create_merged_drcov_writer(file, aggregate, output_directory)
        bb_counters.clear()
        modules.clear()

    # we need to get the modules from the first drcov file
    if counters_only:
        for file in files:
            # If the same file without the .cnt extension exists, we will use it to get the modules
            if file.endswith(".drcov.cnt"):
                drcov_file = file[:-4]
                if os.path.exists(drcov_file):
                    if verbose:
                        print(f"Using modules from {drcov_file}")
                    common_modules = drcov.DrcovData(drcov_file).modules
                    break


    print(f"Found {len(files)} files")
    for file in tqdm.tqdm(files):
        # Skip the files that start with merged
        if os.path.basename(file).startswith("merged"):
            continue
        # Process each input file
        if verbose:
            print("Processing file:", file)

        # should we start a new file?
        if generate_merged_file_name(file, aggregate, output_directory) != writer.file_name:
            if verbose:
                print("Starting new file")
            write_results()

        if not counters_only:
            try:
                DrcovData = drcov.DrcovData(file)
            except Exception as e:
                print("Error processing file:", file)
                print(e)
                continue
            current_modules = DrcovData.modules
            bbs = DrcovData.bbs
        else:
            current_modules = common_modules
            # bbs will be set once we read the counter file
        
        cnt_reader = None
        cnt_file = file if counters_only else file + ".cnt"
        if os.path.exists(cnt_file):
            if verbose:
                print("Processing counter file:", cnt_file)
            try:                
                cnt_reader = DrcovBasicBlockWithCounterReader(cnt_file)
                cnt_reader.close()
                if counters_only:
                    bbs = [drcov.DrcovBasicBlock(key.start, key.size, key.mod_id) for key in cnt_reader.bbs.keys()]
            except Exception as e:
                print("Error processing file:", file)
                print(e)
                continue
        else:
            cnt_file = None

        if verbose:
            print("# of modules:", len(current_modules))
        if verbose:
            print("# of basic blocks:", len(bbs))
        # First check we have compatible modules
        if not counters_only:
            for _, mods in current_modules.items():
                compatible = True
                for m in mods:
                    if not writer.check_module_compatible(m.id, m.path, m.base, m.end):
                        if verbose:
                            print("Incompatible module found, starting new file")
                        write_results()
                        compatible = False
                        break
                if not compatible:
                    break

        for _, mods in current_modules.items():
            for m in mods:
                writer.add_module(m.id, m.path, m.base, m.end)
                modules[m.id] = {"path": m.path, "base": hex(m.base), "end": hex(m.end)}
                if fix_sizes and m.id not in bb_size_calcs and m.id == 0: # an optimization, we don't need to calculate the size of the basic blocks for all modules
                    bb_size_calcs[m.id] = DrcovBasicBlockSizeCalculator(m.path, verbose=verbose)

        for bb in tqdm.tqdm(bbs):
            if verbose:
                print(f"{hex(bb.start), hex(bb.size)}")
            bb_clone = copy(bb) # we need to clone the bb, because we will modify it
            if fix_sizes and bb.mod_id in bb_size_calcs:
                if bb.size == 0:
                    bb.start = bb_size_calcs[bb.mod_id].get_bb_start(bb.start)
                    bb.size = bb_size_calcs[bb.mod_id].get_bb_size(bb.start)
                elif bb.size == 1: 
                    bb.size = bb_size_calcs[bb.mod_id].get_bb_size(bb.start)
                if verbose:
                    print(f"{hex(bb.start), hex(bb.size)}")
            bb_exists = writer.add_bb(bb)  
            if counters:
                def get_bb_counter(bb):
                    if cnt_reader is not None and bb in cnt_reader:
                        if verbose:
                            print(f"Counter for {hex(bb.start)}: {cnt_reader[bb]}")
                        return cnt_reader[bb][1]
                    return 0
                
                if not bb_exists:
                    if bb.mod_id not in bb_counters:
                        # bb_counters[bb.mod_id] = defaultdict(int)
                        bb_counters[bb.mod_id] = defaultdict(lambda: (0, 0))
                # bb_counters[bb.mod_id][hex(bb.start)] += get_bb_counter(bb_clone)
                (_, cur_bb_count) = bb_counters[bb.mod_id][hex(bb.start)]
                bb_counters[bb.mod_id][hex(bb.start)] = (bb.size, cur_bb_count + get_bb_counter(bb_clone))

        if not keep:
            os.remove(file)
            if cnt_file is not None:
                os.remove(cnt_file)

    write_results()
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)

"""
A class that uses pyelftools to return the file and line of a given address in a given executable
TODO - This is not working correctly, need to fix it. 
I wanted to parse the Elf once to save time, but the filenames for the embedded library code are all wrong
Some addresses could not be found so there is a need to find the closest address as well
"""
# from elftools.elf.elffile import ELFFile
# from elftools.dwarf.dwarfinfo import DWARFInfo
# from elftools.dwarf.descriptions import describe_DWARF_expr

# class ElfAddressToLine:
#     def __init__(self, file_name, verbose=False):
#         self.file_name = file_name
#         with open(file_name, 'rb') as f:
#             self.elffile = ELFFile(f)
#             self.dwarfinfo = self.elffile.get_dwarf_info()
#             self.addresses = {}
#             self.verbose = verbose
#             self._read_line_table()

#     def _read_line_table(self):
#         if self.dwarfinfo is None:
#             print(f"ELF file {self.file_name} has no DWARF info.")
#             return
        
#         # Iterate over all the compilation units in the DWARF information
#         print(f"Processing DWARF info for {self.file_name}")
#         for CU in tqdm.tqdm(self.dwarfinfo.iter_CUs()):
#             if self.verbose:
#                 print(f"Processing CU: {CU.get_top_DIE().attributes['DW_AT_name'].value.decode('utf-8')}")
#             try:
#                 line_program = self.dwarfinfo.line_program_for_CU(CU)

#                 # Look for the address in the line program's sequence
#                 for entry in line_program.get_entries():
#                     if entry.state is None:
#                         continue
#                     if entry.state.address is not None:
#                         filename = line_program.header.file_entry[entry.state.file - 1].name.decode('utf-8')
#                         line = entry.state.line
#                         self.addresses[entry.state.address] = (filename, line)
#             except Exception as e:
#                 print(f"Error processing CU: {e}")
#                 continue


#     def get_file_line(self, address):
#         if self.addresses is None:
#             return None, None
#         if address in self.addresses:
#             return self.addresses[address]
#         else:
#             print(f"Address {hex(address)} not found in {self.file_name}")
#         # TODO - find the closest address
#         return None, None

def symbolize(args):
    # check whether llvm-symbolizer is available
    if not os.path.exists(args.symbolizer):
        print(f"Symbolizer {args.symbolizer} not found")
        exit(1)
    
    if args.coverage_info is not None:
        # Create a dictionary of files, lines, and their execution counts
        coverage_info = defaultdict(lambda: defaultdict(int))
        if not os.path.exists(args.coverage_info):
            print(f"Coverage info file {args.coverage_info} not found")
            exit(1)

        # Read the coverage info file
        with open(args.coverage_info, "r") as f:
            """
            The coverage.info file has the following format:
            SF:<path to source file>
            FN:<function name>
            FNDA:<function name>:<count>
            DA:<line number>,<execution count>[,<checksum>]
            LF:<line number>,<execution count>
            end_of_record # terminates the file

            In the files generated by drcov2cov only S and DA records are present
            """
            curr_file = None
            for i, line in enumerate(f):
                if line.startswith("SF:"):
                    curr_file = line.split(":")[1].strip()
                    # Convert the path to the absolute path
                    curr_file = os.path.abspath(curr_file)
                    coverage_info[curr_file] = defaultdict(int)
                elif line.startswith("DA:"):
                    if curr_file is None:
                        print(f"Error: DA record found before SF record at line {i} in {args.coverage_info} file")
                        exit(1)
                    parts = line.split(":")[1].split(",")
                    file_line = int(parts[0])
                    count = int(parts[1])
                    coverage_info[curr_file][file_line] = count
                elif line.startswith("end_of_record"):
                    curr_file = None

    py_symbolizers = {}
    with open(args.input, "r") as f:
        data = json.load(f)
        for k, v in data["bb_counters"].items():
            mod_path = data["modules"][k]["path"]

            if args.verbose:
                print(f"Module {k}: ")
            
            # v1 is a tuple (size, count)
            for k1, v1 in tqdm.tqdm(v.items()):
                # Run this loop for each address in the BB, from k1 to k1 + v1[0]
                # We need to run llvm-symbolizer for each address
                # But we can combine them in a single call 
                addresses = []
                for i in range(v1[0]):
                    addresses.append(hex(int(k1, 16) + i))
                addresses_str = " ".join(addresses)

                # Run llvm-symbolizer and capture its output
                cmd = f"{args.symbolizer} -e={mod_path} --functions=linkage --inlining=false {addresses_str}"
                p = os.popen(cmd)
                output = p.read()
                p.close()
                if args.verbose:
                    print(f"  {addresses_str} (size{v1[0]}): {v1[1]} times")
                    print(output)
                if coverage_info is not None:
                    # The llvm-symbolizer output is in the following format (for each address):
                    # <function name>\n<source file>:<line number>:<column number>\n\n
                    # We need to extract the source file and line number
                    lines = output.split("\n")

                    for i, addr in enumerate(addresses):
                        # Note that we currently discard the function information
                        # Maybe we could add it, but I haven't looked at this yet
                        parts = lines[i * 3 + 1].strip().split(":")
                        if len(parts) > 1:
                            file = parts[0].strip()
                            if not file.startswith("??"):
                                file = os.path.abspath(file)
                            line = int(parts[1].strip())
                            # NOTE - we don't have a way to reflect the column number in the coverage.info file
                            if file in coverage_info:
                                if line not in coverage_info[file]:
                                    if args.verbose:
                                        print(f"    Line {line} not found in coverage info file, adding it")
                                coverage_info[file][line] = v1[1]
                                if args.verbose: 
                                    print(f"    Line {line}: {coverage_info[file][line]} times")
                            else:
                                if file != "??":
                                    if args.verbose:
                                        print(f"    File {file} not found in coverage info file, adding it")
                                    coverage_info[file] = defaultdict(int)
                                    coverage_info[file][line] = v1[1]
                            
                            # # Symbolize using pyelftools
                            # pfile, pline = py_symbolizers[mod_path].get_file_line(int(k1, 16))
                            # if args.verbose: 
                            #     print(f" Python Symbolizers:   {pfile}: {pline}")
                        
    if args.coverage_info is not None:
        if args.coverage_info_output is None:
            args.coverage_info_output = args.coverage_info
            print(f"Overwriting {args.coverage_info} file")
        else:
            print(f"Writing to {args.coverage_info_output} file")
        # Write the updated coverage info file
        with open(args.coverage_info_output, "w") as f:
            for file, lines in coverage_info.items():
                f.write(f"SF:{file}\n")
                sorted_lines = sorted(lines.items(), key=lambda x: x[0])
                for line, count in sorted_lines:
                    f.write(f"DA:{line},{count}\n")
                f.write("end_of_record\n")

# A function that parses the PCTable from an ELF file
# This table is generated when -fsanitize-coverage=pc-table is specified
# The table is a list of the structures below, each one representing a basic block
# struct PcTableEntry {
#     size_t addr,
#     size_t flags,
# };
# The table resides in the sancov_pcs section
# Unfortunately, the BBs are not in the strict order of the code,
# But maybe if we reorder them we can find the sizes of the basic blocks                                                              
def parsePCTable(elf_file, verbose = False) -> List[Tuple[int, int]]:
    with open(elf_file, 'rb') as f:
        elffile = ELFFile(f)
        # Determine the pointer size from the ELF class
        pointer_size = 4 if elffile.elfclass == elffile.header['e_ident']['EI_CLASS'] == ENUM_EI_CLASS['ELFCLASS32'] else 8

        # Find the .sancov_pcs section
        sancov_pcs = None
        for section in elffile.iter_sections():
            if section.name == '__sancov_pcs':
                sancov_pcs = section
                break

        if sancov_pcs is None:
            print(f"No .sancov_pcs section found in {elf_file}")
            return None

        data = sancov_pcs.data()
        pcs = []
        for i in range(0, len(data), 2 * pointer_size):
            addr = int.from_bytes(data[i:i+pointer_size], byteorder='little')
            flags = int.from_bytes(data[i+pointer_size:i+2*pointer_size], byteorder='little')
            if verbose:
                print(f"pctable #{i} addr 0x{addr:x}: 0x{flags:x}")
            pcs.append((addr, flags))
        return pcs
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility to merge files in DrCov format")
    parser.add_argument("-d", "--directory", type=str, help="Directory to process", default=".")
    parser.add_argument("-od", "--output-directory", type=str, help="Output directory")
    parser.add_argument("-a", "--aggregate", choices=["s", "m", "h", "d"], help="Aggregate per second|minute|hour|day")
    parser.add_argument("-k", "--keep", action="store_true", help="Keep the original files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    # Generate block counters for a merged file
    parser.add_argument("-c", "--counters", action="store_true", help="Generate block counters for a merged file")
    parser.add_argument("-f", "--fix-sizes", action="store_true", help="Disassembles the .text section of the module and fixes the basic block sizes in the drcov file")
    parser.add_argument("-co", "--counters-only", action="store_true", help="Generate merged files from .cnt files only. A single .drcov file must be present in the directory as a source for the modules")

    subparsers = parser.add_subparsers(dest='command')

    # Add a parser for the 'convert' command
    convert_parser = subparsers.add_parser('convert')
    convert_parser.add_argument("-i", "--input", required=True, help="Input drcov file")
    convert_parser.add_argument("-o", "--output", required=True, help="Output drcov file")
    convert_parser.add_argument("-d", "--allow-duplicates", action="store_true", help="Allow duplicate basic blocks in the output file")

    # Add a parser for the 'symbolize' command
    symbolize_parser = subparsers.add_parser('symbolize')
    symbolize_parser.add_argument("-i", "--input", required=True, help="Input JSON file")
    symbolize_parser.add_argument("-s", "--symbolizer", help="LLVM Symbolizer", default="llvm-symbolizer")
    symbolize_parser.add_argument("-c", "--coverage-info", help="The name of input coverage.info")
    symbolize_parser.add_argument("-co", "--coverage-info-output", help="The name of input coverage.info. If not specified, the input file will be overwritten.")
    symbolize_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # Add a parser for the 'pc-table' command
    pc_table_parser = subparsers.add_parser('pc-table')
    pc_table_parser.add_argument("-i", "--input", required=True, help="Input ELF file")
    pc_table_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    verbose = args.verbose
    if args.command == "convert":
        drcov_data = drcov.DrcovData(args.input)
        writer = DrcovFile(args.output, args.allow_duplicates)
        for _, mods in drcov_data.modules.items():
            for m in mods:
                writer.add_module(m.id, m.path, m.base, m.end)
        for bb in tqdm.tqdm(drcov_data.bbs):
            writer.add_bb(bb)                   

        writer.write()
    elif args.command == "symbolize":
        symbolize(args)
    elif args.command == "pc-table":
        parsePCTable(args.input, args.verbose)
    else:
        merge_drcov(args.directory, args.aggregate, args.keep, 
                    args.output_directory, args.counters, 
                    args.fix_sizes, args.counters_only)
