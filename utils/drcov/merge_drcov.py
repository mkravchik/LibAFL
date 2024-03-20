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

verbose = False
# DrCov file writer based on 
# https://github.com/gaasedelen/lighthouse/blob/f4642e8b4b4347b11ccb25a79ec4f490c9ad901d/coverage/frida/frida-drcov.py

class HashableDrcovBasicBlock(drcov.DrcovBasicBlock):
    def __init__(self, block):
        self.mod_id = block.mod_id
        self.start = block.start
        self.size = block.size

    def __hash__(self):
        return hash((self.start, self.size, self.mod_id))

    def __eq__(self, other):
        if isinstance(other, HashableDrcovBasicBlock):
            return self.start == other.start and self.size == other.size and self.mod_id == other.mod_id
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
            self.bbs[HashableDrcovBasicBlock(drcov.DrcovBasicBlock(bb.start, bb.size, bb.mod_id))] = bb.count

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

def merge_drcov(directory, aggregate, keep=False, output_directory=None, counters=False):
    # Start measuring the time
    start_time = time.time()

    # List all files in the directory with .drcov extension, sorted by time, in ascending order
    files = sorted(glob.glob(os.path.join(directory, "*.drcov")), key=os.path.getmtime)

    if files is None or len(files) == 0:
        print("No files to process")
        return
    
    writer = create_merged_drcov_writer(files[0], aggregate, output_directory)
    bb_counters = defaultdict(dict)
    modules = {}

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

        try:
            DrcovData = drcov.DrcovData(file)
        except Exception as e:
            print("Error processing file:", file)
            print(e)
            continue
        
        cnt_reader = None
        cnt_file = None
        if os.path.exists(file + ".cnt"):
            cnt_file = file + ".cnt"
            if verbose:
                print("Processing counter file:", cnt_file)
            try:                
                cnt_reader = DrcovBasicBlockWithCounterReader(cnt_file)
                cnt_reader.close()
            except Exception as e:
                print("Error processing file:", file)
                print(e)
                continue

        if verbose:
            print("# of modules:", len(DrcovData.modules))
        if verbose:
            print("# of basic blocks:", len(DrcovData.bbs))
        # First check we have compatible modules
        for _, mods in DrcovData.modules.items():
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

        for _, mods in DrcovData.modules.items():
            for m in mods:
                writer.add_module(m.id, m.path, m.base, m.end)
                modules[m.id] = {"path": m.path, "base": hex(m.base), "end": hex(m.end)}
        for bb in DrcovData.bbs:
            if verbose:
                print(f"{hex(bb.start), hex(bb.size)}")
            bb_exists = writer.add_bb(bb)  
            if counters:
                def get_bb_counter(bb):
                    if cnt_reader is not None and bb in cnt_reader:
                        if verbose:
                            print(f"Counter for {hex(bb.start)}: {cnt_reader[bb]}")
                        return cnt_reader[bb]
                    return 1
                
                if not bb_exists:
                    if bb.mod_id not in bb_counters:
                        bb_counters[bb.mod_id] = defaultdict(int)
                bb_counters[bb.mod_id][hex(bb.start)] += get_bb_counter(bb)

        if not keep:
            os.remove(file)
            if cnt_file is not None:
                os.remove(cnt_file)

    write_results()
    end_time = time.time()
    print("Elapsed time:", end_time - start_time)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility to merge files in DrCov format")
    parser.add_argument("-d", "--directory", type=str, help="Directory to process", default=".")
    parser.add_argument("-od", "--output-directory", type=str, help="Output directory")
    parser.add_argument("-a", "--aggregate", choices=["s", "m", "h", "d"], help="Aggregate per second|minute|hour|day")
    parser.add_argument("-k", "--keep", action="store_true", help="Keep the original files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    # Generate block counters for a merged file
    parser.add_argument("-c", "--counters", action="store_true", help="Generate block counters for a merged file")

    subparsers = parser.add_subparsers(dest='command')

    # Add a parser for the 'convert' command
    convert_parser = subparsers.add_parser('convert')
    convert_parser.add_argument("-i", "--input", required=True, help="Input drcov file")
    convert_parser.add_argument("-o", "--output", required=True, help="Output drcov file")
    convert_parser.add_argument("-d", "--allow-duplicates", action="store_true", help="Allow duplicate basic blocks in the output file")

    # Add a parser for the 'symbolize' command
    convert_parser = subparsers.add_parser('symbolize')
    convert_parser.add_argument("-i", "--input", required=True, help="Input JSON file")
    convert_parser.add_argument("-s", "--symbolizer", help="LLVM Symbolizer", default="llvm-symbolizer")

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
        # check whether llvm-symbolizer is available
        if not os.path.exists(args.symbolizer):
            print(f"Symbolizer {args.symbolizer} not found")
            exit(1)

        with open(args.input, "r") as f:
            data = json.load(f)
            for k, v in data["bb_counters"].items():
                mod_path = data["modules"][k]["path"]
                print(f"Module {k}: ")
                for k1, v1 in v.items():
                    # Run llvm-symbolizer and capture its output
                    cmd = f"{args.symbolizer} -e={mod_path} --functions=linkage --inlining=false {k1}"
                    p = os.popen(cmd)
                    output = p.read()
                    p.close()
                    print(f"  {k1}: {v1} times")
                    print(output)
    else:
        merge_drcov(args.directory, args.aggregate, args.keep, args.output_directory, args.counters)
