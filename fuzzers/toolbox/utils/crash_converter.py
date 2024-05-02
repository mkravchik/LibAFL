import argparse
import json
import re

# Converts the metadata file to json
def convert_crash(metadata_file):
    """
    The input metadata file is a JSON file that looks like this:
{
  "metadata": {
    "map": {
      "67040840998315034357867071195806918738": [
        67040840998315034357867071195806918738,
        "Crash"
      ],
      "151287823049168717282094736171097445375": [
        151287823049168717282094736171097445375,
        [
          "toolbox::crash_stack::BacktraceMetadata",
          {
            "ip": "0x7ff629bd928e",
            "symbol_address": "0x7ff629bd928e",
            "module_base_address": "0x7ff629af0000",
            "symbols": "BacktraceSymbol { name: Some(\"backtrace::backtrace::dbghelp::trace\"), addr: Some(0x7ff629bd9257), filename: Some(\"C:\\\\Users\\\\mkrav\\\\.cargo\\\\registry\\\\src\\\\index.crates.io-6f17d22bba15001f\\\\backtrace-0.3.69\\\\src\\\\backtrace\\\\dbghelp.rs\"), lineno: Some(98), colno: None }"
          },
          {
            "ip": "0x7ff629bd928e",
            "symbol_address": "0x7ff629bd928e",
            "module_base_address": "0x7ff629af0000",
            "symbols": "BacktraceSymbol { name: Some(\"backtrace::backtrace::trace_unsynchronized\"), addr: Some(0x7ff629bd9257), filename: Some(\"C:\\\\Users\\\\mkrav\\\\.cargo\\\\registry\\\\src\\\\index.crates.io-6f17d22bba15001f\\\\backtrace-0.3.69\\\\src\\\\backtrace\\\\mod.rs\"), lineno: Some(66), colno: None }"
          },
        ...
        ]

        What the code needs to do is to 
        1. Open the file
        2. Parse the json 
        3. Go over the map. For each value (which must be a list), check the second element in the sequence.
        4. If the second element is toolbox::crash_stack::BacktraceMetadata, then we need to build the backtrace
          using the following frames.
    """
    try:
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
    except Exception as e:
        print(f"Error loading metadata file: {e}")
        return
    
    # Fields of CrashInfo of FuzzManager
    output = {
        "rawStdout": [],
        "rawStderr": [],
        "backtrace": [],
        "registers": {},
        "crashAddress": None,
        "crashInstruction": None,
    }

    for key, value in metadata['metadata']['map'].items():
        if isinstance(value[1], list) and value[1][0] == "toolbox::crash_stack::BacktraceMetadata":
            stack = value[1][1:]
            # Now you have the backtrace, you can process it as needed...
            for frame in stack:
                # Extract function name from frame.symbols.name that looks like
                # "symbols": "BacktraceSymbol { name: Some(\"backtrace::backtrace::dbghelp::trace\"), addr: Some(0x7ff629bd9257), filename: Some(\"C:\\\\Users\\\\mkrav\\\\.cargo\\\\registry\\\\src\\\\index.crates.io-6f17d22bba15001f\\\\backtrace-0.3.69\\\\src\\\\backtrace\\\\dbghelp.rs\"), lineno: Some(98), colno: None }"
                symbols = frame['symbols']
                match = re.search(r'name: Some\(\"(.*?)\"\)', symbols)
                if match:
                    function_name = match.group(1)
                else:
                    function_name = frame["symbol_address"]    
                output["backtrace"].append(function_name)

    res = json.dumps(output, indent=4)
    print(res)
    return res

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Crash Converter Utility')
    parser.add_argument("-m",'--metadata-file', help='Path to the metadata file')
    args = parser.parse_args()

    # Convert the crash
    convert_crash(args.metadata_file)

if __name__ == '__main__':
    main()