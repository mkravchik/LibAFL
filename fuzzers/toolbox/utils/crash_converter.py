import argparse
import json
import re

class AsanCrashFormatter:
  """
  A class that formats ASan-like crashes.

  Attributes:
    crash_info (dict): A dictionary containing crash information.
    registers (dict): A dictionary containing register values.
    backtrace_frames (list): A list of backtrace frames.

  Methods:
    append_crash_info(address, code=0x0, additional_info={}, type=""):
      Appends crash information to the crash_info dictionary.
    append_register(key, value):
      Appends a register value to the registers dictionary.
    append_backtrace_frame(address, function_name, module_name, source_file, line_number):
      Appends a backtrace frame to the backtrace_frames list.
    output():
      Formats the crash information and returns it as a string.
  """

  def __init__(self):
    self.crash_info = {
      "pid": 1234,  # Default value
      "address": 0x0,
      "code": 0x0,
      "additional_info": {},
      "type": "",
    }
    self.registers = {}
    self.backtrace_frames = []

  def append_crash_info(self, address, code=0x0, additional_info={}, type=""):
    """
    Appends crash information to the crash_info dictionary.

    Args:
      address (int): The address of the crash.
      code (int, optional): The code of the crash. Defaults to 0x0.
      additional_info (dict, optional): Additional information about the crash. Defaults to {}.
      type (str, optional): The type of the crash. Defaults to "".
    """
    self.crash_info["address"] = address
    self.crash_info["code"] = code
    self.crash_info["additional_info"] = additional_info
    self.crash_info["type"] = type

  def append_register(self, key, value):
    """
    Appends a register value to the registers dictionary.

    Args:
      key (str): The register key.
      value (int): The register value.
    """
    self.registers[key] = value

  def append_backtrace_frame(self, address, function_name, module_name, source_file, line_number):
    """
    Appends a backtrace frame to the backtrace_frames list.

    Args:
      address (str): The address of the frame.
      function_name (str): The name of the function.
      module_name (str): The name of the module.
      source_file (str): The source file of the frame.
      line_number (str): The line number of the frame.
    """
    self.backtrace_frames.append(
      f"{address} in {function_name} {source_file}:{line_number} ({module_name})"
    )

  def output(self):
    """
    Formats the crash information and returns it as a string.

    Returns:
      str: The formatted crash information.
    """
    output = [
      f"=={self.crash_info['pid']}==ERROR: AddressSanitizer: {self.crash_info['type']} on unknown address {self.crash_info['address']} "
      + (f"(pc {self.registers['pc']} " if self.registers.get('pc') else "")
      + (f"bp {self.registers['bp']} " if self.registers.get('bp') else "")
      + (f"sp {self.registers['sp']} " if self.registers.get('sp') else ""),
    ]
    for i, frame in enumerate(self.backtrace_frames):
      output.append(f"#{i} {frame}")
    return "\n".join(output)


def convert_crash(metadata_file):
  """
  Converts a metadata file to a formatted crash.

  Args:
    metadata_file (str): The path to the metadata file.

  Returns:
    str: The formatted crash information.
  """
  try:
    with open(metadata_file, 'r') as f:
      metadata = json.load(f)
  except Exception as e:
    print(f"Error loading metadata file: {e}")
    return

  formatter = AsanCrashFormatter()
  for key, value in metadata['metadata']['map'].items():
    if isinstance(value[1], list) and value[1][0] == "toolbox::crash_stack::BacktraceMetadata":
      stack = value[1][1:]
      for frame in stack:
        symbols = frame['symbols']
        name_match = re.search(r'name: (Some\(\"(.*?)\"\)|None)', symbols)
        addr_match = re.search(r'addr: (Some\((.*?)\)|None)', symbols)
        filename_match = re.search(r'filename: (Some\(\"(.*?)\"\)|None)', symbols)
        lineno_match = re.search(r'lineno: (Some\((.*?)\)|None)', symbols)

        if name_match and name_match.group(2):
          function_name = name_match.group(2)
        else:
          function_name = frame["symbol_address"]

        if addr_match and addr_match.group(2):
          address = addr_match.group(2)
        else:
          address = frame["ip"]

        if filename_match and filename_match.group(2):
          file_name = filename_match.group(2)
        else:
          file_name = "unknown"

        if lineno_match and lineno_match.group(2):
          file_line = lineno_match.group(2)
        else:
          file_line = "unknown"

        module_offset = hex(int(address, 16) - int(frame['module_base_address'], 16))
        module_name = "unknown"
        formatter.append_backtrace_frame(address, function_name, module_name, file_name, file_line)

  res = formatter.output()
  print(res)
  return res


def main():
  """
  The main function of the crash converter utility.
  Parses command line arguments and converts the crash.
  So far, the LibAFL metadata is converted to Asan-like text crash format.
  Only the backtrace is converted, other details of crash information are not avaiable yet.
  """
  parser = argparse.ArgumentParser(description='Crash Converter Utility')
  parser.add_argument("-m", '--metadata-file', help='Path to the metadata file')
  args = parser.parse_args()

  convert_crash(args.metadata_file)


if __name__ == '__main__':
  main()
