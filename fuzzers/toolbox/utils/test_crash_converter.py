import json
from FTB.ProgramConfiguration import ProgramConfiguration
from FTB.Signatures.CrashInfo import ASanCrashInfo
from crash_converter import convert_crash
from pathlib import Path
import pytest

def test_convert_crash():
    # Path to the sample metadata file
    metadata_file = Path('./test.metadata')

    # Convert the crash
    converted_crash = convert_crash(metadata_file)

    # Parse the converted crash
    crash_info = converted_crash.splitlines()

    # Create an ASanCrashInfo object from the converted crash
    config = ProgramConfiguration("test", "x86-64", "windows")
    crashInfo = ASanCrashInfo(
        [],
        crash_info,
        config,
    )

    # Check the backtrace
    assert len(crashInfo.backtrace) == 27
    assert crashInfo.backtrace[0].startswith("backtrace::backtrace::dbghelp::trace")

if __name__ == '__main__':
    pytest.main()
