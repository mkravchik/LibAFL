import ctypes
import sys

# Constants
ATTACH_PARENT_PROCESS = -1
CTRL_C_EVENT = 0

# Load the kernel32.dll
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

def log_error(message):
    """
    Logs the given error message to a file.

    :param message: The error message to be logged.
    """
    with open("error_log.txt", "a") as file:
        file.write(f"{message}\n")

def get_error_message(error_code):
    """
    Retrieve a human-readable error message for the given error code.

    :param error_code: The error code to look up.
    :return: A string with the error message.
    """
    # Create a buffer for the error message
    buffer = ctypes.create_unicode_buffer(256)
    
    # Ask Windows to fill the buffer with the error message
    ctypes.windll.kernel32.FormatMessageW(
        0x00001000, # FORMAT_MESSAGE_FROM_SYSTEM
        None,
        error_code,
        0,
        buffer,
        len(buffer),
        None
    )
    
    # Return the error message
    return buffer.value

def get_last_error():
    """
    Retrieves the last error message from GetLastError.
    """
    error = ctypes.get_last_error()

    # Return the error code and the error message 
    # as a formatted string
    
    return f'{error, get_error_message(error)}'




def free_console():
    """
    Detaches the calling process from its console.
    """
    kernel32.FreeConsole()

def attach_to_console(pid):
    """
    Attaches to the console of the specified process.

    :param pid: Process ID of the target process.
    :return: True if successful, False otherwise.
    """
    return kernel32.AttachConsole(pid) != 0

def send_ctrl_c(pid):
    """
    Sends a CTRL+C signal to the process group of the given PID after attaching to its console.

    :param pid: Process ID to which the CTRL+C signal will be sent.
    """
    free_console()
    if attach_to_console(pid) or attach_to_console(ATTACH_PARENT_PROCESS):
        if not kernel32.GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0):  # 0 for the current process group
            error = get_last_error()
            log_error(f"Failed to send CTRL+C. Error code: {error}")
        else:
            print(f"CTRL+C signal sent successfully to the process group of PID {pid}")
    else:
        error = get_last_error()
        log_error(f"Failed to attach to console. Error code: {error}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        log_error("Usage: python script.py <PID>")
        sys.exit(1)

    try:
        target_pid = int(sys.argv[1])
        send_ctrl_c(target_pid)
    except ValueError:
        log_error("Invalid PID entered. Please enter a numeric PID.")
