# TODO - rewrite in Rust using frida-rust crate

import time
import frida
import threading
import sys

# Set up a threading event for synchronization
script_loaded_event = threading.Event()
process_exited_event = threading.Event()

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] From Frida: " + message['payload'])
        if message['payload'] == "Script loaded":
                    script_loaded_event.set()    
    elif message['type'] == 'error':
        print("[!] Frida Error: " + message['stack'])

def on_detached(reason):
    print("[!] Detached from process: " + reason)
    process_exited_event.set()

# Your existing code to set up Frida session
device = frida.get_local_device()
# pid = device.spawn(["test.exe", "-f", "test\\ok_input.txt"])
pid = device.spawn(sys.argv[1:])
# session = device.attach(pid)
# session.on('detached', on_detached)

# # Read the Frida script
# with open("frida_inject.js", "r") as f:
#     script_code = f.read()

# # Create the script
# script = session.create_script(script_code)

# # Connect the message handler
# script.on('message', on_message)

# # Load the script
# script.load()

# # Wait for the script to be fully loaded
# script_loaded_event.wait()

# session.detach()

# Sleep for 30 seconds to allow debugger to attach
# print("Sleeping for 60 seconds...")
# time.sleep(60)

# Continue with your process (e.g., resuming the process)
device.resume(pid)

# Wait for the process to exit
process_exited_event.wait()

print("Done!")

