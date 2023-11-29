# target_script.py
import time

try:
    while True:
        print("Running...")
        time.sleep(2)
except KeyboardInterrupt:
    print("Ctrl+C received, stopping.")
