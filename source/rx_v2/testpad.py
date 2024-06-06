from receiver_v3 import WlskReceiver
from functools import partial
import logging as l
import signal
import time
import sys

def signal_handler(processes, signal, frame):
    print("Ctrl+C caught, terminating processes...")
    for p in processes:
        p.terminate()
    for p in processes:
        p.join()
    print("All processes terminated.")
    sys.exit(0)

if __name__ == "__main__":
    
    new_rec = WlskReceiver("config/wlsk-config-2-1.json",True,l.DEBUG)
    
    new_rec.start_receiver()
    
    # message = new_rec.block_until_message()
    
    # new_rec.stop_receiver()
    
    # print(message)
