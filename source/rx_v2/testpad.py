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
    
    config_path = "/home/enas2001/Documents/WLSK_tests/wireless-latency-shift-keying/config/wlsk-config-2-1.json"
    new_rec = WlskReceiver(config_path,True,l.DEBUG,doGraphs=False)
    
    signal_handler_with_processes = partial(signal_handler, new_rec.processes)
    signal.signal(signal.SIGINT, signal_handler_with_processes)
    
    new_rec.start_receiver()
    
    # message = new_rec.block_until_message()
    
    # new_rec.stop_receiver()
    