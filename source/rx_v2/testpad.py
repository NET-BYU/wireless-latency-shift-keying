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
    
    config_path = sys.argv[1]
    
    new_rec = WlskReceiver(config_path,True,l.DEBUG)
    
    new_rec.start_receiver()
    if not new_rec.windowFileMode:
        message = new_rec.block_until_message()
        og_bits = [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1]
        print(og_bits)
        success = 0 
        for i,bit in enumerate(message):
            if message[i] == og_bits[i]:
                success += 1
        print(f"success rate: {success / len(message)}")
        
        new_rec.stop_receiver()
        
        print(message)



# [1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,0]