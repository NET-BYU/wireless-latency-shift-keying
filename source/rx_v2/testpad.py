from receiver_v3 import WlskReceiver
import logging as l
import time

if __name__ == "__main__":
    
    new_rec = WlskReceiver("/home/enas2001/Documents/WLSK_tests/wireless-latency-shift-keying/config/wlsk-config-2-1.json",True,l.DEBUG)

    new_rec.start_receiver()
    
    message = new_rec.block_until_message()
    
    new_rec.stop_receiver()
    
    print(message)