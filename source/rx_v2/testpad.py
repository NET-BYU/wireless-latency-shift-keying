from receiver_v3 import WlskReceiver
import logging as l
import time

if __name__ == "__main__":
    
    new_rec = WlskReceiver("/home/enas2001/Documents/WLSK_tests/wireless-latency-shift-keying/config/wlsk-config-2-1.json",True,l.DEBUG)
    
    # new_rec._WlskReceiver__isrunning.value = True
    # new_rec._send_wlsk_pings()
    # time.sleep(3)
    # new_rec.__isrunning.value = False
    new_rec.start_receiver()
    
    message = new_rec.block_until_message()
    # time.sleep(7)
    
    # new_rec.stop_receiver()
    
    # print(message)