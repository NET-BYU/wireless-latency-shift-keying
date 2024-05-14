from receiver_v2 import WlskReceiver
import logging

if __name__ == "__main__":
    testRec = WlskReceiver("./config/wlsk-general-config.json",log_dest='console')
    testRec.receive(69)

