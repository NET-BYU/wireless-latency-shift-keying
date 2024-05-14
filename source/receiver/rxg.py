from wlsk_receiver import WlskReceiver
import logging

testRec = WlskReceiver("./config/wlsk-general-config.json",log_dest='console')

testRec.receive(69)

