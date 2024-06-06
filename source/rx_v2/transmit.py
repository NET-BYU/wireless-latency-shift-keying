import time
import matplotlib.pyplot as plt
from matplotlib import style
import json
import os
import shutil
from scapy.all import *
from scapy.all import Ether, IP, TCP, Raw
from multiprocessing import Process, Queue
import serial
import numpy as np
import socket
import subprocess
import paho.mqtt.client as mqtt
import math
from receiver_v3 import WlskReceiver

test_iter_remote_rssi = []
serial_port_names = ["/dev/ttyUSB0"]
mqtt_tx_channel_names = "TBD"
bit_sequence = [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1]

# rx = WlskReceiver()

def on_message(client, userdata, msg):
    global test_iter_remote_rssi
    payload = msg.payload.decode('utf-8')
    # print("Node Update: \n\r{}".format(payload))
    try:
        message = json.loads(payload)
        rssi = message["RSSI"]
        # print("RSSI of remote node is {}".format(rssi))
        if rssi != "None":
            if int(rssi) != 0:
                print("RSSI is {}".format(int(rssi)))
                test_iter_remote_rssi.append(int(rssi))
    except Exception as e: pass
        # print("Error decoding message from MQTT: {}".format(e))

def connect_mqtt_broker():
    mqtt_broker = "wlsk-tx-node.local"  # Change this if your MQTT broker is on a different machine
    mqtt_port = 1883  # Change this if your MQTT broker is using a different port

    client = mqtt.Client()
    client.on_message = on_message

    try:
        client.connect(mqtt_broker, mqtt_port, 60)
        client.loop_start()
        print("Connected to MQTT broker.")
    except ConnectionRefusedError:
        print("Failed to connect to MQTT broker.")
        sys.exit()

    return client

if __name__ == "__main__":
    
    mqtt_client = None
    sers = []
    
    try:
        serial_port_names = serial_port_names
        for port in serial_port_names:
            print("Using Serial port: {}".format(port))
            ser = serial.Serial(port,115200)
            sers.append(ser)
    except:
        print("Error setting up serial ports! Aborting...")
        sys.exit()
    
    test_iter_remote_rssi = []
    
    try:
        time.sleep(2)
        sers[0].write([48])
    except:
        print("Error starting a serial write to ESP32!")
        sys.exit()