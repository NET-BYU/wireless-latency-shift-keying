import os
import subprocess
import json
import time
import paho.mqtt.client as mqtt
import serial
import socket
import sys
from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QPushButton
from PyQt5.QtCore import QTimer, Qt, QTime
import threading
import re

# Function to handle incoming MQTT messages
def on_message(client, userdata, msg):
    payload = msg.payload.decode('utf-8')
    try:
        data = json.loads(payload)
        test_number = data.get('test_number')
        print("received {}".format(data))
        if test_number is not None:
            # Send the command to the ESP32 over UART
            # Replace this line with your UART communication code
            global ser
            ser.write([test_number + 48])
            resp = {
                "node": "wlsk-tx-node",
                "status": "transmitting",
                "data_set": test_number
            }
            client.publish("admin", json.dumps(resp))
            
    except ValueError as e:
        print(f"Invalid JSON: {e}")


# Connect to the MQTT broker
def connect_mqtt_broker():
    mqtt_broker = "localhost"  # Change this if your MQTT broker is on a different machine
    mqtt_port = 1883  # Change this if your MQTT broker is using a different port

    client = mqtt.Client()
    client.on_message = on_message

    try:
        client.connect(mqtt_broker, mqtt_port, 60)
        client.loop_start()
        print("Connected to MQTT broker.")
    except ConnectionRefusedError:
        print("Failed to connect to MQTT broker.")

    return client

def get_wifi_rssi():
    try:
        global ser
        while ser.in_waiting > 0: # Get the most recent measurement
            data = ser.readline().decode()
            print("on serial line:",data)
        rssi = int(data.strip().split(': ')[1]) # if this fails it will throw an exception meaning it probably wasn't a valid RSSI
        return rssi
    except:
        pass
    return None
    # try:
    #     output = subprocess.check_output(["iwconfig", "wlan0"])  # Replace "wlan0" with the appropriate interface name
    #     output = output.decode("utf-8")
    #     rssi_match = re.search(r"Signal level=(-\d+)", output)
    #     if rssi_match:
    #         rssi = int(rssi_match.group(1))
    #         return rssi
    # except subprocess.CalledProcessError:
    #     pass
    # return None


# Main function
def main():
    # Connect to ESP32 over Serial
    global ser
    try:
        ser = serial.Serial('/dev/ttyUSB0',115200,timeout=1)
    except:
        print("can not connect to esp32")
        exit(1)

    mqtt_client = connect_mqtt_broker()
    mqtt_topic = "transmit_test_dataset"  # Replace with your MQTT topic
    mqtt_client.subscribe(mqtt_topic)
    print(f"Subscribed to MQTT topic: {mqtt_topic}")
    
    while True:
        time.sleep(1)  # Keep the script running
        resp = {
            "node": "wlsk-tx-node",
            "RSSI": get_wifi_rssi()
        }
        mqtt_client.publish("rssi", json.dumps(resp))


if __name__ == '__main__':
    main()