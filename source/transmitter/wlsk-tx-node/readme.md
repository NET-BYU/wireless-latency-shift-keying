# WLSK TX Node Test Software 
This package enables quick setup of the Raspberry Pi as a test harness for a WLSK transmitter. 

This software does the following:
1. Sets the mDNS name to allow other devices to find it on a network
2. Sets up a MQTT broker that other devices in the test can connect to and communicate test commands to each other
3. Launches a GUI on a 3.5" TFT screen 

## Prerequisites 
- Raspberry Pi 4
- Adafruit 3.5" TFT screen(https://www.adafruit.com/product/2097)
- ESP32 Dev board (Pre-installed wilth the ESP32_beracon_sync_tx software)

## Setup
To Setup the Pi: 
1. Setup the image with the Raspberry Pi OS Imager [(see screenshot here)](raspi-imager-config.png)
2. Run the deploy script on a host PC to set up the raspberry pi over SSH


## Test commands 
From main test PC: 
- Ensure that this device is connected to the network
- Connect to the MQTT broker 
- publish commands to the `transmit_test_dataset` topic. Message format is
```json
{"test_number":3}
```
where the test number is the dataset index ranging from 0-9 that should be transmitted. 