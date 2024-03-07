#!/bin/bash

cd /home/pi/wlsk-tx-node/
touch /home/pi/wlsk-tx-node/app_log.txt

# Run the python file 
sudo python3 wlsk-tx-node-app.py | tee /home/pi/wlsk-tx-node/app_log.txt

echo "Done" >> /home/pi/wlsk-tx-node/app_log.txt