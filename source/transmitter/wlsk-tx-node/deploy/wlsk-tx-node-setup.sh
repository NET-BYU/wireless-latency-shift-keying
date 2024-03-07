#!/bin/bash

# Create Log file 
cd /home/pi/wlsk-tx-node
touch /home/pi/wlsk-tx-node/setup_log.txt
echo "Starting.." > /home/pi/wlsk-tx-node/setup_log.txt

# Check for previously completed installation
if [ -e "setup_complete"]; then 
    echo "Setup previously completed. Aborting.." >> /home/pi/wlsk-tx-node/setup_log.txt
fi

# Install dependencies 
echo "Installing dependencies.." >> /home/pi/wlsk-tx-node/setup_log.txt
sudo apt update 
sudo apt install -y qmlscene 
sudo apt install -y git python3-pip
sudo apt install -y mosquitto 
pip3 install --upgrade adafruit-python-shell click
pip3 install paho-mqtt
# git clone https://github.com/adafruit/Raspberry-Pi-Installer-Scripts.git

# # Enable 3.5" TFT screen
# echo "Starting Adafruit 3.5 in TFT driver" >> /home/pi/wlsk-tx-node/setup_log.txt
# sudo python3 /home/pi/wlsk-tx-node/Raspberry-Pi-Installer-Scripts/adafruit-pitft.py --display=35r --rotation=90 --install-type=fbcp

# Enable mosquitto MQTT broker to run at boot
echo "Installing MQTT broker and Python Libraries" >> /home/pi/wlsk-tx-node/setup_log.txt
sudo tee /etc/mosquitto/mosquitto.conf > /dev/null << EOL 
pid_file /run/mosquitto/mosquitto.pid
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
port 1883
allow_anonymous true
EOL
sudo systemctl enable mosquitto

# Install and enable wlsk-tx-node system service to run at boot
cp wlsk-tx-node.service /etc/systemd/system/
sudo systemctl enable wlsk-tx-node.service

# Set up Pi to auto login
# Create a new lightdm configuration file
sudo cp /etc/lightdm/lightdm.conf /etc/lightdm/lightdm.conf.bak
sudo tee /etc/lightdm/lightdm.conf > /dev/null << EOL
[SeatDefaults]
autologin-user=pi
autologin-user-timeout=0
EOL
sudo service lightdm restart


echo "Done" >> /home/pi/wlsk-tx-node/setup_log.txt
touch /home/pi/wlsk-tx-node/setup_complete
