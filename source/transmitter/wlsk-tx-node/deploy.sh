#!/bin/bash
# Performs an install of this software on a new Raspberry Pi. 
# or if input arg is "apponly" then will only update an existing node
# Pi should be imaged as described in readme.md 


if [[ "$1" == "apponly" ]]; then 
    echo "copying app to target device"
    scp deploy/wlsk-tx-node-app.py pi@wlsk-tx-node.local:/home/pi/wlsk-tx-node

    echo "restarting system service"
    ssh pi@wlsk-tx-node.local 'sudo systemctl restart wlsk-tx-node.service' 
else
    echo "creating folder on target device"
    ssh pi@wlsk-tx-node.local 'mkdir /home/pi/wlsk-tx-node'

    echo "copying files to pi"
    scp deploy/* pi@wlsk-tx-node.local:/home/pi/wlsk-tx-node

    echo "running setup script on pi"
    ssh pi@wlsk-tx-node.local 'sudo sh /home/pi/wlsk-tx-node/wlsk-tx-node-setup.sh'

    echo "finished"
fi