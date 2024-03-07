#!/bin/bash
# check if venv directory exists
if [ ! -d "venv" ]; then
  # create venv directory using python3
  python3 -m venv venv
fi
# activate venv
source venv/bin/activate
# install dependencies from requirements.txt
pip install -r requirements.txt
sudo pip install -r requirements.txt