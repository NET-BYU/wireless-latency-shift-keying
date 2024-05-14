#!/bin/zsh

echo "-This script fails if not sudo-"
# Check if nmap is installed
if ! command -v nmap &> /dev/null
then
    echo "nmap is not installed. trying to install nmap to proceed..."
    sudo apt-get install -y nmap
fi

# Perform an ARP scan using nmap to discover devices on the local network
nmap_result=$(sudo nmap 192.168.0.0/24)

# Parse the output to extract IP addresses and hostnames
ips=($(echo "$nmap_result" | grep 'Nmap scan report' | awk '{print $5}'))

# Print the IP addresses and hostnames
echo "IP addresses for targeting:"
for ((i=2; i<${#ips[@]}; i++)); do
    echo "IP: ${ips[i]}"
done
