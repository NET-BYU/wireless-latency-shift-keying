import multiprocessing
from wlsk_packet import RawWlskPingPacket
from scapy.all import Ether, IP, TCP, Dot11
import matplotlib.pyplot as plt
from scapy.all import *
import logging as l
import numpy as np
import subprocess
import shutil
import socket
import json
import os

# NUM BEACON SNIFFS
BEACON_SNIFFS = 30 
# TARGET_IPs:
RPI_NODE = '192.168.0.125'
G_HOME = '192.168.86.98'
# SOURCE ADDRESS:
SRC = 'DE:AD:BE:EF:DE:AD'
# MAC ADDRESSES:
SHERI_AND_KUZ = '9c:4f:5f:08:27:7e'   #   Sheri and kuz (neighbor @ home)
BYU_IOT_EB = '60:26:ef:b2:28:a2'      #   BYU-IOT-EB
# INTERFACES:
LC_ETH = 'eno1'                       #   lab computer ethernet
LC_WIFI = 'wlp1s0mon'                 #   lab computer wifi
PC_ETH = 'enx98fc84e63579'            #   laptop ethernet dongle 
PC_WIFI = 'wlp2s0mon'                 #   laptop wifi interface

def send_packets(pipe):
    # This should be replaced with the resolver later
    target_ip = G_HOME # <---------------
    src_addr = SRC # <---------------
    seq = 0
    while not pipe.poll():
        # This is where it should send a packet every 5ms
            # print("Sending TCP SYN frames to {} on channel {}".format(target_ip, channel))
        packet = Ether(src=src_addr) / IP(dst=target_ip) / TCP(seq=seq,dport=80,flags="S")
        seq += 1
        pipe.send(packet)
        sendp(packet, iface=PC_ETH, verbose=False) # <---------------
        time.sleep(0.005)
    return

def packet_saver(pipe):
    global loggy, start_time
    packets = []
    count = 0
    
    def process_ping(packet):
        nonlocal packets
        
    sniff(iface=PC_WIFI,prn=lambda pkt: process_ping(pkt)) # <---------------
    return
     
def sniff_beacons(pipe):
    global start_time, loggy
    times = []
    packet_count = 0
    
    def isBeacon(packet,MAC):
        return (packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8 and packet.addr2 == MAC)
    
    def process_packet(packet):
        nonlocal packet_count
        if isBeacon(packet,SHERI_AND_KUZ): # <---------------
            # determinant logic only works if we get beacons every 102ms.
            offset = ((time.time()-start_time) * 1000) % 102.4
            times.append(offset)
            loggy.debug("%03d found MAC: %s with offset: %fms" %(packet_count, packet.addr2, offset))
            packet_count += 1
            if packet_count >= BEACON_SNIFFS:
                pipe.send(np.mean(times))
        return
                
    sniff(iface=PC_WIFI,prn=lambda pkt: process_packet(pkt), stop_filter=lambda _: packet_count >= BEACON_SNIFFS) # <---------------
    return


if __name__ == "__main__":
    loggy = l.getLogger(__name__)
    loggy.setLevel(l.DEBUG)
    formatter = l.Formatter('%(levelname)s - %(message)s')
    console_handler = l.StreamHandler()
    console_handler.setLevel(l.DEBUG)
    console_handler.setFormatter(formatter)
    loggy.addHandler(console_handler)
    #GLOBAL START TIME
    start_time = time.time()
    p_offset_t, p_offset_g = multiprocessing.Pipe()
    p_pktsend_t, p_pktsend_g = multiprocessing.Pipe()
    # Create processes
    sender_process = multiprocessing.Process(target=send_packets, args=(p_pktsend_t,))
    saver_process = multiprocessing.Process(target=packet_saver, args=((p_offset_g,p_pktsend_g),))
    receiver_process = multiprocessing.Process(target=sniff_beacons, args=(p_offset_t,))
    # Start Processes
    sender_process.start()
    saver_process.start()
    receiver_process.start()
    # Wait for processes to finish
    sender_process.join()
    receiver_process.join()

