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

def send_packets(pipes):
    # This should be replaced with the resolver later
    p_end, p_send = pipes
    target_ip = "192.168.0.125"
    src_addr = "DE:AD:BE:EF:DE:AD"
    seq = 0
    while not p_end.poll():
        # This is where it should send a packet every 5ms
            # print("Sending TCP SYN frames to {} on channel {}".format(target_ip, channel))
        packet = Ether(src=src_addr) / IP(dst=target_ip) / TCP(seq=seq,dport=80,flags="S")
        seq += 1
        p_send(packet)
        sendp(packet, iface="eno1", verbose=False)
        time.sleep(0.005)
        # Kill feature (for exiting / safety)

def packet_saver(pipe):
    count = 0
    while True:
        print("SUB %04d " %(count))
        count += 1  
        if pipe.poll():
            offset = pipe.recv()
            print(f"\nreceived go: {offset}ms offset\n")
            break
        time.sleep(0.5)
     
def sniff_beacons(pipe):
    global start_time
    times = []
    packet_count = [1]
    target_count = 51
    def isBeacon(packet,MAC):
        return (packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8 and packet.addr2 == MAC)
    def process_packet(packet_count,packet):
        if isBeacon(packet,'60:26:ef:b2:28:a2'):
            # determinant logic only works if we get beacons every 102ms.
            dif_time = time.time()
            offset = ((dif_time-start_time) * 1000) % 102.4
            times.append(offset)
            l.debug("%03d found MAC: %s with SSID: %s at Time: %f" %(packet_count[0], packet.addr2, packet.info,times[-1]))
            
            packet_count[0] += 1
            if packet_count[0] >= target_count:
                pipe.send(np.mean(times))
                return
        return
    sniff(iface="wlp1s0mon",prn=lambda pkt: process_packet(packet_count,pkt), stop_filter=lambda _: packet_count[0] >= target_count)


if __name__ == "__main__":
    loggy = l.getLogger(__name__)
    loggy.setLevel(l.DEBUG)
    start_time = time.time()
    p_save_t, p_save_g = multiprocessing.Pipe()
    p_sendstop_t, p_sendstop_g = multiprocessing.Pipe()
    p_pktsend_t, p_pktsend_g = multiprocessing.Pipe()
    # Create processes
    sender_process = multiprocessing.Process(target=send_packets, args=((p_sendstop_g,p_pktsend_t),))
    saver_process = multiprocessing.Process(target=packet_saver, args=(p_save_g,))
    receiver_process = multiprocessing.Process(target=sniff_beacons, args=(p_save_t,))
    # Start Processes
    sender_process.start()
    saver_process.start()
    receiver_process.start()
    # Wait for processes to finish
    sender_process.join()
    receiver_process.join()

