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
BEACON_SNIFFS = 30                      #   num of beacons to find before syncing time
# REFLECTION PARAMETERS:
SRC_ADDR = 'DE:AD:BE:EF:DE:AD'          #   for wlsk TX
# REVOLVER INFO:
RPI_NODE = '192.168.0.156'              #   wlsk-pt-node
G_HOME = '192.168.86.98'                #   My Google home
SPORT = 25565
# MAC ADDRESSES:
SHERI_AND_KUZ = '9c:4f:5f:08:27:7e'     #   Sheri and kuz (neighbor @ home)
BYU_IOT_EB = '60:26:ef:b2:28:a2'        #   BYU-IOT-EB
# INTERFACES:
LC_ETH = 'eno1'                         #   lab computer ethernet
LC_WIFI = 'wlp1s0mon'                   #   lab computer wifi
PC_ETH = 'enx98fc84e63579'              #   laptop ethernet dongle 
PC_WIFI = 'wlp2s0mon'                   #   laptop wifi interface

def _sniff_beacons(pipe) -> None:
    # grab start reference from _send_pings
    global start_time, loggy
    # list of times that will be averaged
    times = []
    packet_count = 0
    def isBeacon(packet,MAC):
        return (packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8 and packet.addr2 == MAC)
    
    def process_packet(packet):
        nonlocal packet_count
        if isBeacon(packet,BYU_IOT_EB): # <---------------
            # determinant logic only works if we get beacons every 102ms.
            offset = ((time.time()-start_time) * 1000) % 102.4
            times.append(offset)
            loggy.debug("%03d found MAC: %s with offset: %fms" %(packet_count, packet.addr2, offset))
            packet_count += 1
            if packet_count >= BEACON_SNIFFS:
                pipe.send(np.mean(times))
                loggy.info("offset {}".format(np.mean(times)))
        return
                
    sniff(iface=LC_WIFI,prn=lambda pkt: process_packet(pkt), stop_filter=lambda _: packet_count >= BEACON_SNIFFS) # <---------------
    return


def _send_pings(pipe) -> None:
    global start_time,loggy # to become self.start_time
    loggy.info("PROCESS - Beginning Ping Process")
    
    # This should be replaced with the resolver later.
    target_ip = RPI_NODE # <---------------
    src_addr = SRC_ADDR # <---------------
    sequence = 0
    
    # original ping time is given by this function for slightly better accuracy
    start_time = time.time()
    while True:
        # Create the packet: sport is mutable; dport is 80
        # currently this iteration of WLSK will slow down your minecraft server...
        packet = Ether(src=src_addr) / IP(dst=target_ip) / TCP(seq=sequence,sport=25565,dport=80,flags="S")
        loggy.debug("PINGER - {}".format(packet))
        # send the packet out
        sendp(packet, iface=LC_ETH, verbose=False,count = 1) # <---------------
        # sequence numbers start at 0 and go up.
        # You can only run the receiver for 6.8 years straight due to integer limits.
        sequence += 1
        # this set the interval in leiu of the parameter
        time.sleep(0.005)


def _sniff_packets(queue) -> None:
    sniff_filter = 'tcp port 25565'
    
    def process_packet(packet):
        global loggy
        if packet.haslayer(TCP):
            seq = packet[TCP].seq
            ackId = packet[TCP].ack
            ackR = ackId - 1
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            if dport == 80 and sport == 25565:
                outgoing = True
            elif dport == 25565 and sport == 80:
                outgoing = False
            else:
                return        
            if outgoing:
                queue.put((seq, packet.time, 0))
                loggy.debug("SNIFFER - seq: {} ack: {} (outgoing)".format(seq,ackId))
            else:
                queue.put((ackR, packet.time, 1))
                loggy.debug("SNIFFER - seq: {} ack: {} (incoming)".format(seq,ackId))
        else:
            print("SNIFFER - EH??? : {}".format(packet))
                
    sniff(iface=LC_ETH,prn=lambda pkt: process_packet(pkt),filter=sniff_filter) # <---------------
    return


if __name__ == "__main__":
    
    # set up logger
    loggy = l.getLogger(__name__)
    loggy.setLevel(l.DEBUG)
    formatter = l.Formatter('%(levelname)s - %(message)s')
    console_handler = l.StreamHandler()
    console_handler.setLevel(l.INFO)
    console_handler.setFormatter(formatter)
    loggy.addHandler(console_handler)

    # GLOBALS
    start_time = 0
    processing_queue = multiprocessing.Queue()
    pkt_list = [{},{},{}]
        
    p_offset_t, p_offset_g = multiprocessing.Pipe()
    p_pktsend_t, p_pktsend_g = multiprocessing.Pipe()
    # Create processes
    ping_process = multiprocessing.Process(target=_send_pings, args=(p_pktsend_t,))
    saver_process = multiprocessing.Process(target=_sniff_packets, args=(processing_queue,))
    # receiver_process = multiprocessing.Process(target=_sniff_beacons, args=(p_pktsend_g,))
    # Start Processes
    ping_process.start()
    saver_process.start()
    # receiver_process.start()
    looptimer = time.time()
    while (time.time() - looptimer) < 3:
        pkt_num, pkt_time, out = processing_queue.get()
        loggy.debug("IMPORT - Got pkt: {} {} {}".format(pkt_num,pkt_time,out))
        pkt_list[out][pkt_num] = pkt_time
        if out == 1:
            pkt_list[2][pkt_num] = pkt_list[1][pkt_num] - pkt_list[0][pkt_num]
    
    loggy.info("items: {} {} {}\nlist:\n{}".format(len(pkt_list[0]),len(pkt_list[1]),len(pkt_list[2]),pkt_list[2]))
    
    ping_process.join()
    # receiver_process.join()

