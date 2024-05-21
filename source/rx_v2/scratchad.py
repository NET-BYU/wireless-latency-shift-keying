import multiprocessing
import multiprocessing.process
from scapy.all import Ether, IP, TCP, Dot11
import matplotlib.pyplot as plt
from scapy.all import *
from enum import Enum, auto
import logging as l
import numpy as np
import subprocess
import shutil
import socket
import json
import os

# "TIMESTAMP" INFO
NUM_SYNC_BITS = 31
NUM_BARKER_BITS = 11
NUM_MESSAGE_BITS = 10
WINDOW_EDGE = 4
SYNC_TIME = NUM_SYNC_BITS * 0.102
MSG_TIME = NUM_BARKER_BITS * NUM_MESSAGE_BITS * 0.102
SYNC_WINDOW = SYNC_TIME + WINDOW_EDGE
MSG_WINDOW = SYNC_TIME + MSG_TIME + WINDOW_EDGE
# NUM BEACON SNIFFS
BEACON_SNIFFS = 20                      #   num of beacons to find before syncing time
# REFLECTION PARAMETERS:
SRC_ADDR = 'DE:AD:BE:EF:DE:AD'          #   for wlsk TX
# REVOLVER INFO:
RPI_NODE = '192.168.0.156'              #   wlsk-pt-node
G_HOME = '192.168.86.98'                #   My Google home
SPORT = 25565
PING_INT = 0.005
# MAC ADDRESSES:
SHERI_AND_KUZ = '9c:4f:5f:08:27:7e'     #   Sheri and kuz (neighbor @ home)
BYU_IOT_EB = '60:26:ef:b2:28:a2'        #   BYU-IOT-EB
# INTERFACES:
LC_ETH = 'eno1'                         #   lab computer ethernet
LC_WIFI = 'wlp1s0mon'                   #   lab computer wifi
PC_ETH = 'enx98fc84e63579'              #   laptop ethernet dongle 
PC_WIFI = 'wlp2s0mon'                   #   laptop wifi interface

# def _sniff_beacons(pipe) -> None:
#     global start_time, loggy
#     loggy.info("HEAD - beginning beacon detection process")
#     # list of times that will be averaged
#     times = []
#     packet_count = 0
#     def isBeacon(packet,MAC):
#         return (packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 8 and packet.addr2 == MAC)
    
#     def process_packet(packet):
#         nonlocal packet_count
#         if isBeacon(packet,BYU_IOT_EB): # <---------------
#             # determinant logic only works if we get beacons every 102ms.
#             offset = ((time.time()-start_time) * 1000) % 102.4
#             times.append(offset)
#             # loggy.debug("%03d found MAC: %s with offset: %fms" %(packet_count, packet.addr2, offset))
#             packet_count += 1
#             if packet_count >= BEACON_SNIFFS:
#                 packet_offset = math.ceil(np.mean(times) / 5)
#                 pipe.send(packet_offset)
#                 loggy.info("offset {}".format(packet_offset))
#         return
    
#     sniff(iface=LC_WIFI,prn=lambda pkt: process_packet(pkt), stop_filter=lambda _: packet_count >= BEACON_SNIFFS) # <---------------
#     return

def _send_pings(pipe,stopped) -> None:
    global start_time,loggy
    loggy.info("HEAD - Beginning Ping Process")
    
    # This should be replaced with the resolver later.
    target_ip = RPI_NODE # <---------------
    src_addr = SRC_ADDR # <---------------
    sequence = 0
    
    # original ping time is given by this function for slightly better accuracy
    start_time = time.time()
    
    while not stopped.value:
        # Create the packet: sport is mutable; dport is 80
        packet = Ether(src=src_addr) / IP(dst=target_ip) / TCP(seq=sequence,sport=SPORT,dport=80,flags="S")
        # loggy.debug("PINGER - {}".format(packet))
        
        # send the packet out
        sendp(packet, iface=LC_ETH, verbose=False,count = 1) # <---------------
        
        # sequence numbers start at 0 and go up.
        # You can only run the receiver for 6.8 years straight due to integer limits.
        sequence += 1
        
        # this sets the interval in leiu of the parameter
        time.sleep(PING_INT)
    loggy.info("HEAD - pinger ended.")
    return


def _sniff_packets(queue, stopped) -> None:
    global loggy
    loggy.info("HEAD - beginning sniff process")
    
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
                # loggy.debug("SNIFFER - seq: {} ack: {} (outgoing)".format(seq,ackId))
            else:
                queue.put((ackR, packet.time, 1))
                # loggy.debug("SNIFFER - seq: {} ack: {} (incoming)".format(seq,ackId))
        else:
            print("SNIFFER - EH??? : {}".format(packet))
                
    sniff(iface=LC_ETH,prn=lambda pkt: process_packet(pkt),filter=sniff_filter, stop_filter=lambda _: stopped.value == True) # <---------------
    loggy.info("HEAD - sniffer ended.")
    return

class Request(Enum):
    '''
    enum for packet requests. Requests come in the form (type, ref_time):
    - type (Request): the request type.
    - ref_time (float): the referenced time of the request. For SYNC/MSG, this is a start time moving forward. For DELETE, it references backwards.
    '''
    SYNC = SYNC_WINDOW
    MSG = MSG_WINDOW
    DELETE = auto()
    WINDOW = 4

def _save_packets(Pqueue_in,Rqueue_out,requestee,stopped) -> None:
    global start_time, loggy
    loggy.info("HEAD - beginning packet save process")
    
    pkt_list = [{},{},{}]
    waiting = False
    ready = False
    request = None
    Rtime = None
    hpkt = 0
    
    def find_starting_packet(list,threshhold) -> int:
        sorted_items = sorted(list.items(), key=lambda x: x[1])
        # loggy.debug("sorted vals:\n{}".format(sorted_items))
        highest_key = None
        for key,value in sorted_items:
            if value >= threshhold:
                highest_key = 0 if (highest_key == None) else highest_key
                break
            highest_key = key
        # loggy.debug(highest_key)
        return highest_key
    
    while not stopped.value:
         
        # while waiting, if you get another poll, that's a problem. Too many requests.
        if requestee.poll():
            if waiting:
                loggy.error("SAVER - received messages too fast. : {}".format(requestee.recv()))
                stopped.value = True
            request, Rtime = requestee.recv()
            waiting = True

        if request == Request.SYNC or request == Request.MSG and ready:
            lpkt = find_starting_packet(pkt_list[1],Rtime)
            outgoing_packets = [{k: v for k, v in d.items() if lpkt <= k <= hpkt} for d in pkt_list]
            Rqueue_out.put(outgoing_packets)
            # loggy.debug("lpkt: {} hpkt: {}".format(lpkt,hpkt))
            # loggy.debug("full list len: {}".format(len(pkt_list[1])))
            waiting, ready, request, Rtime = False, False, None, None
            
        elif request == Request.DELETE:
            delpkt = find_starting_packet(pkt_list[1],Rtime)
            # loggy.debug("delpkt: {}".format(delpkt))
            for key in list(pkt_list[1].keys()):
                if key < delpkt:
                    del pkt_list[0][key]
                    del pkt_list[1][key]
                    del pkt_list[2][key]
            # loggy.debug("Full stack (post):\nSET0: {}\nSET1: {}\nSET2: {}".format(pkt_list[0],pkt_list[1],pkt_list[2]))
            request, Rtime = None, None
        
        # get a packet : layer 0 = outgoing, 1 = incoming
        pkt_num, pkt_time, layer = Pqueue_in.get()
        # loggy.debug("IMPORT - Got pkt: {} {} {}".format(pkt_num,pkt_time,out))
        
        # save the packet time in its corresponding layer
        pkt_list[layer][pkt_num] = pkt_time
        
        # if the packet is incoming, also calculate the rtt layer
        if layer == 1:
            rtt = pkt_list[1][pkt_num] - pkt_list[0][pkt_num]
            if rtt > 0 and rtt < .5:
                pkt_list[2][pkt_num] = rtt
            else:
                pkt_list[2][pkt_num] = -.01
            # loggy.debug("IMPORT - RTT calc: {}, {}".format(pkt_num,pkt_list[2][pkt_num]))
            # only ask on incoming messages because otherwise the keys don't line up
            if Rtime is not None and pkt_time - Rtime > request.value:
                ready = True
                hpkt = find_starting_packet(pkt_list[1],Rtime + request.value)
        
    loggy.info("HEAD - save packets ended.")
    return

def _decode_chunks(Rqueue_in,Mqueue_out,requester, stopped) -> None:
    while not stopped.value:
        test_time = time.time()
        loggy.debug("test time: {}".format(test_time))
        time.sleep(2)
        requester.send((Request.MSG,test_time))
        # requester.send((Request.MSG,test_time))
        loggy.debug("Sending request")
        test_stack = Rqueue_in.get()
        loggy.debug("test stack:\n{}".format(test_stack[1]))
        time.sleep(2)
        requester.send((Request.DELETE,test_time + Request.MSG.value))
        break
        # make a request for TIME_WINDOW worth of data
        # process that request for sync word
            # If sync word found:
                # make request for message worth of data
                # decode the data > queue_out
                # make dump request
            # if sync word not found:
                # adjust values for next request
    loggy.info("HEAD - decoder ended.")
    return

def listen_for_messages(msg_queue) -> list:
    return msg_queue.get()
    
    
if __name__ == "__main__":
    
    # set up logger
    loggy = l.getLogger(__name__)
    loggy.setLevel(l.DEBUG)
    formatter = l.Formatter('%(levelname)s - %(message)s')
    console_handler = l.StreamHandler()
    console_handler.setLevel(l.DEBUG)
    console_handler.setFormatter(formatter)
    loggy.addHandler(console_handler)

    # GLOBALS
    start_time = 0
    processing_queue = multiprocessing.Queue()
    decoding_queue = multiprocessing.Queue()
    message_queue = multiprocessing.Queue()
    process_killer = multiprocessing.Value('b', False)
    # offset_tx, offset_rx = multiprocessing.Pipe()
    pktsend_tx, pktsend_rx = multiprocessing.Pipe()
    request_tx, request_rx = multiprocessing.Pipe()
    
    # Create processes
    ping_process = multiprocessing.Process(target=_send_pings, args=(pktsend_tx,process_killer))
    sniffer_process = multiprocessing.Process(target=_sniff_packets, args=(processing_queue,process_killer))
    # receiver_process = multiprocessing.Process(target=_sniff_beacons, args=(offset_tx,))
    saver_process = multiprocessing.Process(target=_save_packets, args=(processing_queue,decoding_queue,request_rx,process_killer))
    decoder_process = multiprocessing.Process(target=_decode_chunks, args=(decoding_queue,message_queue,request_tx,process_killer))
    
    # Start Processes
    ping_process.start()
    sniffer_process.start()
    # receiver_process.start()
    saver_process.start()
    decoder_process.start()
    
    loggy.info("SYSTEM - press enter to kill the receiver.")
    input()
    process_killer.value = True
    time.sleep(2)
    ping_process.terminate()
    sniffer_process.terminate()
    saver_process.terminate()
    decoder_process.terminate()

