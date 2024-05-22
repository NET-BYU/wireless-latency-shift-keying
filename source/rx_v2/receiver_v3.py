from multiprocessing import Process, Queue, Value, Event
from scapy.all import Ether, IP, TCP, Dot11
from decoder_utils import WlskDecoderUtils
from scipy.signal import find_peaks
import matplotlib.pyplot as plt
import multiprocessing as mlti
from scapy.all import *
from enum import Enum, auto
from random import randint
import logging as l
import numpy as np
import subprocess
import shutil
import socket
import json
import os
LOG_PKTS = 15
LOG_DMPS = 16
LOG_OPS = 17
l.addLevelName(LOG_PKTS,"Log Packets")
l.addLevelName(LOG_DMPS,"Log Data Dumps")
l.addLevelName(LOG_OPS,"Log Operations")
        

class WlskReceiver:
    '''
    This is not the receiver you are looking for.
    NOTE TO SELF GO CHECK YOUR COMMENTS!!
    '''
    VERSION = 2.1
    class Request(Enum):
        '''
        enum for packet requests. Requests come in the form (type, ref_time):
        - type (Request): the request type.
        - ref_time (float): the referenced time of the request. For SYNC/MSG, this is a start time moving forward. For DELETE, it references backwards.
        '''
        def __init__(self,type: float,time: float) -> None:
            self.type = type
            self.ref_time = time
            return
        
    def __init__(self,config_path: string,log_to_console: bool=False,log_level: int=None,logfile: string=None) -> None:
        
        self.l = l.getLogger(__name__)
        self.l.setLevel(log_level)
        formatter = l.Formatter('WLSK: %(levelname)s - %(message)s')
        # Logger parameters: can do either a logfile, to console, or both
        if log_to_console:
            console_handler = l.StreamHandler()
            console_handler.setLevel(log_level)
            console_handler.setFormatter(formatter)
            self.l.addHandler(console_handler)
        if logfile != None:
            file_handler = l.FileHandler(logfile)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            self.l.addHandler(file_handler)

        # set up variables with required default values
        self.isInitalized:      bool    = False
        self.msg_output_dir:    string  = None
        self.DELETE_REQ:        int     = -999
        self.utils                      = WlskDecoderUtils()
        
        # Other variables to be used        | Description of the Variable           | Units
        self.rx_interface:      string      # wired or wireless, for sending pings  
        self.ping_interval:     float       # rate at which pings are sent          | seconds
        self.global_timeout:    int         # if no message is received, turn off   | seconds
        self.target_ip:         string      # ip to be target with the ping packets 
        self.src_addr:          string      # packet address for TX to detect pings 
        self.sport:             int         # port that the receiver listens with   
        self.dport:             int         # should always be port 80              
        self.sync_word:         list        # list of bits making up sync word      
        self.SYNC_WORD_LEN:          int         # length of the sync word; auto-gen     | bits
        self.barker:            list        # list of bits making up the barker code
        self.BARK_WORD_LEN:          int         # length of the barker code; auto-gen   | bits
        self.PACKET_SIZE:       int         # length of the packets expected to get | bits
        self.DEC_TIMEOUT:       int         # for the decoder requests; ignore this | seconds
        self.WINDOW_EDGE:       int         # how much extra to request than normal | seconds
        self.ROLLOVER:          int         # if no sync word is found, clear old data
        self.SYNC_WINDOW:       float       # length of decoder requests for sync   | seconds
        self.MSG_WINDOW:        float       # length of decoder requests for msgs   | seconds
        self._doBeaconSniff:    bool        # ** this doesn't really work, but it might later **
        self.beacon_interface:  string      # wireless only; listens for beacon packets
        self.beacon_ssid:       string      # name of the wifi beacon to listen for
        self.beacon_mac:        string      # MAC address of the beacon  to listen to
        self.num_of_sniffs:     int         # how many beacons to average to find the offset
        
        ''' multiprocessing variables:
        - global_time: time that the receiver starts listening (for coordination)
        - _isrunning: whether the processes continue looping - NOT the same as self.running()
        - packet_tx,rx: pipe used to send sniff packets from sniffer to manager
        - request_tx,rx: pipe used to send requests and replies between manager and decoder
        - process_queue: queue for sniffed packet processing
        - decoding_queue: queue for windows to be decoded
        - message_queue: queue where messages are output to
        '''
        self.global_time                    = mlti.Value('d',-1.0)
        self.__isrunning                    = mlti.Value('b',False)
        self.process_queue                  = mlti.Queue()
        self.decoding_queue                 = mlti.Queue()
        self.message_queue                  = mlti.Queue()
        self.packet_tx, self.packet_rx      = mlti.Pipe()
        self.request_tx, self.request_rx    = mlti.Pipe()
        
        ''' Processes:
        - process 0: pinger. Sends pings at interval specified in config.
        - process 1: sniffer. Listens to all outgoing and incoming pings.
        - process 2: manager. Organizes the traffic and creates RTTS etc.
        - process 3: decoder. Makes requests from the manager to decode messages.
        '''
        self.processes = []
        self.processes.append(mlti.Process(target= self._send_wlsk_pings))
        self.processes.append(mlti.Process(target= self._sniff_ping_packets))
        self.processes.append(mlti.Process(target= self._packet_manager))
        self.processes.append(mlti.Process(target= self._request_and_decode))
        
        # attempt to load the initalizer. THIS DOES NOT CRASH ON FAIL. (Should it?)
        self.initialize(config_path)
        
    def initialize(self,configuration: string) -> bool:
        self.isInitalized = False
        self.l.info("HEAD - Initializing receiver...")
        try:
            with open(configuration,'r') as file:
                config_data = json.load(file)
                version = config_data["version"]
                if version != self.VERSION:
                    raise ValueError("")
                
                rxp = config_data["rx_parameters"]
                self.rx_interface       = rxp["rx_interface"]
                self.ping_interval      = rxp["rx_ping_interval"]
                self.global_timeout     = rxp["rx_timeout_limit"]
                self.target_ip          = rxp["pkt_target_ip"]
                self.src_addr           = rxp["pkt_src_addr"]
                self.sport              = rxp["pkt_source_port"]
                self.dport              = rxp["pkt_dest_port"]
                
                dec = config_data["decoding"]
                self.sync_word          = dec["sync_word"]
                
                self.barker             = dec["barker_code"]
                
                self.PACKET_SIZE        = dec["packet_length"]
                self.DEC_TIMEOUT        = dec["decoder_timeout"]
                self.WINDOW_EDGE        = dec["window_edge"]
                self.ROLLOVER           = dec["window_rollover"]
                
                util = config_data["utilities"]
                self._doBeaconSniff     = util["use_beacon_sniffs"]
                self.beacon_interface   = util["beacon_interface"]
                self.beacon_ssid        = util["beacon_interface"]
                self.beacon_mac         = util["beacon_MAC"]
                self.num_of_sniffs      = util["num_of_sniffs"]
                
                '''some of the variables are crafted to reduce config size.'''
                self.SYNC_WORD_LEN      = len(self.sync_word)
                self.BARK_WORD_LEN      = len(self.barker)
                self.SYNC_WINDOW        = (self.SYNC_WORD_LEN * 0.102) + self.WINDOW_EDGE
                self.MSG_WINDOW         = self.SYNC_WINDOW + (self.PACKET_SIZE * self.BARK_WORD_LEN * 0.102)
                
        except ValueError:
            self.l.error("HEAD - couldn't initialize because the config file version did not match.")
        except FileNotFoundError:
            self.l.error("HEAD - couldn't initialize because the config file path given was not valid.")
        else:
            self.l.info("HEAD - Receiver initialized successfully.")
            self.isInitalized = True   
        return self.isInitalized
    
    def start_receiver(self) -> None:
        if not self.isInitalized:
            self.l.error("HEAD - Tried to start an uninitialized recevier. Fail")
            return
        elif self.running():
            self.l.warning("HEAD - cannot start a receiver that is already going.")
            return
        else:
            self.__isrunning.value = True
            for i,process in enumerate(self.processes):
                self.l.info(f"HEAD - starting process {i}")
                process.start()
            return
    
    def stop_receiver(self) -> None:
        if not self.running():
            self.l.warning("HEAD - cannot stop a receiver that isn't running.")
            return
        else:
            self.__isrunning.value = False
            self.l.info("HEAD - Attempting to stop the receiver cleanly... the decoder will likely hang, after which I'll kill it.")
            time.sleep(5)
            for process in self.processes:
                process.terminate()
            self.l.info("[remaining processes killed]")
            return
    
    def block_until_message(self) -> list:
        return self.message_queue.get()
    
    def check_for_message(self) -> bool:
        return not self.message_queue.empty()
    
    def grab_message(self) -> list:
        if not self.message_queue.empty():
            return self.message_queue.get()
        else:
            return None
    
    def running(self) -> bool:
        return any(process.is_alive() for process in self.processes)
    
    def _send_wlsk_pings(self) -> None:
        # self.l.info("HEAD - Beginning ping process")
        
        # original ping time is given by this function for slightly better accuracy
        self.global_time.value = time.time()
        
        pkt_seq_num = 0
        while self.__isrunning.value:
            # Create the packet: sport is mutable; dport is 80
            packet = Ether(src=self.src_addr) / IP(dst=self.target_ip) / TCP(seq=pkt_seq_num,sport=self.sport,dport=self.dport,flags="S")
            
            # send the packet out
            sendp(packet, iface=self.rx_interface, verbose=False,count = 1) # <---------------
            
            # sequence numbers start at 0 and go up.
            # You can only run the receiver for 6.8 years straight due to integer limits.
            pkt_seq_num += 1
            
            # this sets the interval in leiu of the parameter
            time.sleep(self.ping_interval)
            
        self.l.info("HEAD - ending pinger process")
        return
    
    def _sniff_ping_packets(self) -> None:
        # self.l.info("HEAD - Beginning sniff process")
        
        # this can be modified to better suit things in the future
        sniff_filter = f"tcp port {self.sport}"
        
        def process_packet(packet) -> None:
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
                    self.process_queue.put((seq, packet.time, 0))
                    # loggy.debug("SNIFFER - seq: {} ack: {} (outgoing)".format(seq,ackId))
                else:
                    self.process_queue.put((ackR, packet.time, 1))
                    # loggy.debug("SNIFFER - seq: {} ack: {} (incoming)".format(seq,ackId))
            else:
                self.l.error("SNIFFER - port has other traffic. Consider moving. : {}".format(packet))
                    
        sniff(iface=self.rx_interface,prn=lambda pkt: process_packet(pkt),filter=sniff_filter, stop_filter=lambda _: self.__isrunning.value == False) # <---------------
        self.l.info("HEAD - ending sniffer process")
        return
    
    def _packet_manager(self) -> None:
        # self.l.info("HEAD - Beginning saver process")
        
        pkt_list = [{},{},{}]
        waiting = False
        ready = False
        request = None
        Rtime = None
        hpkt = 0

        while self.__isrunning.value:
            # while waiting, if you get another poll, that's a problem. Too many requests.
            if self.request_rx.poll():
                if waiting:
                    self.l.error("SAVER - received messages too fast. : {}".format(self.request_rx.recv()))
                    self.__isrunning = False
                request, Rtime = self.request_rx.recv()
                self.l.debug("SAVER - recevied request with length {} at time {}".format(request, Rtime))
                waiting = True

            if (request == self.SYNC_WINDOW or request == self.MSG_WINDOW) and ready:
                lpkt = self.__determine_packet_index(pkt_list[1],Rtime)
                # self.l.debug("lpkt: {} hpkt: {}".format(lpkt,hpkt))
                # self.l.debug("full list len: {}".format(len(pkt_list[1])))
                outgoing_packets = [{k: v for k, v in d.items() if lpkt <= k <= hpkt} for d in pkt_list]
                # self.l.debug("outgoing packet_list size: {}".format(len(outgoing_packets[1])))
                self.decoding_queue.put(outgoing_packets)
                self.l.debug("SAVER - sent response window")
                waiting, ready, request, Rtime = False, False, None, None
                
            elif request == self.DELETE_REQ and ready:
                delpkt = self.__determine_packet_index(pkt_list[1],Rtime)
                # loggy.debug("delpkt: {}".format(delpkt))
                for key in list(pkt_list[1].keys()):
                    if key < delpkt:
                        del pkt_list[0][key]
                        del pkt_list[1][key]
                        del pkt_list[2][key]
                self.decoding_queue.put([0])
                waiting, ready, request, Rtime = False, False, None, None
                # loggy.debug("Full stack (post):\nSET0: {}\nSET1: {}\nSET2: {}".format(pkt_list[0],pkt_list[1],pkt_list[2]))
            
            # get a packet : layer 0 = outgoing, 1 = incoming
            pkt_num, pkt_time, layer = self.process_queue.get()
            # loggy.debug("SAVER - Got pkt: {} {} {}".format(pkt_num,pkt_time,layer))
            
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
                if Rtime is not None and pkt_time - Rtime > request:
                    ready = True
                    hpkt = self.__determine_packet_index(pkt_list[1],(Rtime + request))
            
        self.l.info("HEAD - ending saver process")
        return
    
    def _request_and_decode(self) -> None:
        # self.l.info("HEAD - Beginning decoder process")
        time.sleep(3)
        request_time = self.global_time.value
        while self.__isrunning.value:
            try:
                self.l.debug("DECODE - request for time {} with window {}".format(request_time,self.SYNC_WINDOW))
                self.request_tx.send((self.SYNC_WINDOW,request_time))
                stack_in = self.decoding_queue.get(timeout=self.DEC_TIMEOUT)
                self.l.debug("DECODE - response window received")
                # process that request for sync word
                sunk = self.__find_sync_word(stack_in)
                if sunk:
                    self.l.info("DECODE - request for time {} with msg-window {}".format(request_time,self.SYNC_WINDOW))
                    self.request_tx.send((self.MSG_WINDOW,request_time))
                    stack_in = self.decoding_queue.get(timeout=self.DEC_TIMEOUT)
                    self.l.debug("DECODE - response window received")
                    message = self.__decode_message(stack_in)
                    self.message_queue.put(message)
                    self.l.debug("DECODE - message put to queue.")
                    self.l.info("DECODE - Sending delete request for time {}".format(request_time + self.MSG_WINDOW))
                    self.request_tx.send((self.DELETE_REQ,request_time + self.MSG_WINDOW))
                    stack_in = self.decoding_queue.get(timeout=self.DEC_TIMEOUT)
                    self.l.debug("DECODE - response window received")
                    if stack_in[0] != 0:
                        self.l.error("DECODE - got invalid stack return on delete. Quitting")
                        self.__isrunning.value = False
                else:
                    # self.l.info("DECODE - request {} returned nothing".format(request_time))
                    request_time += 1
            except Exception as e:
                self.l.error("DECODE - an exception occured: {}".format(e))
                self.__isrunning.value = False
        self.l.info("HEAD - ending decoder process")
        return
    
    def __find_sync_word(self,stack: list) -> bool:
        cutoff = 10000
        rts_array = np.array([stack[1].get(i, -0.1) for i in range(max(stack[1].keys()) + 1)])
        # self.l.debug("SYNC: rts_array: {}".format(rts_array))
        toa_dist, _ = self.utils.toa_distribution(rts_array)
        toa_dist = toa_dist[0:]
        xcorr = self.utils.correlate(raw_data=toa_dist, code=self.sync_word,window_size=75)
        sync_indices = np.where(xcorr[:cutoff] > xcorr.std()*2)[0]
        if len(sync_indices) != 0:
            self.l.debug("SYNC: found sync word!")
            return True
        self.l.debug("SYNC: didn't find sync word.")
        return False
    
    def __decode_message(self,stack: list) -> list:
        time.sleep(7)
        self.l.debug("--DECODE word test finished--")
        return [1,0,1,0,1,0,1,0,1,0]
    
    def __determine_packet_index(self, item_list: list, threshold: float) -> int:
        sorted_items = sorted(item_list.items(), key=lambda x: x[1])
        # loggy.debug("sorted vals:\n{}".format(sorted_items))
        highest_key = None
        for key,value in sorted_items:
            if value >= threshold:
                highest_key = 0 if (highest_key == None) else highest_key
                break
            highest_key = key
        # loggy.debug("KEY RETURN IS: {}".format(highest_key))
        return highest_key