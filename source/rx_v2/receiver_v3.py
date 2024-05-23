from multiprocessing import Process, Queue, Value, Event
from scapy.all import Ether, IP, TCP, Dot11
from decoder_utils import WlskDecoderUtils
from scipy.signal import find_peaks
import matplotlib.pyplot as plt
import multiprocessing as mlti
from scapy.all import *
import pyshark as p
from enum import Enum, auto
from random import randint
import logging as l
import numpy as np
import subprocess
import shutil
import socket
import queue
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
        self.plot_num:          int     = 0
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
        self.SYNC_WORD_LEN:     int         # length of the sync word; auto-gen     | bits
        self.barker:            list        # list of bits making up the barker code
        self.BARK_WORD_LEN:     int         # length of the barker code; auto-gen   | bits
        self.PACKET_SIZE:       int         # length of the packets expected to get | bits
        self.DEC_TIMEOUT:       int         # for the decoder requests; ignore this | seconds
        self.WINDOW_EDGE:       int         # how much extra to request than normal | seconds
        self.ROLLOVER:          int         # if no sync word is found, clear old data
        self.SYNC_REQ:          float       # length of decoder requests for sync   | seconds
        self.MSG_REQ:           float       # length of decoder requests for msgs   | seconds
        self.grab_timeout:      float       # timeout of the grab_message function  | seconds
        self._doBeaconSniff:    bool        # ** this doesn't really work, but it might later **
        self.beacon_interface:  string      # wireless only; listens for beacon packets
        self.beacon_ssid:       string      # name of the wifi beacon to listen for
        self.beacon_mac:        string      # MAC address of the beacon  to listen to
        self.num_of_sniffs:     int         # how many beacons to average to find the offset
        
        ''' multiprocessing variables:                              | Set By / Used By
        - global_start: indicates that receiver is ready to start   | pinger     /  all
        - global_stop: indicates that processes should shut down    | head       /  all
        - request_tx,rx: pipe of window requests for decoding       | decoder   <-> manager
        - process_queue: queue of raw packets to be sorted          | sniffer   --> manager
        - decoding_queue: queue of windows to be decoded            | manager   --> decoder
        - message_queue: queue of finished messages                 | decoder   --> head
        - global_noise: the noise floor for looking for sync words. | decoder    /  decoder
        - global_time: time that the receiver starts listening      | pinger     /  manager, decoder
        '''
        self.__global_start                   = mlti.Event()
        self.__global_stop                    = mlti.Event()
        self.__request_tx, self.__request_rx  = mlti.Pipe()
        self.__process_queue                  = mlti.Queue()
        self.__decoding_queue                 = mlti.Queue()
        self.__message_queue                  = mlti.Queue()
        self.__global_noise                   = mlti.Value('i',-1)
        self.__global_time                    = mlti.Value('d',-1.0)
        
        ''' Processes:
        - process 0: pinger. Sends pings at interval specified in config. primary runner.
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
                    raise ValueError("Incorrect version of the WLSK receiver config ({} vs {}).".format(version,self.VERSION))
                
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
                self.SYNC_REQ           = (self.SYNC_WORD_LEN * 0.102) + self.WINDOW_EDGE
                self.MSG_REQ            = self.SYNC_REQ + (self.PACKET_SIZE * self.BARK_WORD_LEN * 0.102)
                
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
            for i,process in enumerate(self.processes):
                # you can find the process list in __init__ under 'processes'
                process.start()
            return
    
    def stop_receiver(self) -> None:
        if not self.running():
            self.l.warning("HEAD - cannot stop a receiver that isn't running.")
            return
        
        else:
            self.__global_stop.set()
            itrs = 0
            # give it 5 seconds to try to kill itself, otherwise just finish the job
            while self.running() and itrs < 5:
                time.sleep(1)
                itrs += 1
            if self.running() and itrs >= 5:
                for process in self.processes:
                    process.terminate()
                self.l.info("[remaining processes killed after hanging - consider restarting program before continuing.]")
            return
    
    def block_until_message(self) -> list:
        return self.__message_queue.get()
    
    def has_a_message(self) -> bool:
        return not self.__message_queue.empty()
    
    def grab_message(self) -> list:
        try:
            return self.__message_queue.get(timeout=self.grab_timeout)
        except queue.Empty:
            return None
    
    def running(self) -> bool:
        return any(process.is_alive() for process in self.processes)
    
    def _send_wlsk_pings(self) -> None:
        self.l.info("HEAD - starting pinger; intvl = {}".format(self.ping_interval))
        
        # pinger sets the global time to be closest to the first ping
        self.__global_time.value = time.time()
        
        # creates a scapy socket by hand to send pings at high intervals
        # note that you still might need to set your interval slightly faster than necessary (ex. 5ms becomes 4ms)
        s = conf.L2socket(iface=self.rx_interface)
        
        # It doesn't matter what the sequence is as long as its unique; this counts up from zero.
        pkt_seq_num = 0
        
        # tell the other processes they can go
        self.__global_start.set()
        
        while not self.__global_stop.is_set():
            # Create the packet: sport is mutable; dport is 80
            packet = Ether(src=self.src_addr) / IP(dst=self.target_ip) / TCP(seq=pkt_seq_num,sport=self.sport,dport=self.dport,flags="S")
            
            # send the packet out
            s.send(packet)
            pkt_seq_num += 1
            
            # This is accurate dependant on your system OS. modern Linux is usually within ~1ms?
            # This may not work on Windows though - I read it was minimum 7-10ms with jitter.
            time.sleep(self.ping_interval)  
        self.l.info("HEAD - ending pinger process")
        return
    
    def _sniff_ping_packets(self) -> None:
        # wait until the pinger has set the time (so you don't sniff / request early)
        self.__global_start.wait()        
        self.l.info("HEAD - Beginning sniff process")
        
        # this can be modified if you need it to be
        sniff_filter = f"tcp port {self.sport}"
        
        # this is the function that actually determines whether we think it was a WLSK packet
        # https://scapy.readthedocs.io/en/latest/api/scapy.layers.inet.html#scapy.layers.inet.TCP
        def process_packet(packet) -> None:
            if packet.haslayer(TCP):
                seq = packet[TCP].seq
                ackId = packet[TCP].ack
                ackR = ackId - 1
                dport = packet[TCP].dport
                sport = packet[TCP].sport
                
                # this is essentially how we determine the WLSK packets status. Ngl it could be better
                # In fact, I want to point out this literally tells us nothing based on our current filter...
                # just pick ports that aren't popular I guess
                if dport == 80 and sport == 25565:
                    outgoing = True
                elif dport == 25565 and sport == 80:
                    outgoing = False
                else:
                    return        
                
                # to manager: packet num, time, and 'layer' (outgoing or incoming)
                self.__process_queue.put((seq if outgoing else ackR, packet.time, 0 if outgoing else 1))

            else:
                self.l.error("SNIFFER - port has other traffic. Consider moving. : {}".format(packet))
        
        def stop_sniff(packet,stop_event):
            return stop_event.is_set()
                    
        sniff(iface=self.rx_interface,prn=lambda pkt: process_packet(pkt),filter=sniff_filter, stop_filter=lambda pkt: stop_sniff(pkt,self.__global_stop)) # <---------------
        self.l.info("HEAD - ending sniffer process")
        return 
    
    def _packet_manager(self) -> None:
        # wait for pinger to give the okay
        self.__global_start.wait()
        self.l.info("HEAD - Beginning manager process")
        
        # Manager Variables
        pkt_list    = [{},{},{}]    # list of time in, time out, and rtt for each ping sent
        waiting     = False         # status of an active request; set if desired window is not ready
        ready       = False         # flag to tell manager to send the current requent window out
        request     = None          # receives the request, which is a number representing window length
        Rtime       = None          # receives the starting time index for the request, rounded to the nearest ping time
        hpkt        = 0             # the 'high' packet, or last packet considered a part of the request window

        while not self.__global_stop.is_set():
            
            # while waiting, if you get another poll, that's a problem. Too many requests.
            if self.__request_rx.poll():
                if waiting:
                    self.l.error("SAVER - received messages too fast. : {}".format(self.__request_rx.recv()))
                    self.__global_stop.set()
                request, Rtime = self.__request_rx.recv()
                waiting = True

            # both sync and msg requests are the same thing, just with a different window length
            if (request == self.SYNC_REQ or request == self.MSG_REQ) and ready:
                # calculate 'lowest' packet, or first packet considered in the window
                lpkt = self.__determine_packet_index(pkt_list[1],Rtime)
                outgoing_packets = [{k: v for k, v in d.items() if lpkt <= k <= hpkt} for d in pkt_list]
                self.__decoding_queue.put(outgoing_packets)
                waiting, ready, request, Rtime = False, False, None, None
                
            # a delete request clears all data before a certain time index to reduce list sizes and clutter
            elif request == self.DELETE_REQ and ready:
                # determine the packet idx closest to the given request time
                delpkt = self.__determine_packet_index(pkt_list[1],Rtime)
                keys_to_remove = [key for key, _ in pkt_list[1] if key <= delpkt]
                for key in keys_to_remove:
                    if key in pkt_list[0]: del pkt_list[0][key]
                    if key in pkt_list[1]: del pkt_list[1][key]
                    if key in pkt_list[2]: del pkt_list[2][key]
                # this is basically just a success code so the decoder can continue
                self.__decoding_queue.put([0,0,0])
                waiting, ready, request, Rtime = False, False, None, None
            
            # from manager: layer 0 = outgoing, 1 = incoming
            pkt_num, pkt_time, layer = self.__process_queue.get()
            
            # save the packet time in its corresponding layer
            pkt_list[layer][pkt_num] = pkt_time
            
            # if the packet is incoming, also calculate the rtt layer
            # WARNING: this system may break if packets ever get dropped. High stress environment?
            if layer == 1 and pkt_num in pkt_list[0]:
                rtt = pkt_list[1][pkt_num] - pkt_list[0][pkt_num]
                if rtt > 0 and rtt < .5:
                    pkt_list[2][pkt_num] = rtt
                else:
                    pkt_list[2][pkt_num] = -.01
                # only ask on incoming messages because otherwise the keys may not line up
                if Rtime is not None and pkt_time - Rtime > request:
                    ready = True
                    hpkt = self.__determine_packet_index(pkt_list[1],(Rtime + request))
        self.l.info("HEAD - ending manager process")
        return
  
    '''TODO with decoder:
    - add the delete request to rolling windows - i.e. if you miss the sync word in 10 windows, you don't need to keep all that data.
    - actually, maybe just send a delete request for the data everytime that the sync word fails? so that it gets less clogged. Need
    to compare the amount of time it takes to do a big vs. little delete then to see if that takes too much time w/ extra requests.
    - add the noise floor listener function: something that listens for 10 seconds to get the max normal ping variance and throws out
    windows that don't spike above that - this way you don't try to correlate against regular data.
    - go and fix the dumb __find_sync_word function because it doesn't work
    - make the dumb __decode_message function becuase right now it is a LIE'''  
    def _request_and_decode(self) -> None:
        self.__global_start.wait()
        self.l.info("HEAD - Beginning decoder process")

        time.sleep(3) # TODO: Replace with noise listening
        
        # start the first window at around the time of the first ping
        request_time = self.__global_time.value
        
        def listen_cautious(import_queue: mlti.Queue,stop_event: mlti.Event) -> list:
            '''a simple way of listening for responses on the queue while not blocking (as hard).'''
            while not stop_event.is_set():
                try:
                    item = import_queue.get(timeout=0.1)
                    return item
                except queue.Empty:
                    continue
            return None
        
        while not self.__global_stop.is_set():
            try:
                # First request: ask for a sync word sized window
                self.__request_tx.send((self.SYNC_REQ,request_time))
                stack_in = listen_cautious(self.__decoding_queue,self.__global_stop)
                # if you ever don't get a message its because __global.stop so just leave
                if stack_in == None: break 
                
                # search for the sync word in the window
                sunk = self.__find_sync_word(stack_in)
                
                if sunk:
                    # Second request: starts at the same time, but is long enough for a full message to be inside
                    self.__request_tx.send((self.MSG_REQ,request_time))
                    stack_in = listen_cautious(self.__decoding_queue,self.__global_stop)
                    if stack_in == None: break
                    
                    # decode that message now you found it
                    message = self.__decode_message(stack_in)
                    self.__message_queue.put(message)
                    
                    # Third request: flush the data that was in the manager so it doesn't get slow and cloggy :(
                    self.__request_tx.send((self.DELETE_REQ,request_time + self.MSG_REQ))
                    stack_in = listen_cautious(self.__decoding_queue,self.__global_stop)
                    if stack_in == None: break
                    
                    # this is just the success checker - if it somehow gets something else they are out of sync and should be killed
                    if stack_in[0] != 0:
                        self.__global_stop.set()
                else:
                    # if you didn't find the sync word scroll
                    request_time += 1
            except Exception as e:
                self.l.error("DECODE - an exception occured: {}".format(e))
                self.__global_stop.set()
        self.l.info("HEAD - ending decoder process")
        return
    
    def __find_sync_word(self,stack: list) -> bool:
        # I have no idea what this value means???
        cutoff = 10000

        # the array of return times
        rts_array = np.array([stack[1].get(i, -0.1) for i in range(max(stack[1].keys()) + 1)])

        # toa is a list where the index is 1ms and the value is the number of pings received
        # this used to say toa_dist, toa_distribution but the second one wasn't needed for this?
        toa_dist, _ = self.utils.toa_distribution(rts_array)

        # this correlates WAY too hard sometimes. I don't know what to tweak about it yet
        xcorr = self.utils.correlate(raw_data=toa_dist, code=self.sync_word,window_size=150)
        
        # give it a place to dumpe the plot that it creates for you
        plot_dir = "/home/enas2001/Documents/WLSK_tests/wireless-latency-shift-keying/source/rx_v2/rx_test_plots"
        # "what the plot" will replace the self.decoder.utils plotting functions.
        self.__what_the_plot(directory=plot_dir,toa_dist=toa_dist,xcorr=xcorr)
        
        # somehow this chooses the places where it could be correlating? if there is one I think it means it worked.
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
        highest_key = None
        for key,value in sorted_items:
            if value >= threshold:
                highest_key = 0 if (highest_key == None) else highest_key
                break
            highest_key = key
        return highest_key
    
    def __what_the_plot(self,directory: string,toa_dist: list,xcorr: np.ndarray,show: bool=True) -> None:
        
        fig = plt.figure(figsize=(15,15))
        fig.suptitle("Results from testing")
        
        ax1 = fig.add_subplot(3,1,1)
        ax1.title.set_text("Received packets per 1ms Interval")
        ax1.plot(toa_dist,color='black',linewidth=0.5)
        
        ax2 = fig.add_subplot(3,1,2)
        ax2.plot(xcorr,color='black',linewidth=1)
        ax2.hlines([xcorr.std()*2,xcorr.std()*-2],*ax2.get_xlim())
        ax2.title.set_text("Sync word correlation")

        if show:
            plt.show()
        plt.savefig(os.path.join(directory,"results{}.png".format(self.plot_num)),dpi=600)
        self.plot_num += 1