from scapy.all import Ether, IP, TCP, Dot11
from decoder_utils import WlskDecoderUtils
from scipy.signal import find_peaks, correlate
import matplotlib.animation as animation
import matplotlib.pyplot as plt
import multiprocessing as mlti
from collections import deque
from enum import Enum, auto
from scapy.all import *
import pandas as pd
import logging as l
import numpy as np
import matplotlib
import datetime
from copy import copy
import queue
import json
import math
import csv
import os

LOG_PKTS = 15
LOG_DMPS = 16
LOG_OPS = 17
l.addLevelName(LOG_PKTS,"Log Packets")
l.addLevelName(LOG_DMPS,"Log Data Dumps")
l.addLevelName(LOG_OPS,"Log Operations")

''' TODO:
 - add in the rx_timeout_limit to the state machine
 - talk to Chris about making multiple instances vs. multiple lines
 - clean up the init stuff
 - review the logging states and messages
 - wrap things in user-friendliness
'''      
class Packet:
    def __init__(self,seq: int = None, tin: float = None, tout: float = None, rtt: float = None):
        self.s = seq
        self.i = tin
        self.o = tout
        self.r = rtt
    def __eq__(self, value: 'Packet') -> bool:
        return self.s == value.s
    def __str__(self) -> str:
        return f"PKT-{self.s}"

class Bucket:
    def __init__(self,mil: int = None, pkts: int = None):
        self.m = mil
        self.c = pkts
    def __eq__(self, value: 'Bucket') -> bool:
        return self.m == value.m
    def __str__(self) -> str:
        return f"BKT-{self.m}"

class Message:
    def __init__(self, tstamp: float = None, msg: list = [], length: int = 0, valid: bool = False):
        self.timestamp = tstamp
        self.message = msg
        self.msg_len = length
        self.valid = valid
    def __eq__(self, value: 'Message') -> bool:
        return (self.timestamp == value.timestamp) and (self.timestamp != None)
    def __str__(self) -> str:
        return ''.join(map(str,self.message)) if self.msg_len > 0 else '<empty>'

class WlskReceiver:
    '''
    Wireless Latency Shift Keying is a method of encoding data into network latency,
    allowing a device not in a network to communicate into the network without
    proper authentication beforehand. see the Github for more information:
    https://github.com/NET-BYU/wireless-latency-shift-keying/tree/main 
    '''
    VERSION = 3.0

    class PName(Enum):
        PINGER  = "wlsk-target-pinger"
        SNIFFER = "wlsk-packet-sniffer"
        MANAGER = "wlsk-packet-bucketer"
        DECODER = "wlsk-state-machine"
        NOISER  = "wlsk-characterizer"
        LOGGER  = "wlsk-log-utility"
        BEACON  = "wlsk-beacon-utility"
        DEBUG   = "wlsk-debug-process"
        def __str__(self):
            return self.value
    
    class Mode(Enum):
        LISTENONLY  = auto()
        READFILE    = auto()
        NORMAL      = auto()

    def __init__(self, config_path: string, mode: Mode, **kwargs) -> None:
        '''WLSK Receiver
        The only thing configured directly in the init function is the logging scheme. Everything else is stored
        in the config file, which must be specified for the receiver to work properly.
        
        Keyword Arguments:
        - config_path: string       -- the path the configuration file for the receiver.
        - mode: WLSKReceiver.Mode   -- the operating mode of the receiver.
        - kwargs: any               -- additional kwargs are listed in __init__
        '''
        
        # List of runtime variables and functions:
        #   CAPITALS are fixed objects, such as strings, classes, etc.
        #   camelCase is used for boolean values
        #   underscore_names are used for all numerical types, mutable or not
        #   _underscored variables are multiprocessing variables
        
        # Variable              | Type                  | Initial Value | Description and Units
        self.isInitalized:      bool                    = False         # did all the variables get configured properly
        self.isLogging:         bool                    = False         # determined by kwargs to run logger or not.
        # KWARGS (from __init__)
        self.MODE:              self.Mode               = mode          # the receiver's mode of operation.
        self.CONFIG:            string                  = config_path   # path to the receiver's active configuration.
        self.input_path:        string                  = None          # Kwarg for setting input file in readfile mode.
        self.output_path:       string                  = None          # Kwarg for setting output path for graphs / listen mode.
        self.logToFile:         bool                    = False         # Kwarg for enabling file logging.
        self.logToConsole:      bool                    = False         # Kwarg for enabling console logging.
        self.logPackets:        bool                    = False         # Kwarg for saving raw packets
        self.logBuckets:        bool                    = False         # Kwarg for saving millibuckets
        self.logAll:            bool                    = False         # Kwarg that sets log_to_file, log_packets, and log_buckets.
        self.doLivePlot:        bool                    = False         # Kwarg for enabling the plt animated graph.
        self.doBeaconSniffs:    bool                    = False         # Kwarg for enabling the beacon sniffing process.
        self.verbose:           bool                    = False         # Kwarg for enabling debug output.
        self.quiet:             bool                    = False         # Kwarg for disabling output entirely.
        self.debugEnabled:      bool                    = False
        # LOGGING
        self.path_pkt_csv:      string                  = None          # filepath for raw ping data
        self.path_bukt_csv:     string                  = None          # filepath for bucketed millisecond data
        self.path_logfile:      string                  = None          # filepath for logging output
        # RX_PARAMS
        self.RX_INTERFACE:      string                  = None          # wired or wireless, for sending pings  
        self.TARGET_IP:         string                  = None          # ip of target for the ping packets 
        self.SRC_ADDR:          string                  = None          # packet address for TX to detect pings 
        self.ping_interval:     float                   = 0             # rate at which pings are sent                  | unit: seconds
        self.global_timeout:    int                     = 0             # if no message is received, turn off           | unit: seconds
        self.sport:             int                     = 0             # port that the receiver listens with           | no units
        self.dport:             int                     = 80            # should always be port 80                      | no units
        # DECODER_PARAMS
        self.SYNC_WORD:         list                    = None          # list of bits making up sync word      
        self.sync_word_len:     int                     = 0             # length of the sync word; auto-gen             | unit: bits
        self.BARKER_WORD:       list                    = None          # list of bits making up the barker code
        self.bark_word_len:     int                     = 0             # length of the barker code; auto-gen           | unit: bits
        self.packet_len:        int                     = 0             # length of the packets expected to get         | unit: bits
        self.corr_thresh:       int                     = 0             # number of std. devs. to consider "correlated" | no units
        self.corr_grace:        int                     = 0             # how much extra to request than normal         | unit: milliseconds
        # GRAPH UTILS
        self.listen_only_len:   int                     = 0             # how long to listen when in Listen Only Mode   | unit: seconds
        self.listen_only_file:  int                     = 0             # the savefile number for when in Listen Only   | no units
        self.liveplot:          animation               = None          # object for the live window manager
        # BEACON UTIL
        self.BEACON_INTERFACE:  string                  = None          # wireless only; listens for beacon packets
        self.BEACON_SSID:       string                  = None          # name of the wifi beacon to listen for
        self.BEACON_MAC:        string                  = None          # MAC address of the beacon  to listen to
        self.beacon_instances:  int                     = 0             # how many beacons used to find the offset      | no units
        # UTILITIES
        self.noise_window_len:  int                     = 10            # length of initial noise analysis              | unit: seconds
        
        # MULTIPROCESSING VALUES
        self._global_start                  = mlti.Event()              # indicates processes are ready     | Set by pinger
        self._global_stop                   = mlti.Event()              # indicates receiver should stop    | Set by any
        self._pkt_queue                 = mlti.Queue()              # Queue for holding untouched pkts  | between sniffer and bucketer
        self._bkt_queue              = mlti.Queue()              # Queue for holding ms buckets      | between bucketer and FSM
        self._message_queue                 = mlti.Queue()              # Queue for holding complete msgs   | between FSM and front end
        self._characterizer_queue           = mlti.Queue()              # Queue for characterizer to use    | between FSM and characterizer
        self._pkt_log                = mlti.Queue()              # Queue for saving raw packets      | between sniffer and logger
        self._bkt_log              = mlti.Queue()              # Queue for live graph to use       | between FSM and logger
        self._global_noise                  = mlti.Value('i',1)         # global noise value for msg detect | Set by characterizer
        self._global_time                   = mlti.Value('d',1.0)       # global time for bucketing time    | Set by pinger

        # KWARG ARGUMENT PARSING
        # Get a list of the allowed parameters
        allowed_keys = ['input_path','output_path','doLivePlot',
                        'doBeaconSniffs','verbose','quiet',
                        'logToFile','logToConsole','logPackets',
                        'logBuckets','logAll','debugEnabled']
        # Detect any invalid arguments given
        illegal_keys = [key for key in kwargs if key not in allowed_keys]
        if illegal_keys:
            raise TypeError(f"Unsupported keyword argument(s): {', '.join(illegal_keys)}")
        # Set all the kwarg arguments used
        for key, value in kwargs.items():
            setattr(self,key,value)
        
        # INVALID COMBOS OF KWARGS
        # Being in a listening mode and giving an input file
        if mode != self.Mode.READFILE and self.input_path != None:
            raise SyntaxError("WLSK Error: cannot take an input file (-i) unless in file mode (-m readfile)")
        # Being in readfile mode and giving an output file
        if mode == self.Mode.READFILE and self.output_path != None:
            raise SyntaxError("WLSK Error: can't specify a new output (-o) for file mode (-m readfile), as the file already exists.",
                              "Use the plt GUI to save additional graphs if needed.")       
        # Being in readfile mode and requesting the live plotter
        if mode == self.Mode.READFILE and self.doLivePlot:
            raise SyntaxError("WLSK Error: cannot specify --show_live to a file instance (-m readfile), as it is not in real time.")
        # asking for verbose/a logfile and quiet mode at the same time
        if (self.verbose or self.logToConsole or self.logToFile) and self.quiet:
            print("WLSK Warning: quiet mode (-q) specified with logging (-v, -lf, -lc), quiet mode will win.")
        if (self.debugEnabled and not self.verbose):
            print("WLSK Warning: enabling debugging (-D) without verbose (-v) won't add any messages.")
        # asking for log all and another log warning
        if (self.logBuckets or self.logPackets or self.logToFile) and self.logAll:
            print("WLSK Warning: using log all (-la) and other logs (-lf,-lb,-lp) is not necessary.")
        
        if self.logAll:
            self.logBuckets = True
            self.logPackets = True
            self.logToFile = True

        # asking for file logging without an output path
        if (self.logToFile or self.logBuckets or self.logPackets) and self.output_path == None:
            raise SyntaxError("WLSK Error: cannot specify file logging (-lf) without an output path (-o [path])")
        
        if self.doLivePlot:
            self.isLogging = True
            
        if self.output_path != None:
            self.path_logfile, self.path_pkt_csv, self.path_bukt_csv = self.__output_setup()
            self.isLogging = True
        
        # TODO: rewrite the bits that determine logging, with the new -xvf format.
        # SETUP THE LOGGING
        logLevel = l.DEBUG if self.verbose else l.INFO
        self.l = l.getLogger(__name__)
        self.l.setLevel(logLevel)
        formatter = l.Formatter('%(levelname)s\t- %(message)s')
        # Logger parameters: can do either a logfile, to console, or both
        if self.logToConsole and not self.quiet:
            console_handler = l.StreamHandler()
            console_handler.setLevel(logLevel)
            console_handler.setFormatter(formatter)
            self.l.addHandler(console_handler)
        if self.logToFile and not self.quiet:
            file_handler = l.FileHandler(self.path_logfile)
            file_handler.setLevel(logLevel)
            file_handler.setFormatter(formatter)
            self.l.addHandler(file_handler)

        # MULTIPROCESSING OBJECTS
        # All multiprocessing objects are set as a tuple, with a name (0) and a process (1).
        # they are held in a list that manages them when turning the receiver on or off.
        self.processes = []
        if self.MODE == self.Mode.NORMAL:
            self.processes.append((self.PName.PINGER,mlti.Process(target= self._send_wlsk_pings)))
            self.processes.append((self.PName.SNIFFER,mlti.Process(target= self._sniff_wlsk_packets)))
            self.processes.append((self.PName.MANAGER,mlti.Process(target= self._packet_bucketer)))
            self.processes.append((self.PName.DECODER,mlti.Process(target= self._decoder_PFSM)))
            self.processes.append((self.PName.NOISER,mlti.Process(target= self._characterizer)))
        elif self.MODE == self.Mode.READFILE:
            # Put the file reader setup function here
            pass
        elif self.MODE == self.Mode.LISTENONLY:
            self.processes.append((self.PName.PINGER,mlti.Process(target= self._send_wlsk_pings)))
            self.processes.append((self.PName.SNIFFER,mlti.Process(target= self._sniff_wlsk_packets)))
            # put listen only util here???
        if self.isLogging:
            self.processes.append((self.PName.LOGGER,mlti.Process(target= self._logging_utility)))
        if self.doBeaconSniffs:
            self.processes.append((self.PName.BEACON,mlti.Process(target= self._beacon_sniffer)))
        if self.debugEnabled:
            self.processes.append((self.PName.DEBUG,mlti.Process(target= self._DEBUG_PROCESS)))

        # attempt to load the initalizer. THIS DOES NOT VALIDATE ALL THE CONFIG ENTRIES (Should it?)
        self.initialize(self.CONFIG)
        
    def initialize(self,configuration: string) -> bool:
        '''run this funtion to load the parameters of the receiver based on a given config file.'''
        self.isInitalized = False
        self.l.info("WLSK-HEAD: Initializing receiver...")
        try:
            with open(configuration,'r') as file:
                config_data = json.load(file)
                version = config_data["version"]
                if version != self.VERSION:
                    raise ValueError
                
                # config sections
                rx_params       = config_data["rx_params"]
                decoder_params  = config_data["decoder_params"]
                graph_utils     = config_data["graph_utils"]
                beacon_util     = config_data["beacon_util"]
                misc_utils      = config_data["misc_utils"]
                
                # RX_PARAMS
                self.RX_INTERFACE       = rx_params["rx_interface"]
                self.ping_interval      = rx_params["rx_ping_interval"]
                self.global_timeout     = rx_params["rx_timeout_limit"]
                self.TARGET_IP          = rx_params["ping_target_ip"]
                self.SRC_ADDR           = rx_params["ping_src_addr"]
                self.sport              = rx_params["ping_source_port"]
                self.dport              = rx_params["ping_dest_port"]
                # DECODER_PARAMS
                self.SYNC_WORD          = decoder_params["sync_word"]
                self.sync_word_len      = len(self.SYNC_WORD)
                self.BARKER_WORD        = decoder_params["barker_code"]
                self.bark_word_len      = len(self.BARKER_WORD)
                self.packet_len         = decoder_params["packet_length"]
                self.corr_thresh        = decoder_params["correlation_std-dev_threshold"]
                self.corr_grace         = decoder_params["correlation_window_grace"]
                # GRAPH UTILS
                self.listen_mode_len    = graph_utils["listen_mode_length"]
                # BEACON UTIL
                self.BEACON_INTERFACE   = beacon_util["beacon_interface"]
                self.BEACON_SSID        = beacon_util["beacon_ssid"]
                self.BEACON_MAC         = beacon_util["beacon_MAC"]
                self.beacon_instances   = beacon_util["beacon_instances"]
                # UTILITIES
                self.noise_window_len   = misc_utils["noise_window_length"]

        except KeyError as e:
            self.l.error(f"WLSK-HEAD: couldn't initialize because there was an illegal key (config name conflict or program error): {e}")     
        except ValueError:
            self.l.error("WLSK-HEAD: couldn't initialize because the config file version did not match: {} (expected) vs. {} (actual)".format(self.VERSION,version))
        except FileNotFoundError:
            self.l.error("WLSK-HEAD: couldn't initialize because the config file path given was not valid: ({})".format(configuration))
        else:
            self.l.info("WLSK-HEAD: Receiver initialized successfully.")
            self.isInitalized = True
        return self.isInitalized
    
    def start_receiver(self) -> None:
        '''starts a receiver that has been initialized but isn't running.'''
        if not self.isInitalized:
            self.l.error("WLSK-HEAD: Tried to start an uninitialized recevier. Fail")
            return
        elif self.isRunning():
            self.l.warning("WLSK-HEAD: cannot start a receiver that is already going.")
            return
        else:
            for i,process in enumerate(self.processes):
                # you can find the process list in __init__ under 'processes'
                process[1].start()
            return
    
    def stop_receiver(self, clean: bool = True) -> None:
        '''tells the running receiver to stop running. This may cause errors if it doesn't exit cleanly.'''
        if not self.isRunning():
            self.l.warning("WLSK-HEAD: cannot stop a receiver that isn't running.")
            return
        
        if clean:
            self._global_stop.set()
            self.l.info("WLSK-HEAD: waiting for queues to flush...")
            while not self._pkt_log.empty() or not self._bkt_log.empty():
                time.sleep(0.5)
            self.l.info("WLSK-HEAD: queues flushed, exiting...")
        else:
            self._global_stop.set()
            
        # give it 2 seconds to try to kill itself, otherwise just finish the job
        time.sleep(2)
        if self.isRunning():
            for process in self.processes:
                if process[1].is_alive():
                    process[1].terminate()
                    process[1].join()
                    self.l.warning(f"WLSK-HEAD: [process \"{process[0]}\" was killed after still hanging]")

        self.l.info("WLSK-HEAD: receiver is now inactive.")
        return
   
    def isRunning(self,quiet: bool= True) -> bool:
        '''returns true or false to indicate if the receiver is active.
        Turn off quiet to enable a debug message of which processes are active.'''
        if not quiet:
            self.l.debug(f"WLSK-HEAD: isRunning: {[process[1].is_alive() for process in self.processes]}")
        return any([process[1].is_alive() for process in self.processes])
        
    def block_until_message(self) -> list:
        '''blocks the running thread until a message is received in the queue.
        Use hasMessage() and grab_message() instead to prevent blocking or actively timeout.'''
        return self._message_queue.get()
    
    def grab_message(self,timeout: float= 0.5) -> list:
        '''attempts to grab a message from the message queue. After 'timeout' seconds it will return None instead.'''
        try:
            return self._message_queue.get(timeout=timeout)
        except queue.Empty:
            self.l.debug(f"WLSK-HEAD: grab_message timed out after {timeout} seconds.")
            return None
    
    def hasMessage(self) -> bool:
        '''returns true or false to indicate if the receiver has a message ready.'''
        return not self._message_queue.empty()

    def _read_from_file(self) -> None:
        try:
            filename = os.path.join(self.input_path,"buckets.csv")
            with open(filename, 'r') as csvfile:
                reader = csv.reader(csvfile)

                while True:
                    try:
                        mili = next(reader)
                        pkts = next(reader)
                        bucket = Bucket(mili,pkts)
                        self._bkt_queue.put(bucket)
                    except StopIteration:
                        break

        except FileNotFoundError:
            self.l.error(f"WLSK Error: cannot open \n{filename}\n; path does not exist or the file was not found.")
            self._global_stop.set()
        
        else:
            self.l.info("WLSK-READ: all the buckets have been read from the file. The program will shutdown a few seconds after the FSM finishes.")
            while not self._bkt_queue.empty():
                time.sleep(0.5)
            time.sleep(10)
            self._global_stop.set()

    def _send_wlsk_pings(self) -> None:
        self.l.info("WLSK-PING: Beginning pinger; intvl: {}; ip: {}".format(self.ping_interval,self.TARGET_IP))
        
        # pinger sets the global time to be closest to the first ping
        self._global_time.value = time.time()
        self.l.debug(f"WLSK-PING: global_time set to {self._global_time.value}")
        
        # creates a scapy socket by hand to send pings at high intervals
        # note that you still might need to set your interval slightly faster than necessary (ex. 5ms becomes 4ms)
        s = conf.L2socket(iface=self.RX_INTERFACE)
        
        # It doesn't matter what the sequence is as long as its unique; this counts up from zero.
        pkt_seq_num = 0
        
        # tell the other processes they can go
        self._global_start.set()
        
        while not self._global_stop.is_set():
            # Create the packet: sport is mutable; dport is 80
            packet = Ether(src=self.SRC_ADDR) / IP(dst=self.TARGET_IP) / TCP(seq=pkt_seq_num,sport=self.sport,dport=self.dport,flags="S")
            
            # send the packet out
            s.send(packet)
            pkt_seq_num += 1
            
            # This is accurate dependant on your system OS. modern Linux is usually within ~1ms?
            # This may not work on Windows though - I read it was minimum 7-10ms with jitter.
            time.sleep(self.ping_interval)  
        self.l.info("WLSK-PING: ending pinger process")
        return
    
    def _sniff_wlsk_packets(self) -> None:
        # wait until the pinger has set the time (so you don't sniff / request early)
        self._global_start.wait()        
        self.l.info("WLSK-SNIF: Beginning sniff process")
        
        # this can be modified if you need it to be
        sniff_filter = f"tcp port {self.sport}"
        
        pkt_list    = [{},{},{}]    # list of time in, time out, and rtt for each ping sent

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
                
                try:               
                    # if the packet is outgoing
                    if dport == self.dport and sport == self.sport:
                        # save the outgoing time
                        pkt_list[0][seq] = packet.time
                        
                    # if the packet is incoming
                    elif dport == self.sport and sport == self.dport:
                        # save the return time
                        pkt_list[1][ackR] = packet.time
                        # calculate the flight time
                        rtt = pkt_list[1][ackR] - pkt_list[0][ackR]
                        if rtt > 0 and rtt < .5:
                            pkt_list[2][ackR] = rtt
                        else:
                            # not sure why he puts this here?
                            pkt_list[2][ackR] = -.01
                            
                        # send it:           pkt #, outgoing time,     incoming time,     flight time
                        packaged_pkt = Packet(ackR, pkt_list[0][ackR], pkt_list[1][ackR], pkt_list[2][ackR])
                        if self.MODE == self.Mode.NORMAL:
                            self._pkt_queue.put(packaged_pkt)
                        if self.MODE == self.Mode.LISTENONLY or self.logPackets:
                            self._pkt_log.put(packaged_pkt)
                        
                        # remove the packet from the listing to avoid clutter
                        for pkt_dict in pkt_list:
                            del pkt_dict[ackR]
                        if ackR % 5000 == 0:
                            self.l.debug(f"WLSK-SNIF: health indicators: {len(pkt_list[0])} {len(pkt_list[1])} {len(pkt_list[2])}")
                    else:
                        self.l.warning("WLSK-SNIF: Packet is neither outgoing nor incoming? Unidentified packet received.")
                except KeyError as e:
                    self.l.warning(f"WLSK-SNIF: KeyError - part of packet {str(e).strip()} was dropped (unsure if outgoing or incoming)")                       
            else:
                self.l.error("WLSK-SNIF: port has other traffic. Consider moving. : {}".format(packet))
        
        def stop_sniff(packet,stop_event):
            return stop_event.is_set()
                    
        sniff(iface=self.RX_INTERFACE,prn=lambda pkt: process_packet(pkt),filter=sniff_filter, stop_filter=lambda pkt: stop_sniff(pkt,self._global_stop))
        
        self.l.info("WLSK-SNIF: ending sniffer process")
        return 
    
    def _packet_bucketer(self) -> None:
        # wait for pinger to give the okay
        self._global_start.wait()
        self.l.info("WLSK-BUKT: Beginning bucketer process")
        
        class bState(Enum):
            INIT = auto()
            LOAD = auto()
            SLOT = auto()
            SEND = auto()
        
        # Setup Vars    
        state:    bState  = bState.INIT
        pkt_info: tuple   = None
        pkt_time: int     = 0
        
        # TODO: add the timer for the LISTEN ONLY Mode so you know when to stop
        while not self._global_stop.is_set():
            match (state):
                case bState.INIT:
                    try:
                        pkt_info = self._pkt_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    else:
                        bucket = Bucket()
                        bucket.m = math.floor(pkt_info[2] * 1000)
                        bucket.c = 0
                        state = bState.LOAD
                case bState.LOAD:
                    try:
                        pkt_info = self._pkt_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    else:
                        pkt_time = math.floor(pkt_info[2] * 1000)
                        state = bState.SLOT                
                case bState.SLOT:
                    if pkt_time <= bucket.m:
                        bucket.c += 1
                        state = bState.LOAD
                    else:
                        state = bState.SEND
                case bState.SEND:
                    bkt_copy = copy(bucket)
                    if self.MODE == self.Mode.NORMAL:
                        self._bkt_queue.put(bkt_copy)
                    if self.MODE == self.Mode.LISTENONLY or self.logBuckets:
                        self._bkt_log.put(bkt_copy)
                    bucket.m += 1
                    bucket.c = 0
                    state = bState.SLOT
            # self.l.debug(f"pkt: {pkt_info[0]:05d}\tout: {pkt_info[1]}\tin: {pkt_info[2]}\tflight: {pkt_info[3]}")
            
        self.l.info("WLSK-BUKT: ending bucketer process")
        return

    def _decoder_PFSM(self) -> None:
        # wait for pinger to give the okay
        self._global_start.wait()
        self.l.info("WLSK-PFSM: Beginning PFSM process")

        class dState(Enum):
            INIT = auto()
            LOAD = auto()
            SHFT = auto()
            NCHK = auto()
            GCHK = auto()
            CORR = auto()
            MSGL = auto()
            MSGD = auto()

        state = dState.INIT

        while not self._global_stop.is_set():
            match (state):
                case dState.INIT:
                    # setup goes here!
                    isNoisy = False
                    hasGaps = False
                    strongCorr = False
                    msgDone = False
                    sync_index = 0
                    message = []
                    sync_window = deque()
                    curr_time = 0
                    bit_num = 1
                    state = dState.LOAD

                case dState.LOAD:
                    # how to get x packets :)
                    WINDOW_SIZE = math.ceil(102.4 * self.sync_word_len + self.corr_grace)
                    try:
                        packet = self._bkt_queue.get(timeout=1)
                    except queue.Empty:
                        continue
                    
                    curr_time = packet[0]
                    sync_window.append(packet[1])
                    
                    if len(sync_window) >= WINDOW_SIZE:
                        state = dState.NCHK

                case dState.SHFT:
                    try:
                        packet = self._bkt_queue.get(timeout=1)
                    except queue.Empty:
                        continue
                    
                    curr_time = packet[0]
                    sync_window.popleft()
                    sync_window.append(packet[1])
                    # self.l.debug("WLSK-PFSM: Dist of deque: {}".format(curr_time - math.floor(self._global_time.value * 1000)))
                    
                    state = dState.NCHK
                    pass
                        
                case dState.NCHK:
                    # TODO: Actually do something here
                    isNoisy = True
                    if isNoisy:
                        state = dState.GCHK
                    else:
                        state = dState.SHFT
                
                case dState.GCHK:
                    # TODO: Actually do something here
                    hasGaps = True
                    if hasGaps:
                        state = dState.CORR
                    else:
                        state = dState.SHFT
                
                case dState.CORR:
                    # TODO: Actually do something here
                    # TODO: decide on new window size for smaller windows (?)
                    sync_index = self.__correlate(list(sync_window),self.SYNC_WORD,window_size=75)
                    strongCorr = True
                    if strongCorr:
                        state = dState.MSGL
                    else:
                        state = dState.SHFT
                
                case dState.MSGL:
                    BARKER_SIZE = 1000 # TODO: Calculate Barker sized window
                    # TODO: Figure out how to center the sync_index value
                    # NOTE: Should I just do a message size window after all?
                    # calculated at runtime. It wouldn't affect performance, 
                    # but it would simplify the state machine a lot.
                    try:
                        packet = self._bkt_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    
                    curr_time = packet[0]
                    sync_window.append(packet[1])
                    
                    if len(sync_window) >= WINDOW_SIZE + BARKER_SIZE * bit_num:
                        state = dState.MSGD
                
                case dState.MSGD:
                    # TODO: Actually read the bit and put it in a message
                    bit = 0
                    message.append(bit)
                    if len(message) == self.packet_len:
                        self._message_queue.put(copy(message))
                        message = []
                        state = dState.LOAD
                    else:
                        state = dState.MSGL
                
                case _:
                    self.l.error(f"WLSK-PFSM: Reached illegal state!! state: {state}")

            pass
        self.l.info("WLSK-PFSM: ending PFSM process")
        return
    
    def _characterizer(self) -> None:
        # wait for pinger to give the okay
        self._global_start.wait()
        self.l.info("WLSK-CHAR: Beginning characterizer process")
        
        while not self._global_stop.is_set():
            time.sleep(0.1)
        
        self.l.info("WLSK-CHAR: ending characterizer process")
        return
    
    def _logging_utility(self) -> None:
        self._global_start.wait()
        time.sleep(0.1)
        self.l.info("WLSK-LOGY: Beginning packet log process")
       
        global_mil = math.floor(self._global_time.value * 1000)
        
        def generate_save_data():
            while not self._global_stop.is_set() or not self._pkt_log.empty() or not self._bkt_log.empty():
                if self.logPackets:
                    try:
                        raw_data = self._pkt_log.get(timeout=0.1)
                    except queue.Empty:
                        pass
                    else:
                        with open(self.path_pkt_csv,'a') as file:
                            writer = csv.writer(file)
                            for item in raw_data:
                                writer.writerow([item]) 

                if self.logBuckets:
                    try:
                        mil_info = self._bkt_log.get(timeout=0.1)
                    except queue.Empty:
                        pass
                    else:
                        if self.doLivePlot:
                            live_bkt_feed.put(mil_info)
                        if self.logBuckets:
                            with open(self.path_bukt_csv,'a') as file:
                                writer = csv.writer(file)
                                for item in mil_info:
                                    writer.writerow([item])
                
                # TODO: Put in a message logger block
                # try:
                #     raw_data = self._pkt_log.get(timeout=0.1)
                # except queue.Empty:
                #     pass
                # else:
                #     with open(self.path_raw_csv,'a') as file:
                #         writer = csv.writer(file)
                #         for item in raw_data:
                #             writer.writerow([item]) 
            return

        # PACKET LOGGING THREAD: runs whenever something is being logged.
        data_save_thread = threading.Thread(target=generate_save_data)
        data_save_thread.daemon = True
        data_save_thread.start()
        
        # TODO: Test the new Live plotter and debug the updater fcns.
        # LIVE PLOTTER: If enabled, takes the logged info and displays it.
        if self.doLivePlot:

            # TODO: Move GraphObj into new file as virtual class, where each graph can instantiate an update fcn
            class GraphObj:
                def __init__(self,xsz=0,title="",xlab="",ylab="",axis=None,scroll=0,init_h=0) -> None:
                    self.input = queue.Queue 
                    self.xax: list = []
                    self.yax: list = []
                    self.ymin: int = init_h
                    self.XSZ: int = xsz
                    self.title: str = title
                    self.xlab: str = xlab
                    self.ylab: str = ylab
                    self.axis: plt.Axes = axis
                    self.scatter = None
                    self.scroll = scroll

                def initialize(self):
                    self.axis.set_title("Real Time* Graph of Pings Per Millisecond")
                    self.scatter = self.axis.scatter(self.xax,self.yax,s=2)
                    self.axis.clear()
                    self.axis.set_xlim(0,10)
                    self.axis.set_ylim(0,15)
            
                def update(self,frame):
                    if self.input.qsize() >= 100:
                        last_time = 0
                        for _ in range(100):    
                            mil_time, ppms = self.input.get()
                            conv_time = mil_time - global_mil
                            last_time = conv_time
                            self.xax.append(conv_time)
                            self.yax.append(ppms)
                            if len(self.xax) > 1000:
                                del self.xax[0]
                                del self.yax[0]
                        self.scatter.set_offsets(np.c_[self.xax,self.yax])
                        self.axis.set_xlim(self.xax[0],max(1,last_time))
                        self.axis.set_ylim(0,max(15,max(self.yax)))
                        self.axis.set_xlabel('time (ms)')
                        self.axis.set_ylabel('ppms (pings)')
                        self.axis.set_xticks(np.arange(min(self.xax), max(self.xax), 100))
                        self.axis.set_yticks(np.arange(min(self.yax), max(self.yax)+3, 1))
                        self.axis.canvas.draw()

            NUMBER_OF_GRAPHS = 2
            graph_objs: list[GraphObj] = []
            animatedFig, animatedAxes = plt.subplots(1,NUMBER_OF_GRAPHS,figsize=(15, 6))
            
            # Packet Graph:
            graph_objs.append(GraphObj(
                xsz= 500,
                title= "Live Incoming Packet Log",
                xlab= "pkt seq num",
                ylab= "return time",
                axis=animatedAxes[0],
                scroll=50,
                init_h=0.1
            ))
            # Bucket Graph:
            graph_objs.append(GraphObj(
                xsz= 1000,
                title= "Live Bucket Log",
                xlab= "milliseconds since start",
                ylab= "num pkts received",
                axis=animatedAxes[1],
                scroll=100,
                init_h=0.1
            ))

            def animate(frame):
                for graph in graph_objs:
                    graph.update()
                    pass

            for graph in graph_objs:
                graph.initialize()

            anime = animation.FuncAnimation(animatedFig, animate, blit=True, interval=100) 

            plt.show()   
        
        # If you close the live view while active, the thread should stay alive for logging...
        # TODO: Update this function to catch messages and (also add the general logging var)
        while not self._global_stop.is_set() and (self.logBuckets or self.logPackets):
            time.sleep(1)
        
        self.l.info("WLSK-LOGY: ending packet log process")
        return
    
    def _beacon_sniffer(self) -> None:
        self._global_start.wait()
        self.l.warning("WLSK-HEAD: The beacon sniffer process is a deprecated part of WLSK, and will not run.")
        return

    def __output_setup(self) -> tuple:
        if not os.path.exists(self.output_path):
            raise ValueError(f"WLSK: Output path '{self.output_path}' does not exist or is not a valid path.")
        timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M")
        new_dir = os.path.join(self.output_path, f"WLSK_{timestamp}")
        os.makedirs(new_dir, exist_ok=True)
        log_path = os.path.join(new_dir, 'log.log')
        raw_csv_path = os.path.join(new_dir, 'raw.csv')
        buckets_csv_path = os.path.join(new_dir, 'buckets.csv')
        return (log_path, raw_csv_path, buckets_csv_path)

    def _DEBUG_PROCESS(self) -> None:
        self._global_start.wait()
        time.sleep(0.1)
        self.l.info("WLSK-DEBG: Debug session is running.")
        
        while not self._global_stop.is_set():
            time.sleep(1)
            self.l.debug(f"WLSK-DEBG: queue sizes: raw: {self._pkt_queue.qsize()} save-raw: {self._pkt_log.qsize()} bukt: {self._bkt_queue.qsize()} save-bukt: {self._bkt_log.qsize()} msg: {self._message_queue.qsize()}")
        
        self.l.info("WLSK-DEBG: debug session has ended.")
        return        

    def __code_upscaler(self, word, bitwidth = 102) -> list[int]:
        # TODO: Determine the most accurate way to shape 1 and 0
        upscaled_one = [1] * bitwidth
        upscaled_zero = [-1] * bitwidth

        # Composite the word into a new, huge upscaled word
        new_word = [item for value in word for item in (upscaled_one if value == 1 else upscaled_zero)]
        return new_word

    def __correlate(self, raw_data, code,window_size):
        # Shaping has been moved to __code_upscaler for testing
        code_upscaled = self.__code_upscaler(code)
        
        # TODO: Analyze the correlation function, either by changing shape or style
        var_data = raw_data.rolling(window=window_size).var().bfill()
        conv = np.correlate(var_data,code_upscaled,"full")

        # Return the 0 mean correlate
        return conv-conv.mean()
    
    def __sync_single_window(self, toa_dist):
        # NOTE: The toa_dist is now a sync window instead of a whole message
        toa_dist = toa_dist[0:]

        # find the sync word in the raw data 
        xcorr_sync = self.__correlate(raw_data=toa_dist, code=self.SYNC_WORD,window_size=75)

        xcorr_barker = self.__correlate(raw_data=toa_dist, code=self.BARKER_WORD,window_size=75)

        sync_index = np.argmax(xcorr_sync)
        # TODO: Decide the best way to look at the sync thresholds.
        # NOTE: This is the old code. Since this only picks the sync index, we don't care that much.
        # # Find the first peak of sync word xcorr - this should be the sync word
        # cutoff = 10000 #len(toa_dist) - self.SYNC_WORD_LENGTH - self.NUM_BITS_TO_DECODE * self.BARKER_LENGH
        # sync_indices = np.where(xcorr_sync[:cutoff] > xcorr_sync.std()*2)[0]

        # print("threshold for sync detect: {}".format(xcorr_sync.std()*2))
        # print("cutoff is {}".format(cutoff))
        
        # if len(sync_indices) == 0:
        #     print("Could not find the Sync Word\n")
        #     return None

        # sync_start = sync_indices[0] if xcorr_sync[sync_indices[0]] > xcorr_sync[sync_indices[np.argmax(xcorr_sync[sync_indices])]]*.5 else sync_indices[np.argmax(xcorr_sync[sync_indices])]
        # print("Using Sync Word idx: {}".format(sync_start))
        return sync_index

    def __bit_decision(self):
        # TODO: Implement this in a single use fcn
        #   - Remove the bits that create all the windows (functionize for PSFM-MSGL?)
        #   - Get rid of the for loop
        #   - return it as a single bit in the PFSM
        ones, _ = find_peaks(xcorr_barker, height = 500)
        zeroes, _ = find_peaks(xcorr_barker * -1, height = 500)
    
        # Calculate Bit Decision X-values based on the sync word location.
        timed_xcorr_bit_windows = []
        ori_bit_windows = []
        for bit in range(1, self.NUM_BITS_TO_DECODE+1):
            xval = sync_start + self.BARKER_LENGTH * bit+5*bit
            if xval < len(xcorr_barker):
                timed_xcorr_bit_windows.append(xval)
                ori_bit_windows.append(xval)

        # Finally, make a bit decision at each of the bit window locations. 
        bit_sequence = []
        bit_x_vals = []
        for index in range(len(timed_xcorr_bit_windows)):
            # Handle case where we get off and are right next to a peak. 
            grace = 200 if index == 0 else 150
            point_to_evaluate = timed_xcorr_bit_windows[index]
            nearby_options = np.arange(point_to_evaluate-grace, point_to_evaluate+grace)

            # find the largest peak not just a peak
            largest_index_value_pair = [abs(xcorr_barker[point_to_evaluate]),point_to_evaluate, 200]
            
            if index == 0:
                for option in nearby_options:
                    if (option != point_to_evaluate) and (option in ones ):
                        if (abs(point_to_evaluate -option) < largest_index_value_pair[2] and (abs(xcorr_barker[option]) >largest_index_value_pair[0]/1.8)) or (abs(xcorr_barker[option]) > 1.5*largest_index_value_pair[0]):
                            largest_index_value_pair[0] = abs(xcorr_barker[option])
                            largest_index_value_pair[1] = option
                            largest_index_value_pair[2] = abs(point_to_evaluate -option)

                    elif (option != point_to_evaluate) and (option in zeroes ):
                        if (abs(point_to_evaluate -option) < largest_index_value_pair[2] and (abs(xcorr_barker[option]) >largest_index_value_pair[0]/2)) or abs(xcorr_barker[option]) > 1.5*largest_index_value_pair[0]:
                            largest_index_value_pair[0] = abs(xcorr_barker[option])
                            largest_index_value_pair[1] = option
                            largest_index_value_pair[2] = abs(point_to_evaluate -option)
            elif abs(xcorr_barker[point_to_evaluate]) < 200:
                
                check_index = np.argmax(np.abs(xcorr_barker[nearby_options]))+nearby_options[0]

                if abs(xcorr_barker[check_index]) > 2 * abs(xcorr_barker[largest_index_value_pair[1]]):
                    largest_index_value_pair[1] = check_index
                adjustment = largest_index_value_pair[1]-timed_xcorr_bit_windows[index]
                timed_xcorr_bit_windows[index] += adjustment
                print(index, adjustment, timed_xcorr_bit_windows[index])
                for i,adjust_index in enumerate(range(index+1,len(timed_xcorr_bit_windows))):
                    timed_xcorr_bit_windows[adjust_index] += int(adjustment)

            point_to_evaluate = largest_index_value_pair[1] # get the index that we found else it is still x

            # adjust where we are sampling
            adjustment = point_to_evaluate-timed_xcorr_bit_windows[index]
            if index==0:
                timed_xcorr_bit_windows[index] += adjustment
                for i,adjust_index in enumerate(range(index+1,len(timed_xcorr_bit_windows))):
                    timed_xcorr_bit_windows[adjust_index] += int(adjustment/((i+2)**2))


            if xcorr_barker[point_to_evaluate] > 0:
                bit_sequence.append(1)
            else:
                bit_sequence.append(0)

            bit_x_vals.append(point_to_evaluate)
        
        print("Eval X coordinates: {}\n".format(bit_x_vals))
        return bit_sequence

if __name__ == "__main__":
    
    import argparse as argp
    import signal
    
    # This system prevents Ctr+C from being caught by all processes
    parent_pid = os.getpid()

    def signal_handler(signal, frame, processes, pid):
        curr = os.getpid()
        if curr == pid:
            print("Ctrl+C caught, terminating processes...")
            for p in processes:
                print(f"Process: \"{p[0]}\" terminated.")
                p[1].terminate()
            print("All processes terminated.")
            sys.exit(0)

    def create_handler(processes ,pid):
        def handler(signal,frame):
            signal_handler(signal, frame, processes, pid)
        return handler
    
    # TODO: Test this new process mover and see if references hold up
    receiver: WlskReceiver = None
    signal.signal(signal.SIGINT, create_handler(receiver.processes,parent_pid))
    
    parser = argp.ArgumentParser(description="interface for using the WLSK receiver.")
    
    parser.add_argument(
        '-m', '--mode',
        type=str,
        choices=['normal','listenonly','readfile'],
        required=True,
        help="Mode of operation. Choose from 'normal', 'listenonly', and 'readfile'"
    )
    parser.add_argument('-c','--config', required=True,type=str,help="Path to the receiver's configuration file.")
    parser.add_argument('-i','--input-path',type=str,help="List an input directory for readfile mode.")
    parser.add_argument('-o','--output-path',type=str,help="Output directory for listenonly mode or normal mode.")
    parser.add_argument('-b',action='store_true',help="Runs the beacon sniffer process. [Caution: WIP / deprecated]")
    parser.add_argument('-D','--debug',action='store_true',help="Runs debug process for extra parallel metrics.")
    parser.add_argument('-v','--verbose',action='store_true',help="Tells the receiver to run at the DEBUG log level instead of INFO.")
    parser.add_argument('-q','--quiet',action='store_true',help="Disables the receiver's log entirely.")
    parser.add_argument('-lg','--show-live',action='store_true',help="Shows a real-time graph of the WLSK receiver's latency and performance.")
    parser.add_argument('-lp','--log-packets',action='store_true',help="keeps a log of the raw packet data.")
    parser.add_argument('-lb','--log-buckets',action='store_true',help="keeps a log of the millisecond buckets.")
    parser.add_argument('-la','--log-all',action='store_true',help="logs debugger output, packets, and buckets.")
    parser.add_argument('-lf','--log-to-file',action='store_true',help="writes the logs to a file.")
    parser.add_argument('-lc','--log-to-console',action='store_true',help="writes the logs to the console.")
    parser.add_argument(
        '-l','--log',
        type=str,
        choices=['commands-file','console','buckets','packets','all'],
        nargs='+',
        help="Choose what to log by including any of the following: commands-file, console, buckets, packets, all")
    
    args = parser.parse_args()
    
    if args.mode == 'normal': mode = WlskReceiver.Mode.NORMAL
    if args.mode == 'listenonly': mode = WlskReceiver.Mode.LISTENONLY
    if args.mode == 'readfile': mode = WlskReceiver.Mode.READFILE
    
    # From the class __init__ definition: (kwargs)
    #
    # allowed_keys = ['input_path','output_path','doLivePlot',
    #                   'doBeaconSniffs','verbose','quiet',
    #                   'logToFile','logToConsole','logPackets',
    #                   'logBuckets','logAll','debugEnabled']
   
    receiver = WlskReceiver(args.config, mode,
                            input_path=args.input_path,
                            output_path=args.output_path,
                            doLivePlot=args.show_live,
                            doBeaconSniffs=args.b,
                            verbose=args.verbose,
                            quiet=args.quiet,
                            logToFile=args.log_to_file,
                            logToConsole=args.log_to_console,
                            logPackets=args.log_packets,
                            logBuckets=args.log_buckets,
                            logAll=args.log_all,
                            debugEnabled=args.debug)
    
    receiver.start_receiver()
    
    msg = receiver.grab_message(20)
    
    receiver.stop_receiver(clean=True)