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
        self.doLoggingUtil:     bool                    = False         # determined by kwargs to run logger or not.
        # KWARGS (from __init__)
        self.MODE:              self.Mode               = mode          # the receiver's mode of operation.
        self.CONFIG:            string                  = config_path   # path to the receiver's active configuration.
        self.input_file:        string                  = None          # Kwarg for setting input file in readfile mode.
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
        self.path_raw_csv:      string                  = None          # filepath for raw ping data
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
        self._raw_pkt_queue                 = mlti.Queue()              # Queue for holding untouched pkts  | between sniffer and bucketer
        self._FSM_bucket_queue              = mlti.Queue()              # Queue for holding ms buckets      | between bucketer and FSM
        self._message_queue                 = mlti.Queue()              # Queue for holding complete msgs   | between FSM and front end
        self._characterizer_queue           = mlti.Queue()              # Queue for characterizer to use    | between FSM and characterizer
        self._save_raw_queue                = mlti.Queue()              # Queue for saving raw packets      | between sniffer and logger
        self._save_milli_queue              = mlti.Queue()              # Queue for live graph to use       | between FSM and logger
        self._global_noise                  = mlti.Value('i',1)         # global noise value for msg detect | Set by characterizer
        self._global_time                   = mlti.Value('d',1.0)       # global time for bucketing time    | Set by pinger

        # KWARG ARGUMENT PARSING
        # Get a list of the allowed parameters
        allowed_keys = ['input_file','output_path','doLivePlot',
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
        if mode != self.Mode.READFILE and self.input_file != None:
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
            self.doLoggingUtil = True
            
        if self.output_path != None:
            self.path_logfile, self.path_raw_csv, self.path_bukt_csv = self.__output_setup()
            self.doLoggingUtil = True
        
        
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
        if self.doLoggingUtil:
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
            while not self._save_raw_queue.empty() or not self._save_milli_queue.empty():
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
                            
                        # send it:     pkt #, outgoing time,     incoming time,     flight time
                        packaged_pkt = (ackR, pkt_list[0][ackR], pkt_list[1][ackR], pkt_list[2][ackR])
                        self._raw_pkt_queue.put(packaged_pkt)
                        if self.logPackets:
                            self._save_raw_queue.put(packaged_pkt)
                        
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
        curr_mil: int     = 0
        curr_ct:  int     = 0
        pkt_info: tuple   = None
        pkt_time: int     = 0
        
        while not self._global_stop.is_set():
            match (state):
                case bState.INIT:
                    try:
                        pkt_info = self._raw_pkt_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    else:
                        curr_mil = math.floor(pkt_info[2] * 1000)
                        curr_ct = 0
                        state = bState.LOAD
                case bState.LOAD:
                    try:
                        pkt_info = self._raw_pkt_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
                    else:
                        pkt_time = math.floor(pkt_info[2] * 1000)
                        state = bState.SLOT                
                case bState.SLOT:
                    if pkt_time <= curr_mil:
                        curr_ct += 1
                        state = bState.LOAD
                    else:
                        state = bState.SEND
                case bState.SEND:
                    mil_info = (curr_mil,curr_ct)
                    self._FSM_bucket_queue.put(mil_info)
                    if self.logBuckets or self.doLivePlot:
                        self._save_milli_queue.put(mil_info)
                    curr_mil += 1
                    curr_ct = 0
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
                    message = []
                    sync_window = deque()
                    curr_time = 0
                    state = dState.LOAD

                case dState.LOAD:
                    # how to get x packets :)
                    WINDOW_SIZE = 3900
                    try:
                        packet = self._FSM_bucket_queue.get(timeout=1)
                    except queue.Empty:
                        continue
                    
                    curr_time = packet[0]
                    sync_window.append(packet[1])
                    
                    if len(sync_window) >= WINDOW_SIZE:
                        state = dState.NCHK

                case dState.SHFT:
                    try:
                        packet = self._FSM_bucket_queue.get(timeout=1)
                    except queue.Empty:
                        continue
                    
                    curr_time = packet[0]
                    sync_window.popleft()
                    sync_window.append(packet[1])
                    # self.l.debug("WLSK-PFSM: Dist of deque: {}".format(curr_time - math.floor(self._global_time.value * 1000)))
                    
                    state = dState.NCHK
                    pass
                        
                case dState.NCHK:
                    time.sleep(0.5)
                    # TODO: Actually do something here
                    if isNoisy:
                        state = dState.GCHK
                    else:
                        state = dState.SHFT
                
                case dState.GCHK:
                    # TODO: Actually do something here
                    if hasGaps:
                        state = dState.CORR
                    else:
                        state = dState.SHFT
                
                case dState.CORR:
                    # TODO: Actually do something here (do these need to be separate states?)
                    if strongCorr:
                        state = dState.MSGL
                    else:
                        state = dState.SHFT
                
                case dState.MSGL:
                    WINDOW_SIZE = 1000 # TODO: Calculate Barker sized window
                    try:
                        packet = self._FSM_bucket_queue.get(timeout=1)
                    except queue.Empty:
                        continue
                    
                    curr_time = packet[0]
                    sync_window.append(packet[1])
                    
                    if len(sync_window) >= WINDOW_SIZE:
                        state = dState.MSGD
                
                case dState.MSGD:
                    bit = 0
                    # TODO: Actually read the bit and put it in a message
                    message.append(bit)
                    if msgDone:
                        self._message_queue.put(message)
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
        
        # PACKET LOGGING THREAD
        if self.logPackets:
            def generate_save_data():
                while not self._global_stop.is_set() or not self._save_raw_queue.empty():
                    try:
                        raw_data = self._save_raw_queue.get(timeout=1)
                    except queue.Empty:
                        pass
                    with open(self.path_raw_csv,'a') as file:
                        writer = csv.writer(file)
                        for item in raw_data:
                            writer.writerow([item]) 
                return
            
            save_thread = threading.Thread(target=generate_save_data)
            save_thread.daemon = True
            save_thread.start()
        
        # BUCKET LOGGING AND LIVE GRAPH THREAD
        if self.logBuckets or self.doLivePlot:    
            def generate_data():
                while not self._global_stop.is_set()or not self._save_milli_queue.empty():
                    try:
                        mil_info = self._save_milli_queue.get(timeout=1)
                    except queue.Empty:
                        continue
                    if self.doLivePlot:
                        liveplotfeed.put(mil_info)
                    if self.logBuckets:
                        with open(self.path_bukt_csv,'a') as file:
                            writer = csv.writer(file)
                            for item in mil_info:
                                writer.writerow([item])
                return
            
            data_thread = threading.Thread(target=generate_data)
            data_thread.daemon = True
            data_thread.start()
        
        if self.doLivePlot:   
            liveplotfeed = queue.Queue()        
            time_data = []
            ppms_data = []
            self.livefig, self.liveax = plt.subplots(figsize=(15, 6))
            
            self.liveax.set_title("Real Time* Graph of Pings Per Millisecond")
            scatter = self.liveax.scatter(time_data,ppms_data,s=2)
            
            def init():
                self.liveax.clear()
                self.liveax.set_xlim(0,10)
                self.liveax.set_ylim(0,15)
                return scatter,
            
            global_mil = math.floor(self._global_time.value * 1000)
            def update(frame):
                if liveplotfeed.qsize() >= 100:
                    last_time = 0
                    for _ in range(100):    
                        mil_time, ppms = liveplotfeed.get()
                        conv_time = mil_time - global_mil
                        last_time = conv_time
                        time_data.append(conv_time)
                        ppms_data.append(ppms)
                        # length = len(time_data)
                        # if length >= 2 and ppms > 3:
                        #     self.liveax.plot([time_data[-2],time_data[-1]],[ppms_data[-2],ppms_data[-1]],color='gray',linewidth=0.5)
                        if len(time_data) > 1000:
                            del time_data[0]
                            del ppms_data[0]
                    scatter.set_offsets(np.c_[time_data,ppms_data])
                    self.liveax.set_xlim(time_data[0],max(1,last_time))
                    self.liveax.set_ylim(0,max(15,max(ppms_data)))
                    self.liveax.set_xlabel('time (ms)')
                    self.liveax.set_ylabel('ppms (pings)')
                    self.liveax.set_xticks(np.arange(min(time_data), max(time_data), 100))
                    self.liveax.set_yticks(np.arange(min(ppms_data), max(ppms_data)+3, 1))
                    self.livefig.canvas.draw()
                return scatter,
            
            anime = animation.FuncAnimation(self.livefig, update, init_func=init, blit=True, interval=100) 

            plt.show()   
        
        # If you close the live view, the thread should stay alive...
        while not self._global_stop.is_set():
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
            self.l.debug(f"WLSK-DEBG: queue sizes: raw: {self._raw_pkt_queue.qsize()} save-raw: {self._save_raw_queue.qsize()} bukt: {self._FSM_bucket_queue.qsize()} save-bukt: {self._save_milli_queue.qsize()} msg: {self._message_queue.qsize()}")
        
        self.l.info("WLSK-DEBG: debug session has ended.")
        return        
        
if __name__ == "__main__":
    
    import argparse as argp
    import signal
    
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
    
    # Available kwargs: ['input_file','output_path','doLivePlot','doBeaconSniffs','verbose','quiet','log_to_console']
   
    receiver = WlskReceiver(args.config, mode,
                            input_file=args.input_path,
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
    
    signal.signal(signal.SIGINT, create_handler(receiver.processes,parent_pid))
    
    receiver.start_receiver()
    
    msg = receiver.grab_message(20)
    
    receiver.stop_receiver(clean=True)