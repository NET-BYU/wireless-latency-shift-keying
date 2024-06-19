from scapy.all import Ether, IP, TCP, Dot11
from decoder_utils import WlskDecoderUtils
from scipy.signal import find_peaks, correlate
import matplotlib.animation as animation
import matplotlib.pyplot as plt
from enum import Enum, auto
import multiprocessing as mlti
from scapy.all import *
import pandas as pd
import logging as l
import numpy as np
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
        MANAGER = "wlsk-packet-manager"
        DECODER = "wlsk-state-machine"
        NOISER  = "wlsk-characterizer"
        LOGGER  = "wlsk-log-utility"
        BEACON  = "wlsk-beacon-utility"
    
    class Mode(Enum):
        LISTENONLY  = auto()
        READFILE    = auto()
        NORMAL      = auto()

    def __init__(self, config_path: string, mode: Mode, **kwargs) -> None:
        '''WLSK Receiver
        The only thing configured directly in the init function is the logging scheme. Everything else is stored
        in the config file, which must be specified for the receiver to work properly.
        
        Keyword Arguments:
        - config_path: string   -- the path the configuration file for the receiver.
        - log_to_console: bool  -- log output messages to the console.
        - log_level: int        -- determine the log level WLSK should run at.
        - logfile: string       -- if given, WLSK will log outputs to the given file.
        - saveAllWindows: bool        -- save graphs when processing windows. Slows the receiver considerably.
        '''
        
        # List of runtime variables and functions:
        #   CAPITALS are fixed objects, such as strings, classes, etc.
        #   camelCase is used for boolean values
        #   underscore_names are used for all numerical types, mutable or not
        #   _underscored variables are multiprocessing variables
        
        # Variable              | Type                  | Initial Value | Description and Units
        self.isInitalized:      bool                    = False         # did all the variables get configured properly
        self.runLoggingUtility: bool                    = False         # will be det. by inputs. Decides whether logger is needed.
        # KWARGS (from __init__)
        self.MODE:              self.Mode               = mode          # the receiver's mode of operation.
        self.CONFIG:            string                  = config_path   # path to the receiver's active configuration.
        self.input_file:        string                  = None          # Kwarg for setting input file in readfile mode.
        self.output_path:       string                  = None          # Kwarg for setting output path for graphs / listen mode.
        self.logfile:           string                  = None          # Kwarg for setting file output for logging events.
        self.doLivePlot:        bool                    = False         # Kwarg for enabling the plt animated graph.
        self.doBeaconSniffs:    bool                    = False         # Kwarg for enabling the beacon sniffing process.
        self.verbose:           bool                    = False         # Kwarg for enabling debug output.
        self.quiet:             bool                    = False         # Kwarg for disabling output entirely.
        # RX_PARAMS
        self.RX_INTERFACE:      string                  = None          # wired or wireless, for sending pings  
        self.TARGET_IP:         string                  = None          # ip of target for the ping packets 
        self.SRC_ADDR:          string                  = None          # packet address for TX to detect pings 
        self.ping_interval:     float                   = 0.001         # rate at which pings are sent                  | unit: seconds
        self.global_timeout:    int                     = 100           # if no message is received, turn off           | unit: seconds
        self.sport:             int                     = 25565         # port that the receiver listens with           | no units
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
        self.grab_timeout:      float                   = 10            # timeout of the grab_message function          | unit: seconds
        self.noise_window_len:  int                     = 10            # length of initial noise analysis              | unit: seconds
        
        # MULTIPROCESSING VALUES
        self._global_start                  = mlti.Event()              # indicates processes are ready     | Set by pinger
        self._global_stop                   = mlti.Event()              # indicates receiver should stop    | Set by any
        self._raw_pkt_queue                 = mlti.Queue()              # Queue for holding untouched pkts  | between sniffer and formatter
        self._message_queue                 = mlti.Queue()              # Queue for holding complete msgs   | between FSM and front end
        self._millisecond_queue          = mlti.Queue()              # Queue for logger to see events    | between FSM and logger
        self._global_noise                  = mlti.Value('i',-1)        # global noise value for msg detect | Set by characterizer
        self._global_time                   = mlti.Value('d',-1.0)      # global time for bucketing time    | Set by pinger

        # KWARG ARGUMENT PARSING
        # Get a list of the allowed parameters
        allowed_keys = ['input_file','output_path','doLivePlot','doBeaconSniffs','verbose','quiet','logfile']
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
        if (self.verbose or self.logfile != None) and self.quiet:
            raise SyntaxError("WLSK Error: cannot specify logging (-v or -l) and quiet mode (-q) at the same time.")
        
        ''' BEGIN SETTING UP RECEIVER'''
        # MULTIPROCESSING OBJECTS
        # All multiprocessing objects are set as a tuple, with a name (0) and a process (1).
        self.processes = []
        self.processes.append((self.PName.PINGER,mlti.Process(target= self._send_wlsk_pings)))
        self.processes.append((self.PName.SNIFFER,mlti.Process(target= self._sniff_wlsk_packets)))
        self.processes.append((self.PName.MANAGER,mlti.Process(target= self._packet_bucketer)))
        self.processes.append((self.PName.DECODER,mlti.Process(target= self._decoder_PFSM)))
        self.processes.append((self.PName.NOISER,mlti.Process(target= self._characterizer)))
        if not self.quiet or self.doLivePlot or self.output_path != None:
            self.processes.append((self.PName.LOGGER,mlti.Process(target= self._packet_log_utility)))
        if self.doBeaconSniffs:
            self.processes.append((self.PName.BEACON,mlti.Process(target= self._beacon_sniffer)))
        
        # SETUP THE LOGGING
        doConsoleLog = (not self.quiet) and (self.logfile == None)
        logLevel = l.DEBUG if self.verbose else l.INFO
        self.l = l.getLogger(__name__)
        self.l.setLevel(logLevel)
        formatter = l.Formatter('%(levelname)s\t- %(message)s')
        # Logger parameters: can do either a logfile, to console, or both
        if doConsoleLog:
            console_handler = l.StreamHandler()
            console_handler.setLevel(logLevel)
            console_handler.setFormatter(formatter)
            self.l.addHandler(console_handler)
        if self.logfile != None:
            file_handler = l.FileHandler(self.logfile)
            file_handler.setLevel(logLevel)
            file_handler.setFormatter(formatter)
            self.l.addHandler(file_handler)

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
    
    def stop_receiver(self) -> None:
        '''tells the running receiver to stop running. This may cause errors if it doesn't exit cleanly.'''
        if not self.isRunning():
            self.l.warning("WLSK-HEAD: cannot stop a receiver that isn't running.")
            return
        
        else:
            self._global_stop.set()
            # give it 2 seconds to try to kill itself, otherwise just finish the job
            time.sleep(2)
            if self.isRunning():
                for process in self.processes:
                    process[1].terminate()
                    process[1].join()
                self.l.warning("WLSK-HEAD: [remaining processes were killed after still hanging]")

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
        self.l.info("WLSK-HEAD: Beginning pinger; intvl: {}; ip: {}".format(self.ping_interval,self.TARGET_IP))
        
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
        self.l.info("WLSK-HEAD: ending pinger process")
        return
    
    def _sniff_wlsk_packets(self) -> None:
        # wait until the pinger has set the time (so you don't sniff / request early)
        self._global_start.wait()        
        self.l.info("WLSK-HEAD: Beginning sniff process")
        
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
                    # send the packet out:  pkt #, outgoing time,     incoming time,     flight time
                    self._raw_pkt_queue.put((ackR, pkt_list[0][ackR], pkt_list[1][ackR], pkt_list[2][ackR]))
                    # remove the packet from the listing to avoid clutter
                    for pkt_dict in pkt_list:
                        del pkt_dict[ackR]
                else:
                    return                        
            else:
                self.l.error("WLSK-SNIF: port has other traffic. Consider moving. : {}".format(packet))
        
        def stop_sniff(packet,stop_event):
            return stop_event.is_set()
                    
        sniff(iface=self.RX_INTERFACE,prn=lambda pkt: process_packet(pkt),filter=sniff_filter, stop_filter=lambda pkt: stop_sniff(pkt,self._global_stop))
        
        self.l.info("WLSK-HEAD: ending sniffer process")
        return 
    
    def _packet_bucketer(self) -> None:
        # wait for pinger to give the okay
        self._global_start.wait()
        self.l.info("WLSK-HEAD: Beginning bucketer process")
        
        class bState(Enum):
            INIT = auto()
            LOAD = auto()
            SLOT = auto()
            SEND = auto()
            
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
                    self._millisecond_queue.put((curr_mil,curr_ct))
                    curr_mil += 1
                    curr_ct = 0
                    state = bState.SLOT
            # self.l.debug(f"pkt: {pkt_info[0]:05d}\tout: {pkt_info[1]}\tin: {pkt_info[2]}\tflight: {pkt_info[3]}")
            
        self.l.info("WLSK-HEAD: ending bucketer process")
        return

    def _decoder_PFSM(self) -> None:
        # wait for pinger to give the okay
        self._global_start.wait()
        self.l.info("WLSK-HEAD: Beginning PFSM process")

        class dState(Enum):
            INIT = auto()
            LOAD = auto()
            SHFT = auto()
            NCHK = auto()
            GCHK = auto()
            CORR = auto()
            MSGL = auto()
            MSGD = auto()
        # TESTING FUNCTION
        while not self._global_stop.is_set():
            try:
                mil_info = self._millisecond_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            print(f"millisecond: {mil_info[0]}\tpings: {mil_info[1]}")
            
            
        state = dState.INIT

        while not self._global_stop.is_set():
            match (state):
                case dState.INIT:
                    # setup goes here!
                    full_L = False
                    full_M = False
                    isNoisy = False
                    hasGaps = False
                    strongCorr = False
                    msgDone = False
                    state = dState.LOAD

                case dState.LOAD:
                    # how to get x packets :)
                    # TODO: actually make this lol
                    time.sleep(10)
                    if full_L:
                        state = dState.NCHK

                case dState.SHFT:
                    # do a shift
                    state = dState.NCHK
                    pass
                
                case dState.NCHK:
                    # do the noise checking!
                    if isNoisy:
                        state = dState.GCHK
                    else:
                        state = dState.SHFT
                
                case dState.GCHK:
                    # do the gap checking!
                    if hasGaps:
                        state = dState.CORR
                    else:
                        state = dState.SHFT
                
                case dState.CORR:
                    # correlate some stuff
                    if strongCorr:
                        state = dState.MSGL
                    else:
                        state = dState.SHFT
                
                case dState.MSGL:
                    # do more packet loading!
                    if full_M:
                        state = dState.MSGD
                
                case dState.MSGD:
                    # read the bit!
                    if msgDone:
                        state = dState.LOAD
                    else:
                        state = dState.MSGL
                
                case _:
                    self.l.error(f"WLSK-PFSM: Reached illegal state!! state: {state}")

            pass
        self.l.info("WLSK-HEAD: ending PFSM process")
        return
    
    def _characterizer(self) -> None:
        # wait for pinger to give the okay
        self._global_start.wait()
        self.l.info("WLSK-HEAD: Beginning characterizer process")
        
        while not self._global_stop.is_set():
            time.sleep(0.1)
        
        self.l.info("WLSK-HEAD: ending characterizer process")
        return
    
    def _packet_log_utility(self) -> None:
        self._global_start.wait()
        time.sleep(0.5)
        self.l.info("WLSK-HEAD: Beginning packet log process")
        
        if self.doLivePlot:
            self.livefig, self.liveax = plt.subplots(figsize=(15, 6))
        
        while not self._global_stop.is_set():
            time.sleep(0.1)
        
        self.l.info("WLSK-HEAD: ending packet log process")
        return
    
    def _beacon_sniffer(self) -> None:
        self._global_start.wait()
        self.l.warning("WLSK-HEAD: The beacon sniffer process is a deprecated part of WLSK, and will not run.")
        return
    
if __name__ == "__main__":#
    
    import argparse as argp
    
    parser = argp.ArgumentParser(description="interface for using the WLSK receiver.")
    
    parser.add_argument(
        '-m', '--mode',
        type=str,
        choices=['normal','listenonly','readfile'],
        required=True,
        help="Mode of operation. Choose from 'normal', 'listenonly', and 'readfile'"
    )
    parser.add_argument('-c','--config', required=True,type=str,help="Path to the receiver's configuration file.")
    parser.add_argument('-i','--input',type=str,help="give an input csv file for readfile mode.")
    parser.add_argument('-o','--output',type=str,help="output directory for listenonly mode or normal mode.")
    parser.add_argument('--show_live',action='store_true',help="Shows a real-time graph of the WLSK receiver's latency and performance.")
    parser.add_argument('-b',action='store_true',help="runs with the beacon sniffer process enabled. [Caution: WIP]")
    parser.add_argument('-v','--verbose',action='store_true',help="Tells the receiver to run at the DEBUG log level instead of INFO.")
    parser.add_argument('-q','--quiet',action='store_true',help="Disables the receiver's log")
    parser.add_argument('-l','--log',type=str,help="give a logfile to write logs to instead of the console.")
    
    args = parser.parse_args()
    
    if args.mode == 'normal': mode = WlskReceiver.Mode.NORMAL
    if args.mode == 'listenonly': mode = WlskReceiver.Mode.LISTENONLY
    if args.mode == 'readfile': mode = WlskReceiver.Mode.READFILE
    
    # Available kwargs: ['input_file','output_path','doLivePlot','doBeaconSniffs','verbose','quiet','logfile']
   
    receiver = WlskReceiver(args.config, mode,
                            input_file=args.input,
                            output_path=args.output,
                            doLivePlot=args.show_live,
                            doBeaconSniffs=args.b,
                            verbose=args.verbose,
                            quiet=args.quiet,
                            logfile=args.log)
    
    receiver.start_receiver()
    
    msg = receiver.grab_message(10000)
    
    receiver.stop_receiver()