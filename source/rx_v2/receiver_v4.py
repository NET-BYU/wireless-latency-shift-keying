from scapy.all import Ether, IP, TCP, Dot11
from scipy.signal import find_peaks, correlate
import matplotlib.animation as animation
from __future__ import annotations
import matplotlib.pyplot as plt
import multiprocessing as mlti
from collections import deque
from datetime import datetime
from enum import Enum, auto
from scapy.all import *
from copy import copy
import pandas as pd
import logging as l
import numpy as np
import typing as t
import queue as q
import json
import math
import csv
import os


class WLSK:

    class Packet:
        def __init__(self, seq: int = None, tin: float = None, tout: float = None, rtt: float = None):
            '''WLSK Packet:
            - seq: int - the sequence number of the packet
            - tin: float - the time the packet left the receiver node
            - tout: float - the time that the packet returned to the node
            - rtt: float - the time of flight of the packet'''
            self.s: int = seq
            self.o: float = tout
            self.i: float = tin
            self.r: float = rtt

        def __eq__(self, value: 'Packet') -> bool:
            return self.s == value.s

        def __str__(self) -> str:
            return f"PKT-{self.s}"

        def __iter__(self):
            yield self.s
            yield self.o
            yield self.i
            yield self.r

    class Bucket:
        def __init__(self, mil: int = None, pkts: int = None):
            self.t: int = mil
            self.c: int = pkts
            # with open("./DEBUG.txt","a") as file:
            #     file.write(f"{sync_mil}\n") = pkts

        def time(self):
            return f"{self.t} ms"

        def __eq__(self, value: 'Bucket') -> bool:
            return self.t == value.t

        def __str__(self) -> str:
            return f"BKT-{self.t}"

        def __iter__(self):
            yield self.t
            yield self.c

        def __lt__(self, other: 'Bucket'):
            return self.t < other.t

        def __le__(self, other: 'Bucket'):
            return self.t <= other.t

        def __gt__(self, other: 'Bucket'):
            return self.t > other.t

        def __ge__(self, other: 'Bucket'):
            return self.t >= other.t

        def __float__(self):
            return float(self.c)

    class Message:
        def __init__(self, tstamp: float = None, msg: list[t.Literal[1, 0]] = [], valid: bool = False):
            self.timestamp = tstamp
            self.message = msg
            self.len = len(msg)
            self.__valid = valid

        def add_bit(self, bit: int):
            self.message.append(bit)
            self.len += 1

        def check_vs(self, preamble: 'Message'):
            return (str(preamble) == str(self))

        def clear(self):
            self.timestamp = None
            self.message = []
            self.len = 0
            self.__valid = False

        def stamp(self):
            self.__valid = True

        def __bool__(self):
            return self.__valid

        def __len__(self):
            return self.len

        def __eq__(self, value) -> bool:
            if value == None:
                return not self.__valid
            elif type(value) == Message:
                return self.timestamp == value.timestamp
            elif type(value) == str:
                return str(self) == value
            else:
                return False

        def __str__(self) -> str:
            return ''.join(map(str, self.message)) if self.len > 0 else '<empty>'

    class Mode(Enum):
        LISTENONLY = auto()
        READFILE = auto()
        NORMAL = auto()

    class Process(Enum):
        TPINGER = "wlsk-target-pinger-process"
        SNIFFER = "wlsk-packet-sniffer-process"
        CRAFTER = "wlsk-bucket-crafter-process"
        GENR8ER = "wlsk-generator-process"

        def __str__(self):
            return self.value

    class Receiver:
        '''
        Wireless Latency Shift Keying is a method of encoding data into network latency,
        allowing a device not in a network to communicate into the network without
        proper authentication beforehand. see the Github for more information:
        https://github.com/NET-BYU/wireless-latency-shift-keying/tree/main 
        '''
        VERSION = 3.0

        def __init__(self, config_path: string, mode: WLSK.Mode, **kwargs) -> None:
            '''WLSK Receiver
            The only thing configured directly in the init function is the logging scheme. Everything else is stored
            in the config file, which must be specified for the receiver to work properly.

            Keyword Arguments:
            - config_path: string       -- the path the configuration file for the receiver.
            - mode: WLSKReceiver.Mode   -- the operating mode of the receiver.
            - kwargs: any               -- additional kwargs are listed in __init__
            '''

            self.isInitalized:      bool = False
            self.isLogging:         bool = False
            # KWARGS (from __init__)
            self.MODE:              self.Mode = mode
            self.CONFIG:            string = config_path
            self.input_path:        string = None
            self.output_path:       string = None
            self.logToFile:         bool = False
            self.logToConsole:      bool = False
            self.logPackets:        bool = False
            self.logBuckets:        bool = False
            self.logAll:            bool = False
            self.doLivePlot:        bool = False
            self.doBeaconSniffs:    bool = False
            self.verbose:           bool = False
            self.quiet:             bool = False
            self.debugEnabled:      bool = False
            # LOGGING
            self.path_pkt_csv:      string = None
            self.path_bukt_csv:     string = None
            self.path_logfile:      string = None
            # RX_PARAMS
            self.RX_INTERFACE:      string = None
            self.TARGET_IP:         string = None
            self.SRC_ADDR:          string = None
            self.ping_interval:     float = 0
            self.global_timeout:    int = 0
            self.sport:             int = 0
            self.dport:             int = 80
            # DECODER_PARAMS
            self.SYNC_WORD:         list = None
            self.sync_word_len:     int = 0
            self.BARKER_WORD:       list = None
            self.bark_word_len:     int = 0
            self.packet_len:        int = 0
            self.corr_thresh:       int = 0
            self.corr_grace:        int = 0
            # GRAPH UTILS
            self.listen_only_len:   int = 0
            self.listen_only_file:  int = 0
            self.liveplot:          animation = None
            # BEACON UTIL
            self.BEACON_INTERFACE:  string = None
            self.BEACON_SSID:       string = None
            self.BEACON_MAC:        string = None
            self.beacon_instances:  int = 0
            # UTILITIES
            self.noise_window_len:  int = 10

            # MULTIPROCESSING VALUES
            self._global_start = mlti.Event()
            self._global_stop = mlti.Event()
            self._pkt_queue = mlti.Queue()
            self._bkt_queue = mlti.Queue()
            self.__messages = mlti.Queue()
            self._characterizer_queue = mlti.Queue()
            self._pkt_log = mlti.Queue()
            self._bkt_log = mlti.Queue()
            self._global_noise = mlti.Value('i', 1)
            self._global_time = mlti.Value('d', 1.0)

            # KWARG ARGUMENT PARSING
            # Get a list of the allowed parameters
            allowed_keys = ['input_path', 'output_path', 'doLivePlot',
                            'doBeaconSniffs', 'verbose', 'quiet',
                            'logToFile', 'logToConsole', 'logPackets',
                            'logBuckets', 'logAll', 'debugEnabled']
            # Detect any invalid arguments given
            illegal_keys = [key for key in kwargs if key not in allowed_keys]
            if illegal_keys:
                raise TypeError(
                    f"Unsupported keyword argument(s): {', '.join(illegal_keys)}")
            # Set all the kwarg arguments used
            for key, value in kwargs.items():
                setattr(self, key, value)

            # INVALID COMBOS OF KWARGS
            # Being in a listening mode and giving an input file
            if mode != self.Mode.READFILE and self.input_path != None:
                raise SyntaxError(
                    "WLSK Error: cannot take an input file (-i) unless in file mode (-m readfile)")
            # Being in readfile mode and giving an output file
            if mode == self.Mode.READFILE and self.output_path != None:
                raise SyntaxError("WLSK Error: can't specify a new output (-o) for file mode (-m readfile), as the file already exists.",
                                  "Use the plt GUI to save additional graphs if needed.")
            # Being in readfile mode and requesting the live plotter
            if mode == self.Mode.READFILE and self.doLivePlot:
                raise SyntaxError(
                    "WLSK Error: cannot specify --show_live to a file instance (-m readfile), as it is not in real time.")
            # asking for verbose/a logfile and quiet mode at the same time
            if (self.verbose or self.logToConsole or self.logToFile) and self.quiet:
                print(
                    "WLSK Warning: quiet mode (-q) specified with logging (-v, -lf, -lc), quiet mode will win.")
            if (self.debugEnabled and not self.verbose):
                print(
                    "WLSK Warning: enabling debugging (-D) without verbose (-v) won't add any messages.")
            # asking for log all and another log warning
            if (self.logBuckets or self.logPackets or self.logToFile) and self.logAll:
                print(
                    "WLSK Warning: using log all (-la) and other logs (-lf,-lb,-lp) is not necessary.")

            if self.logAll:
                self.logBuckets = True
                self.logPackets = True
                self.logToFile = True

            # asking for file logging without an output path
            if (self.logToFile or self.logBuckets or self.logPackets) and self.output_path == None:
                raise SyntaxError(
                    "WLSK Error: cannot specify file logging (-lf) without an output path (-o [path])")

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
                self.processes.append(
                    (self.PName.PINGER, mlti.Process(target=self.__send_wlsk_pings)))
                self.processes.append(
                    (self.PName.SNIFFER, mlti.Process(target=self.__sniff_packets)))
                self.processes.append(
                    (self.PName.MANAGER, mlti.Process(target=self.__pkt_to_bkt)))
                self.processes.append(
                    (self.PName.DECODER, mlti.Process(target=self._decoder_PFSM)))
                # self.processes.append((self.PName.NOISER,mlti.Process(target= self._characterizer)))
            elif self.MODE == self.Mode.READFILE:
                # Put the file reader setup function here
                pass
            elif self.MODE == self.Mode.LISTENONLY:
                self.processes.append(
                    (self.PName.PINGER, mlti.Process(target=self.__send_wlsk_pings)))
                self.processes.append(
                    (self.PName.SNIFFER, mlti.Process(target=self.__sniff_packets)))
                self.processes.append(
                    (self.PName.MANAGER, mlti.Process(target=self.__pkt_to_bkt)))
                self.processes.append(
                    (self.PName.LISTENER, mlti.Process(target=self._listener_util)))
                self.processes.append(
                    (self.PName.NOISER, mlti.Process(target=self._characterizer)))
            if self.isLogging:
                self.processes.append(
                    (self.PName.LOGGER, mlti.Process(target=self._logging_utility)))
            if self.doBeaconSniffs:
                self.processes.append(
                    (self.PName.BEACON, mlti.Process(target=self._beacon_sniffer)))
            if self.debugEnabled:
                self.processes.append(
                    (self.PName.DEBUG, mlti.Process(target=self._DEBUG_PROCESS)))

            # attempt to load the initalizer. THIS DOES NOT VALIDATE ALL THE CONFIG ENTRIES (Should it?)
            self.initialize(self.CONFIG)

            # TODO: REMOVE DEBUG STUFF
            self._vlines_sync = mlti.Queue()
            self._bkt_comm = mlti.Queue()
            self.SYNC_WIN_SIZE = mlti.Value('i', 0)
            self.BITS_WIN_SIZE = mlti.Value('i', 0)

        def initialize(self, configuration: string) -> bool:
            '''run this funtion to load the parameters of the receiver based on a given config file.'''
            self.isInitalized = False
            self.l.info("WLSK-HEAD: Initializing receiver...")
            try:
                with open(configuration, 'r') as file:
                    config_data = json.load(file)
                    version = config_data["version"]
                    if version != self.VERSION:
                        raise ValueError

                    # config sections
                    rx_params = config_data["rx_params"]
                    decoder_params = config_data["decoder_params"]
                    graph_utils = config_data["graph_utils"]
                    beacon_util = config_data["beacon_util"]
                    misc_utils = config_data["misc_utils"]

                    # RX_PARAMS
                    self.RX_INTERFACE = rx_params["rx_interface"]
                    self.ping_interval = rx_params["rx_ping_interval"]
                    self.global_timeout = rx_params["rx_timeout_limit"]
                    self.TARGET_IP = rx_params["ping_target_ip"]
                    self.SRC_ADDR = rx_params["ping_src_addr"]
                    self.sport = rx_params["ping_source_port"]
                    self.dport = rx_params["ping_dest_port"]
                    # DECODER_PARAMS
                    self.SYNC_WORD = decoder_params["sync_word"]
                    self.sync_word_len = len(self.SYNC_WORD)
                    self.BARKER_WORD = decoder_params["barker_code"]
                    self.bark_word_len = len(self.BARKER_WORD)
                    self.packet_len = decoder_params["packet_length"]
                    self.corr_thresh = decoder_params["correlation_std-dev_threshold"]
                    self.corr_grace = decoder_params["correlation_window_grace"]
                    # GRAPH UTILS
                    self.listen_mode_len = graph_utils["listen_mode_length"]
                    # BEACON UTIL
                    self.BEACON_INTERFACE = beacon_util["beacon_interface"]
                    self.BEACON_SSID = beacon_util["beacon_ssid"]
                    self.BEACON_MAC = beacon_util["beacon_MAC"]
                    self.beacon_instances = beacon_util["beacon_instances"]
                    # UTILITIES
                    self.noise_window_len = misc_utils["noise_window_length"]

            except KeyError as e:
                self.l.error(
                    f"WLSK-HEAD: couldn't initialize because there was an illegal key (config name conflict or program error): {e}")
            except ValueError:
                self.l.error(
                    "WLSK-HEAD: couldn't initialize because the config file version did not match: {} (expected) vs. {} (actual)".format(self.VERSION, version))
            except FileNotFoundError:
                self.l.error(
                    "WLSK-HEAD: couldn't initialize because the config file path given was not valid: ({})".format(configuration))
            else:
                self.l.info("WLSK-HEAD: Receiver initialized successfully.")
                self.isInitalized = True
            return self.isInitalized

        def __output_setup(self) -> tuple:
            if not os.path.exists(self.output_path):
                raise ValueError(
                    f"WLSK: Output path '{self.output_path}' does not exist or is not a valid path.")
            timestamp = datetime.datetime.now().strftime("%d-%m-%Y_%H-%M")
            new_dir = os.path.join(self.output_path, f"WLSK_{timestamp}")
            os.makedirs(new_dir, exist_ok=True)
            log_path = os.path.join(new_dir, 'log.log')
            raw_csv_path = os.path.join(new_dir, 'raw.csv')
            buckets_csv_path = os.path.join(new_dir, 'buckets.csv')
            return (log_path, raw_csv_path, buckets_csv_path)

        def start_receiver(self) -> None:
            '''starts a receiver that has been initialized but isn't running.'''
            return

        def stop_receiver(self) -> None:
            '''tells the running receiver to stop running. This may cause errors if it doesn't exit cleanly.'''
            return

        def isRunning(self) -> bool:
            return

        def block_until_message(self) -> list:
            '''blocks the running thread until a message is received in the queue.
            Use hasMessage() and grab_message() instead to prevent blocking or actively timeout.'''
            return self.__messages.get()

        def grab_message(self, timeout: float = 0.5) -> list:
            '''attempts to grab a message from the message queue. After 'timeout' seconds it will return None instead.'''
            try:
                return self.__messages.get(timeout=timeout)
            except q.Empty:
                self.l.debug(
                    f"WLSK-HEAD: grab_message timed out after {timeout} seconds.")
                return None

        def hasMessage(self) -> bool:
            '''returns true or false to indicate if the receiver has a message ready.'''
            return not self.__messages.empty()

        # OPTION 1: GET PACKETS VIA ACTUAL TRAFFIC
        def __send_pings(self) -> None:
            self.l.info(
                "WLSK-PING: Beginning pinger; intvl: {}; ip: {}".format(self.ping_interval, self.TARGET_IP))

            # pinger sets the global time to be closest to the first ping
            self._global_time.value = time.time()
            self.l.debug(
                f"WLSK-PING: global_time set to {self._global_time.value}")

            # creates a scapy socket by hand to send pings at high intervals
            # note that you still might need to set your interval slightly faster than necessary (ex. 5ms becomes 4ms)
            s = conf.L2socket(iface=self.RX_INTERFACE)

            # It doesn't matter what the sequence is as long as its unique; this counts up from zero.
            pkt_seq_num = 0

            # tell the other processes they can go
            self._global_start.set()
            print("WLSK-PING: global_start set")

            while not self._global_stop.is_set():
                # Create the packet: sport is mutable; dport is 80
                packet = Ether(src=self.SRC_ADDR) / IP(dst=self.TARGET_IP) / \
                    TCP(seq=pkt_seq_num, sport=self.sport,
                        dport=self.dport, flags="S")

                # send the packet out
                s.send(packet)
                pkt_seq_num += 1
                # This is accurate dependant on your system OS. modern Linux is usually within ~1ms?
                # This may not work on Windows though - I read it was minimum 7-10ms with jitter.
                time.sleep(self.ping_interval)
            self.l.info("WLSK-PING: ending pinger process")
            return

        def __sniff_packets(self) -> None:
            # wait until the pinger has set the time (so you don't sniff / request early)
            self._global_start.wait()
            self.l.info("WLSK-SNIF: Beginning sniff process")

            # this can be modified if you need it to be
            sniff_filter = f"tcp port {self.sport}"

            # list of time in, time out, and rtt for each ping sent
            pkt_list = [{}, {}, {}]

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

                            # send it:            pkt #,    outgoing time,          incoming time,         flight time
                            packaged_pkt = Packet(
                                seq=ackR, tout=pkt_list[0][ackR], tin=pkt_list[1][ackR], rtt=pkt_list[2][ackR])
                            self._pkt_queue.put(packaged_pkt)
                            if self.logPackets:
                                self._pkt_log.put(packaged_pkt)

                            # remove the packet from the listing to avoid clutter
                            for pkt_dict in pkt_list:
                                del pkt_dict[ackR]
                            if ackR % 5000 == 0:
                                self.l.debug(
                                    f"WLSK-SNIF: health indicators: {len(pkt_list[0])} {len(pkt_list[1])} {len(pkt_list[2])}")
                        else:
                            self.l.warning(
                                "WLSK-SNIF: Packet is neither outgoing nor incoming? Unidentified packet received.")
                    except KeyError as e:
                        self.l.warning(
                            f"WLSK-SNIF: KeyError - part of packet {str(e).strip()} was dropped (unsure if outgoing or incoming)")
                else:
                    self.l.error(
                        "WLSK-SNIF: port has other traffic. Consider moving. : {}".format(packet))

            def stop_sniff(packet, stop_event):
                return stop_event.is_set()

            sniff(iface=self.RX_INTERFACE, prn=lambda pkt: process_packet(
                pkt), filter=sniff_filter, stop_filter=lambda pkt: stop_sniff(pkt, self._global_stop))

            self.l.info("WLSK-SNIF: ending sniffer process")
            return

        def __pkt_to_bkt(self) -> None:
            # wait for pinger process to give the okay
            self._global_start.wait()
            self.l.info("WLSK-BUKT: Beginning bucketer process")

            # bucket FSM labels
            class bState(Enum):
                INIT = auto()
                LOAD = auto()
                SLOT = auto()
                SEND = auto()

            # Setup Vars
            state:    bState = bState.INIT
            pkt_info: Packet = None
            pkt_time: int = 0

            # TODO: add the timer for the LISTEN ONLY Mode so you know when to stop
            while not self._global_stop.is_set():
                match (state):
                    case bState.INIT:
                        pkt_info = self.qGet(self._pkt_queue)
                        bucket = Bucket()
                        bucket.t = math.floor(pkt_info.i * 1000)
                        bucket.c = 0
                        state = bState.LOAD
                    case bState.LOAD:
                        pkt_info = self.qGet(self._pkt_queue)

                        pkt_time = math.floor(pkt_info.i * 1000)
                        state = bState.SLOT
                    case bState.SLOT:
                        if pkt_time <= bucket.t:
                            bucket.c += 1
                            state = bState.LOAD
                        else:
                            state = bState.SEND
                    case bState.SEND:
                        bkt_copy = copy(bucket)
                        self._bkt_queue.put(bkt_copy)
                        if self.logBuckets or self.doLivePlot:
                            self._bkt_log.put(bkt_copy)
                        bucket.t += 1
                        bucket.c = 0
                        state = bState.SLOT
                # self.l.debug(f"pkt: {pkt_info[0]:05d}\tout: {pkt_info[1]}\tin: {pkt_info[2]}\tflight: {pkt_info[3]}")

            self.l.info("WLSK-BUKT: ending bucketer process")
            return

        # OPTION 2: GET PACKETS VIA REHEARSED TRAFFIC
        def _read_from_file(self) -> None:
            try:
                filename = os.path.join(self.input_path, "buckets.csv")
                with open(filename, 'r') as csvfile:
                    reader = csv.reader(csvfile)

                    while True:
                        try:
                            mili = next(reader)
                            pkts = next(reader)
                            bucket = Bucket(mili, pkts)
                            self._bkt_queue.put(bucket)
                        except StopIteration:
                            break

            except FileNotFoundError:
                self.l.error(
                    f"WLSK Error: cannot open \n{filename}\n; path does not exist or the file was not found.")
                self._global_stop.set()

            else:
                self.l.info(
                    "WLSK-READ: all the buckets have been read from the file. The program will shutdown a few seconds after the FSM finishes.")
                while not self._bkt_queue.empty():
                    time.sleep(0.5)
                time.sleep(10)
                self._global_stop.set()

        # GENERATOR FUNCTIONS
        def _listener_util(self) -> None:
            self._global_start.wait()

            curr_sec = 1
            now = datetime.now()
            ftime = now.strftime("%m-%d-%H-%M")
            filename = f"{ftime}_bkts.txt"
            self.l.info(
                f"WLSK-SAVE: Beginning save process with file {filename}")
            while not self._global_stop.is_set():
                curr_time = time.time()
                tbkt: Bucket = self.qGet(self._bkt_queue)
                with open(filename, "a") as file:
                    writer = csv.writer(file)
                    writer.writerow((tbkt.t, tbkt.c))
                thetime = curr_time - self._global_time.value

                if math.floor(thetime) > curr_sec:
                    print(thetime)
                    curr_sec += 1

                if thetime > self.listen_mode_len:
                    break

            self._global_stop.set()
            self.l.info("WLSK-SAVE: ending save process")
            return

        def _decoder_PFSM(self) -> None:
            # wait for pinger process to give the okay
            self._global_start.wait()
            self.l.info("WLSK-PFSM: Beginning PFSM process")

            pQueue: q.PriorityQueue[Bucket] = q.PriorityQueue()

            def bucket_gather():
                while not self._global_stop.is_set():
                    tbkt: Bucket = self.qGet(self._bkt_queue)
                    pQueue.put(tbkt)

            # daemon mode helps it to die properly XP
            gather_thread = threading.Thread(target=bucket_gather)
            gather_thread.daemon = True
            gather_thread.start()

            # State machine labels
            class dState(Enum):
                INIT = auto()
                LOAD = auto()
                SHFT = auto()
                NCHK = auto()
                GCHK = auto()
                CORR = auto()
                MSGL = auto()
                MSGD = auto()
                MSGE = auto()

            # anything that says self.l is a reference to the internal logger, and can be ignored.
            self.l.debug(f"state: NONE -> INIT")
            state: dState = dState.INIT
            # this list keeps track of the seen milliseconds we have synced at already, so we don't waste time
            seen_idxs: list[int] = []

            while not self._global_stop.is_set():
                match (state):
                    # INIT - Create all the variables and prepare for war
                    case dState.INIT:
                        self.SYNC_WIN_SIZE.value = math.ceil(
                            102.4 * self.sync_word_len + self.corr_grace)
                        self.BITS_WIN_SIZE.value = math.ceil(
                            102.4 * self.bark_word_len)

                        # We define the windows as deques. This allows
                        # us to "scoot" very easily because we can use popleft()
                        sync_window: deque[Bucket] = deque()
                        bit_window: deque[Bucket] = deque()

                        # Before we know whether or not the preamble is valid,
                        # we have to keep storing the buckets. This deque stores
                        # those buckets so we can push them back or discard them.
                        tmpQ: deque[Bucket] = deque()

                        # This is the "feed" for the machine: The most recent bucket grabbed
                        curr_bkt: Bucket = None

                        # The current message being built
                        message: Message = Message()

                        # The place that currently the PFSM thinks the message starts
                        sync_index: int = 0

                        # TODO: Make sure this all gets replaced with real computation.
                        # These are mostly placeholders for further filtering we do not currently do.
                        isNoisy = False
                        eFlag = False
                        hasGaps = False
                        strongCorr = False
                        beninging = 0
                        # self.l.debug(f"state: INIT -> LOAD")
                        state = dState.LOAD

                    # LOAD - Loads the sync window until it is full.
                    case dState.LOAD:
                        # Again, this is always the most "recent" millisecond -
                        # i.e. first one not currently in the window.
                        curr_bkt = self.qGet(pQueue)
                        # self.l.debug(curr_bkt)

                        # The front of the deque is always the earliest point in time
                        sync_window.append(curr_bkt)

                        # self.l.debug(f"sync: {len(sync_window)}")
                        # If you have filled the sync window with enough buckets
                        if len(sync_window) >= self.SYNC_WIN_SIZE.value:
                            # the _bkt_comm is just to communicate with the grapher
                            # you can ignore anything GraphComm related.
                            self._bkt_comm.put(
                                (GraphComm.NEWMAX, curr_bkt.t + self.corr_grace, 0))
                            # eFlag comes from the decode state - we will come back to it.
                            # It's default value is False.
                            if eFlag:
                                # self.l.debug(f"state: LOAD -> SHFT")
                                state = dState.SHFT
                            else:
                                # self.l.debug(f"state: LOAD -> NCHK")
                                state = dState.NCHK

                    # SHFT - Shift. Scoots the sync window over by one bucket.
                    case dState.SHFT:
                        # TODO: Configur-ify this var. We can choose how many buckets to shift by.
                        # One seems too small since the beacons are 102 of them wide...
                        # I have tried 10, 50, and 102, with little variance (except maybe processing speed? TBD)
                        SHIFT_SIZE = 102

                        for _ in range(SHIFT_SIZE):
                            # get a new bucket
                            curr_bkt = self.qGet(pQueue)
                            # Essentially scooting along by 1ms - old buckets are lost
                            # because they have no message (hah losers)
                            sync_window.popleft()
                            sync_window.append(curr_bkt)
                        self._bkt_comm.put(
                            (GraphComm.NEWMAX, curr_bkt.t + self.corr_grace, 0))
                        # self.l.debug(f"state: SHFT -> NCHK")
                        state = dState.NCHK

                    # NCHK - Noise Check. looks for a spike in the latency, signifying a signal.
                    case dState.NCHK:
                        # TODO: Actually do something here
                        # In our original diagram, this was the first preprocessing stage. Phil
                        # had talked to us about post-filtering with preambles so we never
                        # decided how to implement this. It is a future consideration to be had.
                        # -------------#
                        isNoisy = True
                        # -------------#

                        # All the 'checking' states will default to shift if they fail.
                        if isNoisy:
                            # self.l.debug(f"state: NCHK -> GCHK")
                            state = dState.GCHK
                        else:
                            # self.l.debug(f"state: NCHK -> SHFT")
                            state = dState.SHFT

                    # GCHK - Gap check. checks to see if there is WLSK-esque spacing in the window.
                    case dState.GCHK:
                        # TODO: Actually do something here
                        # This was originally our second layer of preprocessing. It would have looked
                        # for the distinct gaps that we found in the sync word.
                        # -------------#
                        hasGaps = True
                        # -------------#

                        if hasGaps:
                            # self.l.debug(f"state: GCHK -> CORR")
                            state = dState.CORR
                        else:
                            # self.l.debug(f"state: GCHK -> GCHK")
                            state = dState.SHFT

                    # CORR - correlate. Performs a correlation on the sync window.
                    case dState.CORR:
                        # Between these lines is essentially the "drag and drop" section where
                        # the state machine just needs something that correlates and spits a
                        # location for us to start searching for preambles.
                        # We also had talked about a layer of preprocessing with the
                        # std deviations. I haven't implemented that yet.
                        # -------------#
                        # This should be a function you read
                        sync_index = self.sync_single_window(
                            pd.Series(sync_window))

                        # this is the millisecond that we are going to choose to decide what the buckets should be at
                        # the reason it looks so complex is that I convert from raw UNIX time to milliseconds since
                        # start of the program.
                        sync_mil = sync_window[self.sync_word_len * 102 + sync_index - 1].t - math.floor(
                            self._global_time.value * 1000)
                        # TODO: What defines strong correlation?
                        # -------------#

                        # I was logging the millis for something; ignore
                        # with open("./DEBUG.txt","a") as file:
                        #     file.write(f"{sync_mil}\n")

                        # This should choose to shift if the point it wants to say
                        # was a sync word was already determined a failure
                        if sync_index not in seen_idxs:
                            seen_idxs.append(sync_index)
                            # after receiving index, we assume that the bit window should start on
                            # the sync edge (which seemed to be what we saw in graph tests).
                            # Therefore, we push the buckets after the sync word back into
                            # the main pQueue for use in the bucket windows.
                            while sync_index > sync_window[-1].t:
                                pQueue.put(sync_window.pop())

                            # self._bkt_comm.put((GraphComm.VLINES,[sync_mil],0))
                            # spit sync time
                            self.l.debug(f"Sync Time: {sync_mil}")
                            # self.l.debug(f"state: CORR -> MSGL")
                            state = dState.MSGL
                        else:
                            # self.l.debug(f"state: CORR -> SHFT")
                            self.l.debug("--Reused idx - shifting--")
                            state = dState.SHFT

                    # MSGL - Message Load. Takes in a set of buckets equal to the size of a bit decision window.
                    case dState.MSGL:
                        # This is an identical state to LOAD except with a different window and size
                        curr_bkt = self.qGet(pQueue)

                        bit_window.append(curr_bkt)

                        if len(bit_window) >= self.BITS_WIN_SIZE.value:
                            self._bkt_comm.put(
                                (GraphComm.NEWMAX, curr_bkt.t, 1))
                            # self.l.debug(f"state: MSGL -> MSGD")
                            state = dState.MSGD

                    # MSGD - Message Decode. Perform the bit decision operation and add the result to the message.
                    case dState.MSGD:
                        # This function decides how a bit is determined, and you should read it.
                        bit = self.bit_decision(
                            pd.Series(bit_window), var_size=75)

                        # put the bit in the message
                        message.add_bit(bit)
                        # TODO: Parameterize the preamble detection
                        # this is the preamble, and we will compare the message to it.
                        preamble = Message(0, [1, 0, 1, 0, 1, 0], False)

                        # Always save the info of the first few bits in case the message isn't valid
                        if message.len < preamble.len:
                            tmpQ.extend(bit_window)
                            bit_window.clear()
                            # self.l.debug(f"state: MSGD -> MSGL")
                            state = dState.MSGL

                        # At the end of the preamble, validate the message integrity
                        elif message.len == preamble.len:
                            if message.check_vs(preamble):
                                # we will continue reading
                                beninging = sync_mil - \
                                    (self.sync_word_len * 102)
                                self._bkt_comm.put(
                                    (GraphComm.VLINES, [sync_mil, beninging], 0))
                                self.l.debug(
                                    "DECODE: found the preamble, finishing message")
                                state = dState.MSGL  # finish the message
                                tmpQ.clear()        # clear the queue
                                bit_window.clear()  # prep window (see the next elif block)
                            else:
                                # Message Error state for cleanup
                                self.l.debug(
                                    f"Preamble fail: {preamble} vs. {message} (act)")
                                state = dState.MSGE  # clear the TMP Q and try again
                                while bit_window:
                                    # move bits to tmpQ for cleanup
                                    tmpQ.append(bit_window.pop())

                        # All bits afterwards don't need to be saved now its a real message
                        # this means we can just say bit_window.clear() and trash it all
                        elif message.len < self.packet_len:
                            bit_window.clear()
                            # self.l.debug(f"state: MSGD -> MSGL")
                            state = dState.MSGL

                        # if the message is finished (will have already been validated so it should be real)
                        elif message.len == self.packet_len:
                            # TODO: Send message statistics to logger (you can ignore this)
                            message.stamp()
                            self.__messages.put(copy(message))
                            message.clear()
                            sync_window.clear()
                            bit_window.clear()
                            # Load essentially puts us back a step 0 and so this process can repeat forever.
                            state = dState.LOAD

                    # MSGE - Message Error. Clear the message, and return to the search state
                    case dState.MSGE:
                        # put the packets back in their queue (yay for free order with priority).
                        while tmpQ:
                            pQueue.put(tmpQ.pop())
                        message.clear()
                        # The eFlag means that this time when it loads, it is a "reload"
                        # of something we already know is not a message. The eFlag will
                        # tell it to go into the SHFT state before it goes back to checking
                        # which saves us from infinite loops.
                        eFlag = True
                        state = dState.LOAD

                    case _:
                        self.l.error(
                            f"WLSK-PFSM: Reached illegal state!! state: {state}")

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


if __name__ == "__main__":

    import argparse as argp
    import argcomplete as argc
    import signal

    import pip
    import subprocess
    # generate the requirements file
    with open("source/rx_v2/requirements.txt", 'w') as file:
        subprocess.run([pip.__file__, 'freeze'], stdout=file, text=True)

    # Useful sometimes
    parent_pid = os.getpid()

    config = sys.argv[1]

    receiver = WLSK.Receiver(config)

    receiver.start_receiver()

    msg = receiver.block_until_message()

    compare = WLSK.Message(msg=[1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1,
                           1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0], valid=True)

    if msg != None:
        print(f"Original Message : {compare}")
        print(f"Message Received!: {msg}")

    receiver.stop_receiver(clean=True)
