from __future__ import annotations
from scapy.all import Ether, IP, TCP, Dot11
from scipy.signal import find_peaks, correlate
import matplotlib.animation as animation
import matplotlib.pyplot as plt
import multiprocessing as mlti
from collections import deque
from datetime import datetime
from enum import Enum, auto
from scapy.all import *
from copy import copy
import pandas as pd
import logging as log
import numpy as np
import typing as t
import queue as q
from queue import PriorityQueue as pq
import threading
import yaml
import time
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
        def __init__(self, tstamp: float = None, msg: list[t.Literal[1, 0]] = [], forceValid: bool = False):
            self.timestamp = tstamp
            self.message = msg
            self.len = len(msg)
            self.__valid = forceValid
        def add_bit(self, bit: int):
            self.message.append(bit)
            self.len += 1
        def list(self):
            return self.message
        def check_vs(self, preamble):
            diff = sum(r != w for r, w in zip(self.message, preamble))
            return diff < 5
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
                return str(self) == str(self)
            elif type(value) == str:
                return str(self) == value
            elif type(value) == list:
                return self.message == value
            else:
                return False
        def __str__(self) -> str:
            return ''.join(map(str, self.message)) if self.len > 0 else '<empty>'

    class Mode(Enum):
        LISTENONLY = auto()
        NORMAL = auto()

    class Process(Enum):
        TPINGER = "wlsk-target-pinger-process"
        SNIFFER = "wlsk-packet-sniffer-process"
        CRAFTER = "wlsk-bucket-crafter-process"
        DECODER = "wlsk-decoder-process"
        def __str__(self):
            return self.value

    class Timer(threading.Thread):
        '''A timer is a thread that will sleep for a duration and then set a given event flag to true.'''
        def __init__(self, duration, eventFlag):
            super().__init__()
            self.duration = duration
            self.eventFlag = eventFlag
        def run(self):
            '''The timer will sleep for the duration and then set the event flag to true.'''
            time.sleep(self.duration)
            self.eventFlag.set()

    class Window:
        '''A window is a collection of buckets that are used to determine the latency of a period of time.'''
        def __init__(self, maxSize):
            self.max = maxSize
            self.size = 0
            self.window: deque[WLSK.Bucket] = deque()
            self.queue = None
            self.start = 0
            self.seen_idxs = set()

        def append(self, item):
            '''appends a bucket to the window'''
            if len(self.window) < self.max:
                self.window.append(item)
                self.size += 1
            else:
                self.window.popleft()
                self.window.append(item)
            self.start = self.window[0].t
        def appendFrom(self, queue):
            '''appends a bucket from the queue to the window'''
            result = queue.get()
            self.append(result)
        def setQueue(self, queue):
            '''sets the queue to pull from'''
            self.queue = queue
        def clear(self):
            '''clears the window of all items'''
            self.window.clear()
            self.size = 0
            self.start = 0
            self.seen_idxs.clear()
        def resize(self, size=None, time=None, offset=0):
            '''resizes the window to a new size or start time'''
            # set the new size and start time
            self.max = size if size != None else self.max
            # adjust the size
            while len(self.window) < self.max:
                self.appendFrom(self.queue)
            while self.size > self.max:
                self.window.popleft()
                self.start = self.window[0].t
            # adjust the start time
            if time != None:
                while self.window[0].t < time - offset:
                    self.appendFrom(self.queue)
        def printAll(self, times=False):
            '''prints all the items in the window'''
            if times:
                return ','.join(map(str, [item.t for item in self.window])) if self.size > 0 else '<empty>'
            else:
                return ','.join(map(str, [item.c for item in self.window])) if self.size > 0 else '<empty>'
        def __iter__(self):
            for item in self.window:
                yield item
        def __getitem__(self, index):
            return self.window[index]
        def __len__(self):
            return len(self.window)
        def __str__(self):
            return f"Window: {self.size} / {self.max} ({self.start})"

    class Receiver:
        '''
        Wireless Latency Shift Keying is a method of encoding data into network latency,
        allowing a device not in a network to communicate into the network without
        proper authentication beforehand. see the Github for more information:
        https://github.com/NET-BYU/wireless-latency-shift-keying/tree/main
        '''
        VERSION = 4.0

        def __init__(self, config_path: string, mode: WLSK.Mode, **kwargs) -> None:
            '''WLSK Receiver
            The only thing configured directly in the init function is the logging scheme. Everything else is stored
            in the config file, which must be specified for the receiver to work properly.

            Keyword Arguments:
            - config_path: string       -- the path the configuration file for the receiver.
            - mode: WLSKReceiver.Mode   -- the operating mode of the receiver.
            - kwargs: any               -- additional kwargs are listed in __init__
            '''

            self.isInitalized:      bool        = False
            self.config_path:       string      = config_path
            self.mode:              WLSK.Mode   = mode
            self.rx_interface:      string
            self.ping_interval:     float
            self.target_ip:         string
            self.src_addr:          string
            self.sport:             int
            self.dport:             int
            self.preamble:          list[int]
            self.packet_len:        int
            self.timeout:           float
            self.doConsoleOutput:   bool
            self.doDebugOutput:     bool
            self.l:                 log.Logger    = None
            self.b_offset:          int
            self.f_offset:          int

            # attempt to load the initalizer. THIS DOES NOT VALIDATE ALL THE CONFIG ENTRIES (Should it?)
            self.initializeReceiver(self.config_path)

            # MULTIPROCESSING OBJECTS
            # All multiprocessing objects are set as a tuple, with a name (0) and a process (1).
            # they are held in a list that manages them when turning the receiver on or off.
            self.processes: list[tuple[WLSK.Process,mlti.Process]] = []

            # generate the processes for the receiver
            self.processes.append(
                (WLSK.Process.TPINGER, mlti.Process(target=self.sendPingPackets)))
            self.processes.append(
                (WLSK.Process.SNIFFER, mlti.Process(target=self.capturePackets)))
            self.processes.append(
                (WLSK.Process.CRAFTER, mlti.Process(target=self.convertPacketsToBuckets)))
            if self.mode == WLSK.Mode.NORMAL:
                self.processes.append(
                    (WLSK.Process.DECODER, mlti.Process(target=self.latencyDecoder)))


            # MULTIPROCESSING PIPELINES
            self.global_stop:  mlti.Event               = mlti.Event()
            self.global_start: mlti.Event               = mlti.Event()
            self.pkt_queue:    mlti.Queue[WLSK.Packet]  = mlti.Queue()
            self.bkt_queue:    mlti.Queue[WLSK.Bucket]  = mlti.Queue()
            self.msg_queue:    mlti.Queue[WLSK.Message] = mlti.Queue()
            self.global_time:  mlti.Value               = mlti.Value('d', 0.0)

            # SETUP THE LOGGING
            logLevel = log.DEBUG if self.doDebugOutput else log.INFO
            self.l = log.getLogger(__name__)
            self.l.setLevel(logLevel)
            formatter = log.Formatter('%(levelname)s\t- %(message)s')
            if self.doConsoleOutput:
                console_handler = log.StreamHandler()
                console_handler.setLevel(logLevel)
                console_handler.setFormatter(formatter)
                self.l.addHandler(console_handler)
            # if self.logToFile and not self.quiet:
            #     file_handler = log.FileHandler(self.path_logfile)
            #     file_handler.setLevel(logLevel)
            #     file_handler.setFormatter(formatter)
            #     self.l.addHandler(file_handler)

            if self.isInitalized:
                self.l.info("WLSK-HEAD: Receiver created successfully.")
            else:
                self.l.error("WLSK-HEAD: Receiver failed to initialize.")

        def initializeReceiver(self, configuration: string) -> bool:
            '''run this funtion to load the parameters of the receiver based on a given config file.'''
            self.isInitalized = False
            if self.l != None: self.l.info("WLSK-HEAD: Initializing receiver...")
            try:
                with open(configuration, 'r') as file:
                    config_data = yaml.load(file, Loader=yaml.FullLoader)
                    version = config_data["version"]
                    if version != self.VERSION:
                        raise ValueError

                    # config sections
                    rx_params               = config_data["rx_params"]
                    decoder_params          = config_data["decoder_params"]
                    utilities               = config_data["utilities"]
                    logging                 = utilities["logging"]

                    # RX_PARAMS
                    self.rx_interface       = rx_params["rx_interface"]
                    self.ping_interval      = rx_params["rx_ping_interval"]
                    self.target_ip          = rx_params["ping_target_ip"]
                    self.src_addr           = rx_params["ping_src_addr"]
                    self.sport              = rx_params["ping_source_port"]
                    self.dport              = rx_params["ping_dest_port"]

                    # DECODER_PARAMS
                    self.b_offset           = decoder_params["system"]["back_offset"]
                    self.f_offset           = decoder_params["system"]["front_offset"]
                    self.zero_percentage    = decoder_params["system"]["zero_percentage"]
                    self.preamble           = decoder_params["preamble"]
                    self.preamble_len       = len(self.preamble)
                    self.packet_len         = decoder_params["packet_length"]
                    self.sync_threshold     = decoder_params["system"]["sync_threshold"]

                    # UTILITIES
                    self.timeout            = utilities["timeout"]
                    self.doConsoleOutput    = logging["console_output"]
                    self.doDebugOutput      = logging["debug_outputs"]

            except KeyError as e:
                raise KeyError(
                    f"WLSK-HEAD: couldn't initialize because there was an illegal key (this is likely an internal program error): {e}")
            except ValueError:
                raise ValueError(
                    "WLSK-HEAD: couldn't initialize because the config file version did not match: {} (expected) vs. {} (actual)".format(self.VERSION, version))
            except FileNotFoundError:
                raise FileNotFoundError(
                    "WLSK-HEAD: couldn't initialize because the config file path given was not valid: ({})".format(configuration))
            else:
                if self.l != None: self.l.info("WLSK-HEAD: Receiver initialized successfully.")
                self.isInitalized = True

        def startReceiver(self) -> None:
            '''starts a receiver that has been initialized but isn't running.'''
            for process in self.processes:
                process[1].start()
            self.l.info("WLSK-HEAD: Receiver started.")
            return

        def stopReceiver(self) -> None:
            '''tells the running receiver to stop running. This may cause errors if it doesn't exit cleanly.'''
            for process in self.processes:
                process[1].terminate()
            self.l.info("WLSK-HEAD: Receiver stopped.")
            return

        def isRunning(self) -> bool:
            if self.isInitalized:
                for process in self.processes:
                    if process[1].is_alive():
                        self.l.debug("WLSK-HEAD: Receiver is running.")
                        return True
            return

        #TODO: implement this function
        def waitUntilMessage(self) -> list:
            '''blocks the running thread until a message is received in the queue.
            Use hasMessage() and grab_message() instead to prevent blocking or actively timeout.'''
            msg = self.fetch(self.msg_queue)
            return msg

        #TODO: implement this function
        def grabMessage(self, timeout: float = 0.5) -> list:
            '''attempts to grab a message from the message queue. After 'timeout' seconds it will return None instead.'''
            return

        #TODO: implement this function
        def messageAvailable(self) -> bool:
            '''returns true or false to indicate if the receiver has a message ready.'''
            return

        # OPTION 1: GET PACKETS VIA ACTUAL TRAFFIC
        def sendPingPackets(self) -> None:
            self.l.info(
                "WLSK-PING: Beginning pinger; intvl: {}; ip: {}".format(self.ping_interval, self.target_ip))

            # pinger sets the global time to be closest to the first ping
            self.global_time.value = time.time()
            self.l.debug(
                f"WLSK-PING: global_time set to {self.global_time.value}")

            # creates a scapy socket by hand to send pings at high intervals
            # note that you still might need to set your interval slightly faster than necessary (ex. 5ms becomes 4ms)
            s = conf.L2socket(iface=self.rx_interface)

            # It doesn't matter what the sequence is as long as its unique; this counts up from zero.
            pkt_seq_num = 0

            # tell the other processes they can go
            self.global_start.set()
            print("WLSK-PING: global_start set")

            while not self.global_stop.is_set():
                # Create the packet: sport is mutable; dport is 80
                packet = Ether(src=self.src_addr) / IP(dst=self.target_ip) / \
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

        def capturePackets(self) -> None:
            # wait until the pinger has set the time (so you don't sniff / request early)
            self.global_start.wait()
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
                            packaged_pkt = WLSK.Packet(
                                seq=ackR, tout=pkt_list[0][ackR], tin=pkt_list[1][ackR], rtt=pkt_list[2][ackR])
                            # self.l.debug("WLSK-SNIF: sending packet: {}".format(packaged_pkt))
                            self.pkt_queue.put(packaged_pkt)

                            # remove the packet from the listing to avoid clutter
                            for pkt_dict in pkt_list:
                                del pkt_dict[ackR]
                            # if ackR % 5000 == 0:
                            #     self.l.debug(
                            #         f"WLSK-SNIF: health indicators: {len(pkt_list[0])} {len(pkt_list[1])} {len(pkt_list[2])}")
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

            sniff(iface=self.rx_interface, prn=lambda pkt: process_packet(
                pkt), filter=sniff_filter, stop_filter=lambda pkt: stop_sniff(pkt, self.global_stop))

            self.l.info("WLSK-SNIF: ending sniffer process")
            return

        def convertPacketsToBuckets(self) -> None:
            # wait for pinger process to give the okay
            self.global_start.wait()
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
            while not self.global_stop.is_set():
                match (state):
                    case bState.INIT:
                        # self.l.debug("WLSK-BUKT: init")
                        pkt_info = self.fetch(self.pkt_queue)
                        bucket = WLSK.Bucket()
                        bucket.t = math.floor(pkt_info.i * 1000)
                        bucket.c = 0
                        state = bState.LOAD
                    case bState.LOAD:
                        # self.l.debug("WLSK-BUKT: load")
                        pkt_info = self.fetch(self.pkt_queue)

                        pkt_time = math.floor(pkt_info.i * 1000)
                        state = bState.SLOT
                    case bState.SLOT:
                        # self.l.debug("WLSK-BUKT: slot")
                        if pkt_time <= bucket.t:
                            bucket.c += 1
                            state = bState.LOAD
                        else:
                            state = bState.SEND
                    case bState.SEND:
                        # self.l.debug("WLSK-BUKT: send")
                        if self.mode == WLSK.Mode.NORMAL:
                            bkt_copy = copy(bucket)
                            # self.l.debug("WLSK-BUKT: sending bucket: {}".format(bkt_copy))
                            self.bkt_queue.put(bkt_copy)
                            with open("DEBUG.txt", 'a') as f:
                                writer = csv.writer(f)
                                writer.writerow(bucket)
                        # TODO: add the listen only mode
                        # else:
                        #     with open(os.path.join(self.output_path, "buckets.csv"), 'a') as csvfile:
                        #         writer = csv.writer(csvfile)
                        #         writer.writerow(bucket)
                        bucket.t += 1
                        bucket.c = 0
                        state = bState.SLOT
            self.l.info("WLSK-BUKT: ending bucketer process")
            return

        # OPTION 2: GET PACKETS VIA REHEARSED TRAFFIC
        def readBucketsFromCsv(self) -> None:
            try:
                filename = os.path.join(self.input_path, "buckets.csv")
                with open(filename, 'r') as csvfile:
                    reader = csv.reader(csvfile)

                    while True:
                        try:
                            mili = next(reader)
                            pkts = next(reader)
                            bucket = Bucket(mili, pkts)
                            self.bkt_queue.put(bucket)
                        except StopIteration:
                            break

            except FileNotFoundError:
                self.l.error(
                    f"WLSK Error: cannot open \n{filename}\n; path does not exist or the file was not found.")
                self.global_stop.set()

            else:
                self.l.info(
                    "WLSK-READ: all the buckets have been read from the file. The program will shutdown a few seconds after the FSM finishes.")
                while not self.bkt_queue.empty():
                    time.sleep(0.5)
                time.sleep(10)
                self.global_stop.set()

        # DECODE THE PACKETS
        def determineNoiseFloor(self, duration) -> int:
            # timer_event = threading.Event()
            # timer_thread = WLSK.Timer(duration, timer_event)
            # timer_thread.start()

            noise_floor = self.sync_threshold
            # while not timer_event.is_set():
            #     # TODO: add the noise floor calculation
            #     pass

            return noise_floor

        def latencyDecoder(self) -> None:
            # wait for pinger process to give the okay
            self.global_start.wait()
            self.l.info("WLSK-PFSM: Beginning PFSM process")

            # State machine labels
            class ds(Enum):
                '''Decoder State Machine labels'''
                INIT = auto()
                FIND = auto()
                RESIZE = auto()
                SYNC  = auto()
                DECODE = auto()
                CLEAN = auto()
                NONE = auto()

            class State:
                DEF_SIZE = 102 + (103*self.preamble_len)
                MSG_SIZE = DEF_SIZE + (103*self.packet_len)
                def __init__(self):
                    self.state: ds = ds.INIT
                    self.prev_state: ds = ds.NONE
                    self.noise_floor: int = 0
                    self.chg_win_size: int = 0
                    self.chg_start: int = 0
                    self.window: WLSK.Window = None
                    self.sync_idx: int = None
                    self.sync_passed: bool = False
                    self.message: WLSK.Message = WLSK.Message()
                def __str__(self):
                    return f"---FSM---\n\t\tJust Ran: {self.prev_state}\n\t\tNoise: {self.noise_floor}\n\t\tChgSize: {self.chg_win_size}\n\t\tChgStart: {self.chg_start}\n\t\tSync: {self.sync_idx}\n\t\tSync Pass: {self.sync_passed}\n\t\tWindow: {self.window}\n\t\tMessage:{self.message}\n\t\tNext State: {self.state}"

            pQueue: pq[WLSK.Bucket] = pq()
            def bucket_gather():
                while not self.global_stop.is_set():
                    pQueue.put(self.fetch(self.bkt_queue))
            gather_thread = threading.Thread(target=bucket_gather)
            gather_thread.daemon = True
            gather_thread.start()

            FSM: State = State()
            while not self.global_stop.is_set():
                FSM.prev_state = FSM.state
                match (FSM.state):
                    # INIT - Create all the variables and prepare for war
                    case ds.INIT:
                        noise_time = 10 #TODO: decide how long to listen for noise
                        FSM.window = WLSK.Window(102 + (103 * self.preamble_len))
                        FSM.window.setQueue(pQueue)
                        FSM.window.appendFrom(pQueue)
                        FSM.noise_floor = self.determineNoiseFloor(noise_time)
                        FSM.chg_win_size = State.DEF_SIZE      # set it to default size
                        FSM.chg_start = FSM.window.start    # i.e. don't change the start
                        # State transition
                        FSM.state = ds.RESIZE

                    # RESIZE - creates windows of various sizes.
                    case ds.RESIZE:
                        FSM.window.resize(size=FSM.chg_win_size,time=FSM.chg_start,offset=self.b_offset)
                        # self.l.debug("WLSK-PFSM: window resized to size: {} and start: {}".format(FSM.window.size, FSM.window.start))
                        # self.l.debug("actual window size: {}".format(len(FSM.window)))
                        # self.l.debug(FSM.window)
                        # self.l.debug(FSM.window.printAll())
                        # State transition
                        if FSM.window.size == State.DEF_SIZE:
                            if FSM.sync_idx != None:
                                FSM.state = ds.SYNC
                            else:
                                FSM.state = ds.FIND
                        if FSM.window.size == State.MSG_SIZE:
                            FSM.state = ds.DECODE
                        else:
                            self.l.error("WLSK-PFSM: window size failure.")

                    # FIND - Searches for the points that could be the start of a message.
                    case ds.FIND:
                        FSM.sync_idx = None
                        for bucket in FSM.window:
                            if bucket.c > FSM.noise_floor and bucket.t not in FSM.window.seen_idxs:
                                FSM.sync_idx = bucket.t
                                FSM.state = ds.SYNC
                                break
                        # State transition
                        if FSM.sync_idx == None:
                            FSM.state = ds.CLEAN
                        else:
                            FSM.chg_start = FSM.sync_idx
                            FSM.state = ds.RESIZE

                    # SYNC - Syncs the window to the start of the message, and checks the preamble.
                    case ds.SYNC:
                        # TODO: add the bit decision logic and how to space the sync window
                        def zero_percentage(time_center):
                            packets= [pkt.c for pkt in FSM.window]
                            time_center = time_center - FSM.window[0].t
                            print(packets)
                            num_zeros = sum(
                                1
                                for pkt in packets[time_center - self.b_offset : time_center + self.f_offset]
                                if pkt == 0
                            )
                            percent_above = num_zeros / (self.b_offset + self.f_offset) * 100
                            result = percent_above > self.zero_percentage
                            print(percent_above, result)
                            return result

                        for i in range(self.preamble_len):
                            time_center = FSM.sync_idx + math.ceil(102.4 * i)
                            # print(time_center)
                            if zero_percentage(time_center):
                                FSM.message.add_bit(1)
                            else:
                                FSM.message.add_bit(0)
                        FSM.sync_passed = FSM.message.check_vs(self.preamble)
                        self.l.debug(f"WLSK-SYNC: {FSM.message}")
                        # State transition
                        FSM.message.clear()
                        if FSM.sync_passed:
                            FSM.chg_win_size = State.MSG_SIZE
                            FSM.state = ds.RESIZE
                        else:
                            FSM.window.seen_idxs.add(FSM.sync_idx)
                            FSM.state = ds.FIND

                    # DECODE - Decodes the message and sends it to the message queue.
                    case ds.DECODE:
                        for i in range(self.preamble_len + self.packet_len):
                            time_center = FSM.sync_idx + math.ceil(102.4 * i)
                            if zero_percentage(time_center):
                                FSM.message.add_bit(1)
                            else:
                                FSM.message.add_bit(0)
                        self.msg_queue.put(copy(FSM.message))
                        FSM.state = ds.CLEAN

                    # CLEAN - empties the window and waits for the next message.
                    case ds.CLEAN:
                        # TODO: add the clean up logic
                        FSM.chg_win_size = State.DEF_SIZE
                        FSM.chg_start = FSM.window[-1].t + 1 # move the start to the end of the current window
                        FSM.window.clear()
                        FSM.message.clear()
                        # State transition
                        FSM.state = ds.RESIZE

                    case _:
                        self.l.error(
                            f"WLSK-PFSM: Reached illegal state!! state: {FSM.state}")
                # slow down the loop for debugging
                self.l.debug(FSM)
                # time.sleep(.1)
            self.l.info("WLSK-PFSM: ending PFSM process")
            return


        def fetch(self, queue) -> t.Any:
            while not self.global_stop.is_set():
                try:
                    result = queue.get(timeout=.1)
                except q.Empty:
                    continue
                else:
                    return result

def signal_handler(sig, frame, receiver: WLSK.Receiver):
    print(" - Ctrl+C caught, stopping receiver.")
    receiver.stopReceiver()
    os._exit(0)

if __name__ == "__main__":
    # Useful sometimes
    import signal
    parent_pid = os.getpid()

    config = sys.argv[1]

    receiver = WLSK.Receiver(config, WLSK.Mode.NORMAL)

    receiver.startReceiver()
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, receiver))

    msg = receiver.waitUntilMessage()
    #   1, 0, 1, 0, 1, 0, 1, 0, 1, 1
    # 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0
    # 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1
    #                                                                                         ##
    # compare = WLSK.Message(msg=[1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,0,
    # compare = WLSK.Message(msg=[
    #                     1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1,
    #                     1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0,
    #                     1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1,
    #                     1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0
    #                     ], forceValid=True)
    #
    compare = WLSK.Message(msg=[1,0,1,1,0,1,0,1,0,1,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,0,0,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0,1,0,1,1,0,1,0,1,0,1,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,0,0,0,1,1,0,1,0,0,1,0,1,1,0,0,1,1,1,0,1,1,0,1,0], forceValid=False)

    print(f"Original Message : {compare}")
    print(f"Message Received!: {''.join(str(x) for x in msg.message[31:])}")

    receiver.stopReceiver()
