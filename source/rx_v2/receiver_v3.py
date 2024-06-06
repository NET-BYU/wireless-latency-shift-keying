from scapy.all import Ether, IP, TCP, Dot11
from decoder_utils import WlskDecoderUtils
from supergrapher import SuperGrapher
from scipy.optimize import curve_fit
from scipy.signal import find_peaks
import matplotlib.pyplot as plt
import multiprocessing as mlti
from scapy.all import *
import logging as l
import numpy as np
import queue
import json
import csv
import os

LOG_PKTS = 15
LOG_DMPS = 16
LOG_OPS = 17
l.addLevelName(LOG_PKTS,"Log Packets")
l.addLevelName(LOG_DMPS,"Log Data Dumps")
l.addLevelName(LOG_OPS,"Log Operations")
        

class WlskReceiver:
    '''
    Wireless Latency Shift Keying is a method of encoding data into network latency,
    allowing a device not in a network to communicate into the network without
    proper authentication beforehand. see the Github for more information:
    https://github.com/NET-BYU/wireless-latency-shift-keying/tree/main 
    '''
    VERSION = 2.1
        
    def __init__(self, config_path: string, log_to_console: bool=False,
                 log_level: int=l.INFO, logfile: string=None, doGraphs: bool = False) -> None:
        '''WLSK Receiver
        
        Keyword Arguments:
        - config_path: string   -- the path the configuration file for the receiver.
        - log_to_console: bool  -- log output messages to the console.
        - log_level: int        -- determine the log level WLSK should run at.
        - logfile: string       -- if given, WLSK will log outputs to the given file.
        - doGraphs: bool        -- save graphs when processing windows. Slows the receiver considerably.
        '''
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
        self.doGraphs:          bool    = doGraphs
        self.isInitalized:      bool    = False
        self.msg_output_dir:    string  = None
        self.DELETE_REQ:        int     = -999
        self.plot_num:          int     = 0
        self.utils                      = WlskDecoderUtils()
        self.sg                         = SuperGrapher()
        
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
        self.NOISE_ATTN:        int         # length of initial noise analysis      | seconds
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
        '''run this funtion to load the parameters of the receiver based on a given config file.'''
        self.isInitalized = False
        self.l.info("HEAD\t- Initializing receiver...")
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
                self.WINDOW_ROLLOVER    = dec["window_rollover"]
                
                util = config_data["utilities"]
                self.save_mode          = util["save_mode"]
                self.SAVE_WINDOW        = util["save_window"]
                self.SAVEFILE           = util["savefile_num"]
                self.grab_timeout       = util["grab_timeout"]
                self.plot_dir           = util["plot_directory"]
                self.NOISE_ATTN         = util["noise_attention"]
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
                self.sg.set_directory(self.plot_dir)
                
        except ValueError:
            self.l.error("HEAD\t- couldn't initialize because the config file version did not match.")
        except FileNotFoundError:
            self.l.error("HEAD\t- couldn't initialize because the config file path given was not valid.")
        else:
            self.l.info("HEAD\t- Receiver initialized successfully.")
            self.isInitalized = True
        return self.isInitalized
    
    def start_receiver(self) -> None:
        '''starts a receiver that has been initialized but isn't running.'''
        if not self.isInitalized:
            self.l.error("HEAD\t- Tried to start an uninitialized recevier. Fail")
            return
        elif self.running():
            self.l.warning("HEAD\t- cannot start a receiver that is already going.")
            return
        else:
            for i,process in enumerate(self.processes):
                # you can find the process list in __init__ under 'processes'
                process.start()
            return
    
    def stop_receiver(self) -> None:
        '''tells the running receiver to stop running. This may cause errors if it doesn't exit cleanly.'''
        if not self.running():
            self.l.warning("HEAD\t- cannot stop a receiver that isn't running.")
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
                self.l.info("HEAD\t- [remaining processes killed after hanging - consider restarting program before continuing.]")
            return
    
    def block_until_message(self) -> list:
        '''blocks the running thread until a message is received in the queue.
        Use has_a_message() and grab_message() instead to prevent blocking.'''
        return self.__message_queue.get()
    
    def has_a_message(self) -> bool:
        '''returns true or false to indicate if the receiver has a message ready.'''
        return not self.__message_queue.empty()
    
    def grab_message(self) -> list:
        '''attempts to grab a message from the message queue. Timeout is set in config file.'''
        try:
            return self.__message_queue.get(timeout=self.grab_timeout)
        except queue.Empty:
            return None
    
    def running(self) -> bool:
        '''returns true or false to indicate if the receiver is active.'''
        return any(process.is_alive() for process in self.processes)
    
    def _send_wlsk_pings(self) -> None:
        '''Pinger Process for WLSK
        
        The pinger process is the first to start when the receiver begins listening.
        It simply catches its own start time as the 'global time' for the rest of the
        processes to use, then tells other process to begin via the __global_start event
        and starts sending TCP SYN packets at the rate specified in the config.
        
        This process starts automatically when start_receiver is called. It can be killed
        with the __global_stop event.
        '''
        self.l.info("HEAD\t- starting pinger; intvl: {}; ip: {}".format(self.ping_interval,self.target_ip))
        
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
        self.l.info("HEAD\t- ending pinger process")
        return
    
    def _sniff_ping_packets(self) -> None:
        '''Sniffer Process for WLSK
        
        The sniffer process uses Scapy sniff to listen to incoming packets, filters for
        the specific TCP SYN packets being sent by the rx line in the pinger process.
        It then forwards them along to the manager process via the process queue.
        
        This process cannot start until after the __global_start event. It can be killed 
        with the __global_stop event.
        '''
        # wait until the pinger has set the time (so you don't sniff / request early)
        self.__global_start.wait()        
        self.l.info("HEAD\t- Beginning sniff process")
        
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
                self.l.error("SNIFFS\t- port has other traffic. Consider moving. : {}".format(packet))
        
        def stop_sniff(packet,stop_event):
            return stop_event.is_set()
                    
        sniff(iface=self.rx_interface,prn=lambda pkt: process_packet(pkt),filter=sniff_filter, stop_filter=lambda pkt: stop_sniff(pkt,self.__global_stop)) # <---------------
        self.l.info("HEAD\t- ending sniffer process")
        return 
    
    def _packet_manager(self) -> None:
        '''Packet Manager Process for WLSK
        
        the packet manager receives a stream of packets from the sniffer process
        via the process_queue. It then determines whether the packet was incoming
        or outgoing, and assigns the appropriate values within the general pkt_list.
        this list has 3 'channels': the outgoing time, the incoming time, and the
        rtt. each channel is a dictionary where the key is the sequence number of
        the packet, and the value is the time. The packet manager also fulfills 
        requests made by the decoder process by giving it windows of stored data
        and delete data that has been processed or deemed useless.
        
        This process cannot start until after the __global_start event. It can be killed 
        with the __global_stop event.
        '''
        # wait for pinger to give the okay
        self.__global_start.wait()
        self.l.info("HEAD\t- Beginning manager process")
        
        # Manager Variables
        pkt_list    = [{},{},{}]    # list of time in, time out, and rtt for each ping sent
        waiting     = False         # status of an active request; set if desired window is not ready
        ready       = False         # flag to tell manager to send the current request window out
        request     = None          # receives the request, which is a number representing window length
        Rtime       = None          # receives the starting time index for the request, rounded to the nearest ping time
        hpkt        = 0             # the 'high' packet, or last packet considered a part of the request window

        while not self.__global_stop.is_set():
            
            # while waiting, if you get another poll, that's a problem. Too many requests.
            if self.__request_rx.poll():
                if waiting:
                    self.l.error("SAVER\t- received messages too fast. : {}".format(self.__request_rx.recv()))
                    self.__global_stop.set()
                request, Rtime = self.__request_rx.recv()
                waiting = True

            # both sync and msg requests are the same thing, just with a different window length
            if request != self.DELETE_REQ and ready:
                self.l.info("SAVER\t- RSP: window ({}) {}".format(request,Rtime))
                # calculate 'lowest' packet, or first packet considered in the window
                lpkt = self.__determine_packet_index(pkt_list[1],Rtime)
                outgoing_packets = [{k: v for k, v in d.items() if lpkt <= k <= hpkt} for d in pkt_list]
                self.__decoding_queue.put(outgoing_packets)
                waiting, ready, request, Rtime = False, False, None, None
                
            # a delete request clears all data before a certain time index to reduce list sizes and clutter
            elif request == self.DELETE_REQ and ready:
                self.l.info("SAVER\t- RSP: delete {}".format(Rtime))
                # determine the packet idx closest to the given request time
                delpkt = self.__determine_packet_index(pkt_list[1],Rtime)
                keys_to_remove = [key for key in pkt_list[1].keys() if key <= delpkt]
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
        self.l.info("HEAD\t- ending manager process")
        return
  
    '''
    TODO with decoder:
    - Maybe just send a delete request for the data everytime that the sync word fails? so that it gets less clogged. Need
    to compare the amount of time it takes to do a big vs. little delete then to see if that takes too much time w/ extra requests.
    - I wiped out the sync word function and the decode function. They need to be redone.
    '''  
    def _request_and_decode(self) -> None:
        '''Request and Decode Process for WLSK
        
        requests rolling windows of time from the manager process to analyze
        data and search for messages. it first searches for sync words, after
        which it requests a message size window of time and analyzes the data
        as though it had been a prerecorded set of data. It will also periodically
        send messages to the manager process to clear the old data that no
        longer has any use to save space and clutter.
        
        This function can also save raw data. See "save_mode" in the config.
        
        This process cannot start until after the __global_start event. It can be killed 
        with the __global_stop event.
        '''
        self.__global_start.wait()
        self.l.info("HEAD\t- Beginning decoder process")
        
        # decoder likes to have 1 or 2 packets already available for some reason
        time.sleep(0.5)
        
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
        
        # 0th request: request a window to listen to the raw 'noise'; becomes the save window if save mode is enabled (debugging utility)
        if self.save_mode:
            init_request = (self.SAVE_WINDOW,request_time)
        else:
            init_request = (self.NOISE_ATTN, request_time)
            
        self.l.info("DECODE\t- REQ: window ({}) {}".format(init_request[0],init_request[1]))
        self.__request_tx.send(init_request)
        # after sending a request, the next thing to do is always listen for the window response
        stack_in = listen_cautious(self.__decoding_queue, self.__global_stop)
        if not stack_in == None:
            if self.save_mode:
                self.__save_window_to_file(stack_in)
                self.__global_stop.set()
                time.sleep(3)
                self.l.info("HEAD\t- Save mode finished. Quitting...")
                return
            # use the max buffered packets to determine the noise floor
            self.__global_noise = self.__find_noise_floor(stack_in)
        
        # move the request time up to the length of data used
        request_time += self.NOISE_ATTN
        
        # delete the data used in the noise calculations
        self.l.info("DECODE\t- REQ: delete {}".format(request_time))
        self.__request_tx.send((self.DELETE_REQ, request_time))
        stack_in = listen_cautious(self.__decoding_queue, self.__global_stop)
        if not stack_in == None and stack_in[0] != 0:
            self.__global_stop.set()
        
        # this tells the system when to throw out old data
        window_rolls = 0
        
        while not self.__global_stop.is_set():
            try:
                # clear the queue when there is a bunch of extra silence
                if window_rolls >= self.WINDOW_ROLLOVER:
                    window_rolls = 0
                    self.l.info("DECODE\t- REQ: rollover clear")
                    self.__request_tx.send((self.DELETE_REQ, request_time))
                    stack_in = listen_cautious(self.__decoding_queue, self.__global_stop)
                    if (stack_in == None or stack_in[0] != 0): break 
                
                # First request: ask for a sync word sized window
                self.l.info("DECODE\t- REQ: window ({}) {}".format(self.SYNC_REQ, request_time))
                self.__request_tx.send((self.SYNC_REQ, request_time))
                stack_in = listen_cautious(self.__decoding_queue, self.__global_stop)
                # if you ever don't get a message its because __global.stop so just leave
                if stack_in == None: break 

                # search for the sync word in the window
                self.__debug_stack(stack_in)
                sunk = self.__find_sync_word(stack_in)
                
                if sunk:
                    # delete request will be sent anyways
                    window_rolls = 0
                    
                    # Second request: starts at the same time, but is long enough for a full message to be inside
                    self.l.info("DECODE\t- REQ: window ({}) {}".format(self.MSG_REQ, request_time))
                    self.__request_tx.send((self.MSG_REQ, request_time))
                    stack_in = listen_cautious(self.__decoding_queue, self.__global_stop)
                    if stack_in == None: break
                    
                    # decode that message now you found it
                    message = self.__decode_message(stack_in)
                    self.__message_queue.put(message)
                    
                    # Third request: flush the data that was in the manager so it doesn't get cloggy :(
                    self.l.info("DECODE\t- REQ: delete {}".format(request_time))
                    self.__request_tx.send((self.DELETE_REQ, request_time + self.MSG_REQ))
                    stack_in = listen_cautious(self.__decoding_queue, self.__global_stop)
                    if (stack_in == None or stack_in[0] != 0): break

                else:
                    # if you didn't find the sync word scroll 1 second - the windows are oversize so its fine
                    request_time += 1
                    window_rolls += 1
                    
            except Exception as e:
                self.l.error("DECODE\t- an exception occured: {}".format(e))
                
        self.__global_stop.set()
        self.l.info("HEAD\t- ending decoder process")
        return
    
    def __find_noise_floor(self,stack) -> int:
        '''finds the noise floor, as in the normal amount of packets that get buffered during untouched transmission.'''
        rts_array = np.array([stack[1].get(i, -0.1) for i in range(max(stack[1].keys()) + 1)])
        toa_dist, _ = self.utils.toa_distribution(rts_array)
        noise_distribution = [item for item in toa_dist if item > 0]
        noise_floor = np.mean(noise_distribution)
        self.l.info("DECODE\t- noise floor was set to {}".format(noise_floor))
        
        # plot_dir = "/home/enas2001/Documents/WLSK_tests/wireless-latency-shift-keying/source/rx_v2/rx_test_plots"
        # # Plotting the results
        # plt.scatter(range(0,len(noise_distribution)), noise_distribution, color='blue', label='Original data')
        # plt.xlabel('Time (ms)')
        # plt.ylabel('Values (x{})'.format(len(noise_distribution)))
        # plt.legend()
        # plt.savefig(os.path.join(plot_dir,"noise{}.png".format(self.plot_num)),dpi=600)
        # plt.close()
        
        # it = 1
        # while len(noise_distribution) > 0:
        #     print("there are {} with at least {}".format(len(noise_distribution),it))
        #     noise_distribution = [item for item in toa_dist if item > it]
        #     it += 1
        
        return noise_floor

    # TODO: This does not actually work? It still finds the sync word even on blank t-lines maybe
    def __find_sync_word(self,stack: list,__force_show = False) -> bool:
        '''determines whether or not a WLSK sync word exists given a toa array in time. Returns true or false'''
        
        time.sleep(5)
        
        return False
    
    # TODO: This does not exist
    def __decode_message(self,stack: list) -> list:
        '''decodes a WLSK message from a toa array in time. returns a list of bits'''
        plot_dir = "/home/enas2001/Documents/WLSK_tests/wireless-latency-shift-keying/source/rx_v2/rx_test_plots"
        
        rts_array = np.array([stack[1].get(i, -0.1) for i in range(max(stack[1].keys()) + 1)])
        toa_dist, _ = self.utils.toa_distribution(rts_array)
        
        return_bits = self.__decode_single_test(toa_dist= toa_dist, test_dir = plot_dir, test_num = 0, rtt_setup = stack[2])
        
        self.l.debug("message received: {}".format(return_bits))
        return return_bits
    
    def __determine_packet_index(self, item_list: list, threshold: float) -> int:
        '''determines packet indexing for creating windows of time. returns an integer index.'''
        sorted_items = sorted(item_list.items(), key=lambda x: x[1])
        highest_key = None
        for key,value in sorted_items:
            if value >= threshold:
                highest_key = 0 if (highest_key == None) else highest_key
                break
            highest_key = key
        return highest_key
    
    def __what_the_plot(self, directory: string, toa_dist: list, xcorr: np.ndarray, show: bool=True) -> None:
        '''optional plotter for diagnostic information. Not used in the receiver main code.'''
        
        background_color = '#A9A9A9'
        
        fig = plt.figure(figsize=(15,15), facecolor=background_color)
        fig.suptitle("Results {} from pinging {}".format(self.plot_num, self.target_ip))
        
        ax1 = fig.add_subplot(3,1,1, facecolor=background_color)
        ax1.title.set_text("Received packets per 1ms Interval")
        ax1.plot(toa_dist,color='black',linewidth=0.5)
        
        ax2 = fig.add_subplot(3,1,2, facecolor=background_color)
        ax2.plot(xcorr,color='black',linewidth=1)
        ax2.hlines([xcorr.std()*2,xcorr.std()*-2],*ax2.get_xlim())
        ax2.title.set_text("Sync word correlation")

        plt.savefig(os.path.join(directory,"results{}.png".format(self.plot_num)),dpi=600)
        if show:
            plt.show()
        
        self.plot_num += 1
        plt.close(fig)

    def __debug_stack(self, stack):
        self.l.debug("average rtt: {}".format(sum(stack[2].values()) / len(stack[2])))
        return
    
    # TODO: This needs to go into the other one, I just don't wanna do it now.
    def __decode_single_test(self, toa_dist, test_dir = None, test_num = 0, rtt_setup = []):
        toa_dist = toa_dist[0:]
        bit_sequence = []
        
        xcorr_sync = self.utils.correlate(raw_data=toa_dist, code=self.sync_word,window_size=75)

        # Generate Cross Corelation of Barker Codes with the Received Chips 
        self.barker = [1,1,1,-1,-1,-1,1,-1,-1,1,-1]
        xcorr_barker = self.utils.correlate(raw_data=toa_dist, code=self.barker,window_size=75)

        # Find the first peak of sync word xcorr - this should be the sync word
        cutoff = 1000

        sync_indices = np.where(xcorr_sync[:cutoff] > xcorr_sync.std()*2)[0]

        self.l.info("threshold for sync detect: {}".format(xcorr_sync.std()*2))
        self.l.info("cutoff is {}".format(cutoff))        
        
        if len(sync_indices) == 0:
            self.l.info("Could not find the Sync Word\n")
        
        try:
            sync_start = sync_indices[0] if xcorr_sync[sync_indices[0]] > xcorr_sync[sync_indices[np.argmax(xcorr_sync[sync_indices])]]*.5 else sync_indices[np.argmax(xcorr_sync[sync_indices])]
            self.l.info("Using Sync Word idx: {}".format(sync_start))

            ones, _ = find_peaks(xcorr_barker, height = 500)
            zeroes, _ = find_peaks(xcorr_barker * -1, height = 500)
                
            # Calculate Bit Decision X-values based on the sync word location.
            timed_xcorr_bit_windows = []
            ori_bit_windows = []
            for bit in range(1, self.SYNC_WORD_LEN+1):
                xval = sync_start + self.BARK_WORD_LEN * bit+5*bit
                if xval < len(xcorr_barker):
                    timed_xcorr_bit_windows.append(xval)
                    ori_bit_windows.append(xval)
            # Finally, make a bit decision at each of the bit window locations. 
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
            
            self.l.info("Eval X coordinates: {}\n".format(bit_x_vals))
        except Exception as e:
            self.l.info("the dude failed")
        # Generate Plot showing raw data
        self.plot_noisy_noise(test_num,toa_dist,xcorr_sync,xcorr_barker,rtt_setup,test_dir,bg_color="#A9A9A9")
        self.l.info("me I plot.")
        return bit_sequence

    def plot_noisy_noise(self,target_ip,toa_dist,sync_corr,barker_corr,rtt_array,plot_dir,bg_color="#A9A9A9"):
        '''optional plotter for diagnostic information. Not used in the receiver main code.'''
        result_list = [rtt_array[key] for key in sorted(rtt_array.keys())]
        
        
        fig = plt.figure(figsize=(25,25), facecolor=bg_color)
        fig.suptitle("Results from pinging {}".format(target_ip))
        
        ax1 = fig.add_subplot(2,2,1, facecolor=bg_color)
        ax1.title.set_text("Received packets per 1ms Interval")
        ax1.plot(toa_dist,color='black',linewidth=0.5)
        
        # ax2 = fig.add_subplot(2,2,2, facecolor=bg_color)
        # ax2.plot(sync_corr,color='black',linewidth=1)
        # ax2.hlines([sync_corr.std()*2,sync_corr.std()*-2],*ax2.get_xlim())
        # ax2.title.set_text("Sync word correlation")
        
        # ax3 = fig.add_subplot(2,2,3, facecolor=bg_color)
        # ax3.plot(barker_corr,color='black',linewidth=1)
        # ax3.hlines([barker_corr.std()*2,barker_corr.std()*-2],*ax2.get_xlim())
        # ax3.title.set_text("Barker word correlation")
        
        # ax4 = fig.add_subplot(2,2,4, facecolor=bg_color)
        # ax4.title.set_text("rtt measurements")
        # ax4.plot(result_list,color='black',linewidth=0.5)

        plt.savefig(os.path.join(plot_dir,"noise_results.png"),dpi=600)
        plt.close(fig)
        return
    
    def __save_window_to_file(self,stack):
        path = os.path.join(self.plot_dir, "saved_data/test_result_{}.csv".format(self.SAVEFILE))
        
        with open(path,mode='w',newline='') as file:
            writer = csv.writer(file)
            common_keys = sorted(set(stack[0]).intersection(*stack[1:]))
            for row in stack:
                to_write = [row.get(key,'') for key in common_keys]
                writer.writerow(to_write)
        return