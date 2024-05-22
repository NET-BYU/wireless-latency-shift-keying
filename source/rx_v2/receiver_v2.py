from decoder_v2 import WlskDecoder
from multiprocessing import Process, Queue
from scapy.all import Ether, IP, TCP
import matplotlib.pyplot as plt
from scapy.all import *
import logging as l
import numpy as np
import subprocess
import shutil
import socket
import json
import os

class WlskReceiver_old:
    """
        I dunno what it does yet. Don't bug me about it.
    """
    VERSION = 2.0
    
    def __init__(self, config_path, log_dest=None,log_level=l.DEBUG):
        # Logging info
        self.l = l.getLogger(__name__)
        self.l.setLevel(log_level)
        formatter = l.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        if log_dest != None and log_dest != 'console':
            logfile = l.FileHandler(log_dest)
            logfile.setLevel(log_level)
            logfile.setFormatter(formatter)
            self.l.addHandler(logfile)
        elif log_dest == 'console':
            console_handler = l.StreamHandler()
            console_handler.setLevel(l.DEBUG)
            console_handler.setFormatter(formatter)
            self.l.addHandler(console_handler)
        
        # Parameters from config.json
        self.interface = "enp5s0"
        self.interval = 0.005
        self.timeout = 10
        self.timeout = 30
        self.num_receivers = 1
        self.target_ips = ["wlsk-pt-node.local"]
        self.src_addrs = ["DE:AD:BE:EF:DE:AD"]
        self.sync_word = [1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,0]
        self.barker_code = [1,1,1,-1,-1,-1,1,-1,-1,1,-1]
        self.packet_length = 32
        self.max_packets = 1000
        self.decoder = None
                
        # Runtime variables
        self.rx_q = None
        self.rx_data = []
        self.ping_processes = []
        self.ping_process = None
        self.sniff_process = None
        self.msg_id = 0
        self.output_dir = None
        self.sniffed_packets = None
        self.initialized = False
       
        # Load Config 
        self.reload(config_path)
        return

    def reload(self, config_path):
        self.initialized = False
        self.l.info("Initializing WLSK Receiver...")
        try:
            # Read JSON file 
            with open(config_path, 'r') as file:
                config_data = json.load(file)
                version = config_data["version"]
                if version != 2.0:
                    self.l.error(f"Using the wrong version of config file. Expected v{self.VERSION}, got v{version}")
                    return
                rx_params = config_data["rx_params"]
                reflectors = config_data["reflectors"]
                message = config_data["messages"]
                utilities = config_data["utilities"]
                # RX Parameters
                self.interface = rx_params["rx_interface"]
                self.interval = rx_params["rx_ping_interval"]
                self.timeout = rx_params["rx_timeout_limit"]
                # Reflector Parameters
                self.num_receivers = reflectors["num_receivers"]
                self.target_ips = reflectors["target_ips"]
                self.src_addrs = reflectors["src_addrs"]
                # Message Parameters (for the decoder)
                self.sync_word = message["sync_word"]
                self.barker_code = message["barker_code"]
                self.packet_length = message["packet_length"]
                self.max_packets = message["max_packets"]
                # Utility Parameters
                
            self.l.debug("WLSK sync ({} bit): {}".format(len(self.sync_word),self.sync_word))
            self.l.debug("WLSk barker ({} bit): {}".format(len(self.barker_code),self.barker_code))
            self.decoder = WlskDecoder(self.sync_word,self.barker_code,self.packet_length)  
            self.l.debug("WLSK decoder finished setup.")
              
            self.initialized = True
        except Exception as e:
            self.l.error("Error initializilng WLSK RX! {}".format(e))
        self.l.info("WLSK Receiver Initialized.")
        return
    
    def receive(self, msg_id):
        # Make sure we are initialized
        if not self.initialized:
            self.l.error("Init before running RX!")
            return
        self.l.info("Starting RX receiver...")
        
        # Clear out the RX data from previous tests
        self.rx_data = []
        self.rx_q = Queue()
        self.util_q = Queue()
        self.msg_id = msg_id
        self.ping_processes = []
        self.sniffed_packets = None

        # If config says so, then kick off a channel util measurement
        if self.collect_channel_util:
            self.l.info("Util is enabled.")
            self.util_sample_process = Process(target=self._sample_channel_util)

        # Multiple processes sending pings, single process collecting and parsing
        self.l.debug("creating process for sniffing.")
        self.sniff_process = Process(target=self._sniff_pings, args=(self.rx_q,))
        for i in range(self.num_receivers):
            self.l.debug(f"creating process for receiver {i}")
            self.ping_processes.append(Process(target=self._send_pings))

        # self.ping_process = Process(target=self._send_pings)
        
        # Kick off processes
        if self.collect_channel_util and self.util_sample_process is not None:
            self.l.debug(f"starting util process.")
            self.util_sample_process.start()
        self.l.debug("starting sniffer process")
        self.sniff_process.start()
        
        # self.ping_process.start()
        
        for i,process in enumerate(self.ping_processes):
            self.l.debug(f"starting process for receiver {i}")
            process.start()
            time.sleep(0.001)
        return

    def wait(self):
        # Get result from sniffing process from Queue
        self.l.info("Obtaining raw data from the queue")
        self.sniffed_packets = None
        self.sniffed_packets = self.rx_q.get()
        # self.util_rate = self.util_q.get()
        self.l.info("Data successfully obtained!")
        # Close the spawned processes
        if self.collect_channel_util and self.util_sample_process is not None:
            self.util_sample_process.terminate()
            self.l.debug("closed util process")
        self.sniff_process.terminate()
        self.l.debug("closed sniffing process")
        # self.ping_process.terminate()
        for i,process in enumerate(self.ping_processes):
            process.terminate()
            self.l.debug(f"closed rx process {i}") 
        return

    def save_rx_data(self):
        # Process and save the results
        # Define 3D array for timestamps and rtt values 
        # Index in the array is the ID of the ping. 
        # Row 0 is the time of hte packet sent out 
        # Row 1 is the time the response came back for that packet 
        # Row 2 is the RTT for the ping. 
        
        # this holds all the data
        self.rx_data = []
        
        for i in range(self.num_receivers):
            # fill all the data with 0s
            self.rx_data.append([[0.00 for i in range(0, self.max_pings)] for j in range(3)])
        
        
        '''Iterate through sniffed packets, calculating RTT and filling array'''
        
        # This is the 'original time' of the first packet i guess? as in start time of the recording
        startTime = self.sniffed_packets[0][TCP].time
        
        # in this instance the pings are counted to the max - mine has to be just counting
        max_ping_seq = self.max_pings
        
        # set the original corner data point now that we have it
        self.rx_data[0][0][0] = startTime
        
        # I think that this is just to get the files created if they don't exist? Or begin rewriting them
        subprocess.check_output('echo "Suspicious Packets: "> sus.txt', shell=True)
        subprocess.check_output('echo "Missing Packets: "> zeroes.txt', shell=True)
        
        # This is the process of actually determining the RTT
        for packet in self.sniffed_packets:
            # get the response ID of the packet
            ackId = packet[TCP].ack
            # TCP SYN packets are incremental in seq - get the orignial SYN ID
            ackResponseId = ackId - 1
            # Why does it need the return seq number?
            seq = packet[TCP].seq
            # get the destination and source port - not sure how those determine the WLSK-ness. Do we use a weird port?
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            
            # Figure out which channel it is on - I think channel really means revceiver?
            channel = 0
            ##### What does outgoing mean?
            outgoing = True
            
            """This is how we tell between outgoing and incoming packets, but are we sniffing both?"""
            
            # if the packet is from the router, mark it as so
            if dport == 80 and sport < self.num_receivers:
                channel = sport
                outgoing = True
            #if the packet is from our machine, mark it as so
            elif sport == 80 and dport < self.num_receivers:
                channel = dport
                outgoing = False
            # This is probably a non-wlsk packet. Don't process it.
            else: 
                subprocess.check_output('echo "c: {} s: {} d: {}">> sus.txt'.format(channel, sport, dport), shell=True)
                continue

            """It seems like sniff is looking at both the outgoing and incoming packets - is that intentional? Solvable"""
            
            # if the packet is coming from our machine, assign its time to row 0
            if outgoing and seq != None and seq < max_ping_seq:
                self.rx_data[channel][0][seq] = packet.time
                
            # if the packet is coming into our machine, calculate the rtt and assign rows 1 and 2
            elif not outgoing and ackResponseId != None and ackResponseId < max_ping_seq:
                
                # We believe that this is one of the packets coming back and time of original SYN packet is already stored 
                rtt = packet.time - self.rx_data[channel][0][ackResponseId]
                self.rx_data[channel][1][ackResponseId] = packet.time
                if rtt > 0 and rtt < .5:
                    self.rx_data[channel][2][ackResponseId] = rtt
                else:
                    self.rx_data[channel][2][ackResponseId] = -.01
            else:
                # Probably a non-wlsk packet that has same ports as ours
                print("impasta!")
                continue

        # create the temporary directory
        print("Creating directory and saving the data")
        tmp_dir = os.path.join(self.output_dir, self.msg_id)
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.mkdir(tmp_dir)
        
        fig = plt.figure()
        
        for i in range(self.num_receivers):   
            csv_path = os.path.join(tmp_dir, str(i) + ".csv")
            self._save_csv(csv_path, self.rx_data[i])
            # Add Subplot
            ax = fig.add_subplot(self.num_receivers, 1, i + 1)
            ax.plot(self.rx_data[i][2], color='black', linewidth=0.1)

        # Save a Graphic of the raw data for later inspection
        plt.savefig(os.path.join(tmp_dir, "rtt.png"), dpi=600)

        # Save the sniffed packets as a .pcap file 
        wrpcap(os.path.join(tmp_dir, "capture.pcap"), self.sniffed_packets)
        
        # util_path = "tests/utilization" + str(test_id) + ".csv"
        # save_csv(util_path, util_rate)
        if self.util_rate is not None:
            # Process the data 
            average = np.average(self.util_rate[1])
            print("Average Util Rate = {}".format(average))
            print(self.util_rate[1])

            # plot the data 
            fig = plt.figure(figsize =(10,7))
            plt.boxplot(self.util_rate[1])
            plt.savefig(os.path.join(tmp_dir, "util.png"))

            # Save test results!
            util_csv_path = os.path.join(tmp_dir, "util.csv")
            self._save_csv(util_csv_path, self.util_rate)

        print("Finished Receiving Test Iteration: {}".format(self.msg_id))
        return self.rx_data

    def _save_csv(self, filename, rtt_times):
        import csv
        with open(filename, "w+") as my_csv:
            csvWriter = csv.writer(my_csv, delimiter=',')
            csvWriter.writerows(rtt_times)
        return

    def _zip_results(self, csv_data, test_name):
        import zipfile
        zip_path = test_name + '.zip'
        with zipfile.ZipFile(zip_path, mode='w') as zipF:
            zipF.write(csv_data, 'data.csv', compress_type=zipfile.ZIP_DEFLATED)
        print("Results saved to " + zip_path)  
        return          

    def _send_pings(self):
        conf.verb = False # Disable verbose mode for scapy

        # Convert hostnames into IP addresses
        for idx, val in enumerate(self.target_ips):
            print(f"target-ip: {val}")
            ip = socket.gethostbyname(val)
            self.target_ips[idx] = ip
            print("Resolving {} to {}".format(val, ip))

        if self.rx_sample_with_pings:
            # print("Sending Pings to {} on channel {}".format(target_ip, channel))
            packets = []
            for i in range(self.max_pings):
                for c in range (self.num_receivers):
                    # Create an ICMP Echo Request packet with custom payload
                    target_ip = self.target_ips[c]
                    src_addr = self.src_addrs[c]
                    packet = Ether(src=src_addr)/IP(dst=target_ip)/ICMP()/("wlsk_" + str(c) + "_" + str(i)) # type: ignore
                    packets.append(packet)
            sendp(packets, iface=self.interface, inter=self.interval/self.num_receivers)
            print("Done sending")
        else:
            # print("Sending TCP SYN frames to {} on channel {}".format(target_ip, channel))
            packets = []
            for i in range (self.max_pings):
                for c in range(self.num_receivers):
                    target_ip = self.target_ips[c]
                    src_addr = self.src_addrs[c]
                    # Doesn't this mean that the port is random?
                    packet = Ether(src=src_addr) / IP(dst=target_ip) / TCP(seq=i, sport=c, dport=80,flags="S")
                    packets.append(packet)
            print("Sending {} packets at an interval of {}".format(len(packets), self.interval / self.num_receivers))
            sendp(packets, iface=self.interface, inter=self.interval/self.num_receivers)
            print("Done sending")
        return

    def _sniff_pings(self, rx_q):
        print("Sniffing on interface: {}...".format(self.interface))
        if self.rx_sample_with_pings:
            packets = sniff(timeout=self.sniff_time_sec + 5, iface=self.interface, filter='icmp')
        else:
            packets = sniff(timeout=self.sniff_time_sec + 5, iface=self.interface, filter='tcp')
        print("Done Sniffing")
        rx_q.put(packets)
        return