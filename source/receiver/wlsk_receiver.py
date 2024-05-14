from sample_util import WlskChanUtilSampler
from multiprocessing import Process, Queue
from wlsk_packet import RawWlskPingPacket
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

class WlskReceiver:
    """
        I dunno what it does yet. Don't bug me about it.
    """
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
        self.max_pings = 100
        self.timeout = 30
        self.sniff_time_sec = self.max_pings * self.interval * 1.2 + 1
        self.num_receivers = 1
        self.target_ips = ["wlsk-pt-node.local"]
        self.src_addrs = ["DE:AD:BE:EF:DE:AD"]
        self.rx_sample_with_pings = False
        self.channel_util_if = "wlan0mon"
        self.collect_channel_util = False
        self.channel_util_sample_time = 45
        self.channel_util_sample_ssid = "TP-Link_13FA"
        self.util_rate = None
        
        # Runtime variables
        self.rx_q = None
        self.util_q = None
        self.rx_data = []
        self.ping_processes = []
        self.ping_process = None
        self.sniff_process = None
        self.util_sample_process = None
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
                rx_params = config_data["rx_params"]
                reflectors = config_data["reflectors"]
                utilities = config_data["utilities"]
                # RX Parameters
                self.interface = rx_params["rx_interface"]
                self.interval = rx_params["rx_ping_interval"]
                self.timeout = rx_params["rx_timeout_limit"]
                self.max_pings = rx_params["rx_max_pings"]
                self.rx_sample_with_pings = rx_params["rx_sample_with_pings"]
                # Reflector Parameters
                self.num_receivers = reflectors["num_receivers"]
                self.target_ips = reflectors["target_ips"]
                self.src_addrs = reflectors["src_addrs"]
                # Utility Parameters
                self.collect_channel_util = utilities["collect_channel_utilization"]
                self.channel_util_if = utilities["channel_util_if"]
                self.channel_util_sample_ssid = utilities["channeL_util_ssid"]
                self.channel_util_sample_time = utilities["channel_util_time"]
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
        self.rx_data = []
        for i in range(self.num_channels):
            self.rx_data.append([[0.00 for i in range(0, self.max_pings)] for j in range(3)])
        
        if self.rx_sample_with_pings:
            # Iterate through sniffed packets, calculating RTT and filling array
            def process_packet(packet_obj: RawWlskPingPacket = None):
                if packet_obj is None:
                    return
                chan = packet_obj.channel
                idx = packet_obj.index
                # Check if the spot is already filled 
                if self.rx_data[chan][0][idx] == 0:
                    # First time
                    self.rx_data[chan][0][idx] = packet_obj.timestamp
                else:
                    # This is probably the ping response. Populate the rest of the matrix
                    rtt = packet_obj.timestamp - self.rx_data[chan][0][idx]
                    if (rtt >=0 and rtt < 5):
                        self.rx_data[chan][1][idx] = packet_obj.timestamp
                        self.rx_data[chan][2][idx] = rtt
                    
            for packet in self.sniffed_packets:
                packet_obj = RawWlskPingPacket(packet)
                if packet_obj.successfully_parsed:
                    process_packet(packet_obj)
        else:
            # Iterate through sniffed packets, calculating RTT and filling array
            startTime = self.sniffed_packets[0][TCP].time
            max_ping_seq = self.max_pings
            self.rx_data[0][0][0] = startTime
            subprocess.check_output('echo "Suspicious Packets: "> sus.txt', shell=True)
            subprocess.check_output('echo "Missing Packets: "> zeroes.txt', shell=True)
            for packet in self.sniffed_packets:
                ackId = packet[TCP].ack
                ackResponseId = ackId - 1
                seq = packet[TCP].seq
                dport = packet[TCP].dport
                sport = packet[TCP].sport
                
                # Figure out which channel it is on
                channel = 0
                outgoing = True
                if dport == 80 and sport < self.num_channels:
                    channel = sport
                    outgoing = True
                elif sport == 80 and dport < self.num_channels:
                    channel = dport
                    outgoing = False
                else:
                    # Probably a non-wlsk packet sniffed. Don't process it. 
                    subprocess.check_output('echo "c: {} s: {} d: {}">> sus.txt'.format(channel, sport, dport), shell=True)
                    continue

                if outgoing and seq != None and seq < max_ping_seq:
                    self.rx_data[channel][0][seq] = packet.time
                    # if seq > 4000 and seq < 4100:
                    #     print("{} - ch{} - {} ->".format(packet.time, channel, seq))
                elif not outgoing and ackResponseId != None and ackResponseId < max_ping_seq:
                    # We believe that this is one of the packets coming back and time of original SYN packet is already stored 
                    rtt = packet.time - self.rx_data[channel][0][ackResponseId]
                    self.rx_data[channel][1][ackResponseId] = packet.time
                    if rtt > 0 and rtt < .5:
                        self.rx_data[channel][2][ackResponseId] = rtt
                    else:
                        self.rx_data[channel][2][ackResponseId] = -.01
                    # if ackResponseId > 4000 and ackResponseId < 4100:
                    #     print("{} - ch{} - {} <- RTT: {}".format(packet.time, channel, ackResponseId, rtt))
                    
                else:
                    # Probably a non-wlsk packet that has same ports as ours
                    print("impasta!")
                    continue
        
        # for idx, val in enumerate(self.rx_data[0][2]):
        #     if val == 0:
        #         a = self.rx_data[0][0][idx]
        #         b = self.rx_data[0][1][idx]
        #         c = self.rx_data[0][2][idx]
        #         subprocess.check_output('echo "Ch: 0, missing seq: {}; {} {} {}">> zeroes.txt'.format(idx,a,b,c), shell=True)

        # create the temporary directory
        print("Creating directory and saving the data")
        tmp_dir = os.path.join(self.output_dir, self.msg_id)
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.mkdir(tmp_dir)
        
        fig = plt.figure()
        
        for i in range(self.num_channels):   
            csv_path = os.path.join(tmp_dir, str(i) + ".csv")
            self._save_csv(csv_path, self.rx_data[i])
            # Add Subplot
            ax = fig.add_subplot(self.num_channels, 1, i + 1)
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
                for c in range (self.num_channels):
                    # Create an ICMP Echo Request packet with custom payload
                    target_ip = self.target_ips[c]
                    src_addr = self.src_addrs[c]
                    packet = Ether(src=src_addr)/IP(dst=target_ip)/ICMP()/("wlsk_" + str(c) + "_" + str(i))
                    packets.append(packet)
            sendp(packets, iface=self.interface, inter=self.interval/self.num_channels)
            print("Done sending")
        else:
            # print("Sending TCP SYN frames to {} on channel {}".format(target_ip, channel))
            packets = []
            for i in range (self.max_pings):
                for c in range(self.num_receivers):
                    target_ip = self.target_ips[c]
                    src_addr = self.src_addrs[c]
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
    
    def _sample_channel_util(self):
        # Create Object 
        chann_util_sampler = WlskChanUtilSampler(self.channel_util_if)
        util_rate = chann_util_sampler.measure_util_rate(self.channel_util_sample_time, self.channel_util_sample_ssid)
        self.util_q.put(util_rate)
        return