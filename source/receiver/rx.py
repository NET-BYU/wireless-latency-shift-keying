import time
import matplotlib.pyplot as plt
from matplotlib import style
import json
import os
import shutil
from scapy.all import *
from scapy.all import Ether, IP, TCP, Raw
from multiprocessing import Process, Queue
import serial
import numpy as np
from decoder import WlskDecoderUtils, WlskDecoder
from sample_util import WlskChanUtilSampler
import socket
import subprocess
import paho.mqtt.client as mqtt


def on_message(client, userdata, msg):
    global test_iter_remote_rssi
    payload = msg.payload.decode('utf-8')
    # print("Node Update: \n\r{}".format(payload))
    try:
        message = json.loads(payload)
        rssi = message["RSSI"]
        # print("RSSI of remote node is {}".format(rssi))
        if rssi != "None":
            if int(rssi) != 0:
                print("RSSI is {}".format(int(rssi)))
                test_iter_remote_rssi.append(int(rssi))
    except Exception as e: pass
        # print("Error decoding message from MQTT: {}".format(e))


# Connect to the MQTT broker
def connect_mqtt_broker():
    mqtt_broker = "wlsk-tx-node.local"  # Change this if your MQTT broker is on a different machine
    mqtt_port = 1883  # Change this if your MQTT broker is using a different port

    client = mqtt.Client()
    client.on_message = on_message

    try:
        client.connect(mqtt_broker, mqtt_port, 60)
        client.loop_start()
        print("Connected to MQTT broker.")
    except ConnectionRefusedError:
        print("Failed to connect to MQTT broker.")
        sys.exit()

    return client


class RawWlskPingPacket:
    """
        Object to store packets parsed by sniffing the interface
        Can represent either an outgoing or an incoming ping.
        self.successfully_parsed is set to true if it is a valid WLSK ping
    """
    def __init__(self, raw_packet = None):
        self.channel = 0
        self.index = 0
        self.timestamp = 0
        self.raw_data = None
        self.successfully_parsed = False
        if raw_packet is not None:
            self.parse(raw_packet)

    def parse(self, packet):
        if packet.haslayer(Raw) and packet[Raw].load.decode()[0:4] == "wlsk":
            try:
                payload_params = packet[Raw].load.decode().split("_")
                # print(payload_params)
                self.channel = int(payload_params[1])
                self.index = int(payload_params[2])
                self.timestamp = packet.time
                self.raw_data = packet

                self.successfully_parsed = True
            except:
                print("Error Parsing Ping: {}".format(packet[Raw].load.decode()))

class WlskReceiver:
    """
        Receives raw data, and saves into directory structure:
        wlsk/tests/<output_dir>/<test_id>/channel_<channel>.zip
        Zip file contains
        - RX data array 
        - Channel Util rate (if enabled in config file)
        - Plot of raw data (if enabled in config file) 

    """
    def __init__(self, output_dir, config_path):
        # Parameters from config.json
        self.interface = "enp5s0"
        self.interval = 0.005
        self.num_pings = 100
        self.sniff_time_sec = self.num_pings * self.interval * 1.2 + 1
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
        self.test_id = 0
        self.output_dir = None
        self.sniffed_packets = None

        # Indicate whether we are ready to run
        self.initialized = False
       
        # Load Config 
        self.init_reinit(output_dir, config_path)

    def init_reinit(self, output_dir, config_path):
        self.initialized = False
        print("Initializing WLSK Receiver...")
        try:
            # Read JSON file 
            with open(config_path, 'r') as file:
                config_data = json.load(file)
            
            # Copy JSON values to memory
            rx_params = config_data["rx_params"]
            self.interface = rx_params["rx_interface"]
            self.interval = rx_params["rx_ping_interval"]
            self.num_pings = rx_params["rx_num_pings"]
            self.sniff_time_sec = self.num_pings * self.interval * 1.2 + 1
            self.num_channels = rx_params["rx_num_channels"]
            self.target_ips = rx_params["rx_target_ips"]
            self.src_addrs = rx_params["rx_src_addrs"]
            self.rx_sample_with_pings = rx_params["rx_sample_with_pings"]
            self.collect_channel_util = rx_params["collect_channel_utilization"]
            self.channel_util_if = rx_params["channel_util_if"]
            self.channel_util_sample_ssid = rx_params["channeL_util_ssid"]
            self.channel_util_sample_time = rx_params["channel_util_time"]

            # Update the Output directory
            if os.path.exists(output_dir):
                # Exists, but we are going to override it
                print("Overriding existing output directory")
                shutil.rmtree(output_dir)
            os.mkdir(output_dir)
            self.output_dir = output_dir
            self.initialized = True
            print("RX Initialized! Data will be output to: {}".format(self.output_dir))

        except Exception as e:
            print("Error initializilng WLSK RX! {}".format(e))

    def receive(self, test_id):
        # Make sure we are initialized
        if not self.initialized:
            print("Init before running RX!")
            return
        print("Starting receiver for ")
        # Clear out the RX data from previous tests
        self.rx_data = []
        self.rx_q = Queue()
        self.util_q = Queue()
        self.test_id = test_id
        self.ping_processes = []
        self.sniffed_packets = None


        # If config says so, then kick off a channel util measurement
        if self.collect_channel_util:
            self.util_sample_process = Process(target=self._sample_channel_util)

        # Multiple processes sending pings, single process collecting and parsing
        self.sniff_process = Process(target=self._sniff_pings, args=(self.rx_q,))
        # for i in range(self.num_channels):
        #     self.ping_processes.append(Process(target=self._send_pings, args=(i,)))

        self.ping_process = Process(target=self._send_pings)
        
        # Kick off processes
        if self.collect_channel_util and self.util_sample_process is not None:
            self.util_sample_process.start()
        self.sniff_process.start()
        self.ping_process.start()
        # for process in self.ping_processes:
        #     process.start()
        #     time.sleep(0.001)

    def wait(self):
        # Get result from sniffing process from Queue
        print("Obtaining the raw data from the Queue")
        self.sniffed_packets = None
        self.sniffed_packets = self.rx_q.get()
        # self.util_rate = self.util_q.get()
        print("Data successfully obtained!")
        # Close the spawned processes
        if self.collect_channel_util and self.util_sample_process is not None:
            self.util_sample_process.terminate()
            print("Closed measurement process")
        self.sniff_process.terminate()
        self.ping_process.terminate()
        print("Closed Processes")
        # for process in self.ping_processes:
        #     process.terminate()
        #     print("Closed ping process {}".format(process))

    

    def save_rx_data(self):

        # Process and save the results
        # Define 3D array for timestamps and rtt values 
        # Index in the array is the ID of the ping. 
        # Row 0 is the time of hte packet sent out 
        # Row 1 is the time the response came back for that packet 
        # Row 2 is the RTT for the ping. 
        self.rx_data = []
        for i in range(self.num_channels):
            self.rx_data.append([[0.00 for i in range(0, self.num_pings)] for j in range(3)])
        
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
            max_ping_seq = self.num_pings
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
        tmp_dir = os.path.join(self.output_dir, self.test_id)
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

        print("Finished Receiving Test Iteration: {}".format(self.test_id))
        return self.rx_data

    def _save_csv(self, filename, rtt_times):
        import csv
        with open(filename, "w+") as my_csv:
            csvWriter = csv.writer(my_csv, delimiter=',')
            csvWriter.writerows(rtt_times)

    def _zip_results(self, csv_data, test_name):
        import zipfile
        zip_path = test_name + '.zip'
        with zipfile.ZipFile(zip_path, mode='w') as zipF:
            zipF.write(csv_data, 'data.csv', compress_type=zipfile.ZIP_DEFLATED)
        print("Results saved to " + zip_path)            

    def _send_pings(self):
        conf.verb = False # Disable verbose mode for scapy

        # Convert hostnames into IP addresses
        for idx, val in enumerate(self.target_ips):
            ip = socket.gethostbyname(val)
            self.target_ips[idx] = ip
            print("Resolving {} to {}".format(val, ip))

        if self.rx_sample_with_pings:
            # print("Sending Pings to {} on channel {}".format(target_ip, channel))
            packets = []
            for i in range(self.num_pings):
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
            for i in range (self.num_pings):
                for c in range(self.num_channels):
                    target_ip = self.target_ips[c]
                    src_addr = self.src_addrs[c]
                    packet = Ether(src=src_addr) / IP(dst=target_ip) / TCP(seq=i, sport=c, dport=80,flags="S")
                    packets.append(packet)
            print("Sending {} packets at an interval of {}".format(len(packets), self.interval / self.num_channels))
            sendp(packets, iface=self.interface, inter=self.interval/self.num_channels)
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

if __name__ == "__main__":
    """
        Main routine - to be used for unit testing this module
    """
    test_iter_remote_rssi = []
    # Initialize the receiver using the config file and output directory 
    # For test in test iterations, run the receiver. 
    if len(sys.argv) < 3:
        print("Usage: sudo python3 rx.py <output_dir> <config_path>")
        sys.exit(1)
    else:
        print("Starting Receiver..\nOutput directory: {}\n \
              Config Directory: {}".format(sys.argv[1], sys.argv[2]))
    
    output_dir = sys.argv[1]
    config_path = sys.argv[2]

    rx = WlskReceiver(output_dir=output_dir, config_path=config_path)
    if not rx.initialized:
        print("Error Initializing receiver! Quitting Application..")
        sys.exit(1)

     # Read JSON file 
    with open(config_path, 'r') as file:
        config_data = json.load(file)

    test_parms = config_data["test_params"]
    num_test_iterations = test_parms["num_test_iterations"]
    tx_params = config_data["tx_params"]

    mqtt_client = None
    # Set up Connection to ESP32 Transmitters to Kick off Transmission for each RX iteration
    sers = []
    if tx_params["use_serial"]:
        try:
            serial_port_names = tx_params["serial_port_names"]
            for port in serial_port_names:
                print("Using Serial port: {}".format(port))
                ser = serial.Serial(port, 115200)
                sers.append(ser)
        except:
            print("Error Setting up Serial Ports! Aborting..")
            sys.exit()
    else:
        mqtt_client = connect_mqtt_broker()
        mqtt_client.subscribe("rssi")

    # Initialize Decoder
    decoder_utils = WlskDecoderUtils()
    decoder = WlskDecoder()


    for i in range(num_test_iterations):
        test_iter_remote_rssi= []
        # Start Receiver
        rx.receive("test_iter_{}".format(i))
        
        # Kick off Transmitter(s)
        if tx_params["use_serial"]:
            try:
                time.sleep(2)
                # for ser in sers:
                #     ser.write([i + 48])
                #     time.sleep(0.5)
                sers[0].write([i+48])
            except:
                print("Error starting a serial write to ESP32!")
                sys.exit()
        else:
            if mqtt_client is not None:
                print("Triggering TX via MQTT")
                cmd = {"test_number":i}
                mqtt_client.publish("transmit_test_dataset", json.dumps(cmd))
        
        # Wait for RX to finish
        rx.wait()
        rx_data = rx.save_rx_data()

        expected_data = tx_params["bit_sequences"][i]
        
        # Decode the received data 
        for channel, channel_rx_data in enumerate(rx_data):
            return_time_stamps_array = np.array(channel_rx_data[1])
            toa_dist, toa_dist_times = decoder_utils.toa_distribution(return_time_stamps_array)
            decode_output_dir = os.path.join(output_dir, "test_iter_{}".format(i))
            decoded_bits = decoder.decode_single_test(toa_dist, decode_output_dir, channel, True)
            print("Decoded: {}".format(decoded_bits))
            print("Expected: {}".format(expected_data))

            # Calculate BER
            if decoded_bits is not None:
                correct = 0
                for index, bit in enumerate(decoded_bits):
                    if bit == expected_data[index]:
                        correct = correct + 1
                ber = 1 - (correct / len(decoded_bits))
            else:
                ber = 1.0
            print("BER of test_iter_{} channel {} is {}\n".format(i, channel, ber))
            # save BER as file 
            ber_file = os.path.join(decode_output_dir, "{}.txt".format(channel))
            output = subprocess.check_output('echo {} > {}'.format(ber, ber_file), shell=True)
            print(output)

            if not tx_params["use_serial"]:
                # Save Remote RSSI array
                print("Saving RSSI from remote TX node: {}".format(test_iter_remote_rssi))
                rssi_average = np.average(test_iter_remote_rssi)
                print("Average is {}".format(rssi_average))
                rssi_file = os.path.join(decode_output_dir, "tx_rssi.txt")
                output = subprocess.check_output('echo {} > {}'.format(rssi_average, rssi_file), shell=True)
                print(output)              
        
        # Copy config into temp directory
        tmp_config_path = os.path.join(output_dir, "config.json")
        subprocess.check_output('cp {} {}'.format(config_path, tmp_config_path), shell=True)  
            





   


