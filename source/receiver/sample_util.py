from scapy.all import *
from scapy.all import Ether, IP, TCP
from multiprocessing import Process, Queue
import numpy as np
import matplotlib.pyplot as plt


class WlskChanUtilSampler:

    def __init__(self, interface):
        self.sniff_time_sec = 45
        self.iface = interface

    def sample_utilization_1_sec(self, ssid, print_util=False):
        util_rates = []
        util_rates_raw = []
        # Callback function for sniffing
        def sniff_callback(pkt):
            def get_chann_util(pkt):
                if pkt.haslayer(Dot11Elt):
                    if pkt[Dot11Elt].ID == 11: # BSS Load
                        util_rate = pkt[Dot11Elt].info[2] * 100/255
                        util_rate_raw = pkt[Dot11Elt].info[2]
                        util_rates.append(util_rate)
                        util_rates_raw.append(util_rate_raw)
                        return
                    get_chann_util(pkt[Dot11Elt].payload)

            # Function to parse Beacon frames
            def parse_beacon(pkt):
                if pkt.haslayer(Dot11Beacon):
                    ssid = pkt[Dot11Elt].info.decode()
                    if ssid == ssid:
                        get_chann_util(pkt)
            
            if pkt.haslayer(Dot11):
                parse_beacon(pkt)


        # Sniff on the specified interface for Beacon frames
        sniff(iface=self.iface, prn=sniff_callback, timeout=1)
        
        if len(util_rates) == 0:
            # Network doesn't support QBSS Load? 
            return 0
        
        average = sum(util_rates) / len(util_rates)
        average_raw = sum(util_rates_raw) / len(util_rates_raw)
        average_raw_np = np.average(util_rates_raw)
        if print_util:
            print("Average Util Rate: {}%".format(average))
            print("Average Util Rate (Raw): {} ({})".format(average_raw, average_raw_np))
        return average

    def sample_utilization(self, util_q, ssid):
        num_samples = int(self.sniff_time_sec)
        util_data = [[0.00 for i in range(0, num_samples)] for j in range(2)]
        start_time = time.time()
        elapsed = time.time() - start_time
        idx = 0
        previous_print_time = time.time()
        while elapsed <= self.sniff_time_sec:
            if time.time() - previous_print_time > 5:
                # Print out channel util once every 5 seconds
                print_util = True
                previous_print_time = time.time()
            else:
                print_util = False
            if idx < num_samples:
                util_rate = self.sample_utilization_1_sec(ssid, print_util)
                util_data[1][idx] = util_rate
                util_data[0][idx] = elapsed
                idx = idx + 1
                elapsed = time.time() - start_time
        # Handle last element 
        util_data[0][-1] = util_data[0][-2]
        util_data[1][-1] = util_data[1][-2]

        print("Ending Util Sampler")
        util_q.put(util_data)

    def save_csv(self, filename, rtt_times):
        import csv
        with open(filename, "w+") as my_csv:
            csvWriter = csv.writer(my_csv, delimiter=',')
            csvWriter.writerows(rtt_times)

    def measure_util_rate(self, time_to_measure, ssid):
        util_q = Queue()
        self.sniff_time_sec = time_to_measure
        p = Process(target=self.sample_utilization, args=(util_q,ssid))
        p.start()
        util_rate = util_q.get()
        p.join()
        return util_rate


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 sample_util.py <filename> <time_to_sniff>")
    
    # Get app variables 
    sniff_time_sec = int(sys.argv[2])
    interface = "wlp7s0f4u2u4mon"
    ssid = "TP-Link_13FA"

    # Create Object 
    chann_util_sampler = WlskChanUtilSampler(interface)
    util_rate = chann_util_sampler.measure_util_rate(sniff_time_sec, ssid)

    # Process the data 
    average = np.average(util_rate[1])
    print("Average Util Rate = {}".format(average))

    # plot the data 
    fig = plt.figure(figsize =(10,7))
    plt.boxplot(util_rate[1])
    plt.show()

    # Save test results!
    util_path = sys.argv[1]
    chann_util_sampler.save_csv(util_path, util_rate)
