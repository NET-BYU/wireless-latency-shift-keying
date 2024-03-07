import sys
from visualization_utils import WlskVisualizationUtils
import time
import matplotlib.pyplot as plt
from matplotlib import style
import json
import os
import shutil
from scapy.all import *
from scapy.all import Ether, IP, TCP, Raw
from multiprocessing import Process, Queue
import numpy as np
import subprocess


test_iter_path = sys.argv[1]

utils = WlskVisualizationUtils()


# Read the Data
data_file = os.path.join(test_iter_path, "0.csv")
time_stamps, rtt_values, return_time_stamps = utils.read_saved_data(data_file)
times_from_start = np.array([i - time_stamps[0] for i in time_stamps])

# Transpose into RX packets per millisecond
toa_dist, toa_dist_times = utils.toa_distribution(np.array(return_time_stamps))
toa_dist_times_from_start = np.array([i - toa_dist_times[0] for i in toa_dist_times])

# Get Avg. latency over time (per 1 second)
num_pings_per_second = 1/0.005
window_size = int(1 * num_pings_per_second)
rolling_avg = np.convolve(rtt_values, np.ones(window_size)/window_size, mode='valid')


# Get the Avg. throughput over time (per 1 second)
num_time_steps_per_second = 1/0.001
window_size = int(1 * num_time_steps_per_second)
rolling_tp_avg = np.convolve(toa_dist, np.ones(window_size), mode='valid')

# Plot stuff
fig, ax = plt.subplots()
        
# Overlay a line graph with means
# ax.plot(toa_dist_times_from_start, toa_dist, color="blue", linewidth=0.5, label='TCP Packets Received Per ms')
ax.plot(toa_dist_times_from_start[0:len(rolling_tp_avg)], rolling_tp_avg, color="blue", linewidth=0.75, label='TCP Packets Received Per Second')
ax2 = ax.twinx()
ax2.plot(times_from_start, rtt_values, color='gray', linewidth=0.25, label="Instantaneous Latency Per Packet")
ax2.plot(times_from_start[0:len(rolling_avg)], rolling_avg, color='red', linewidth=1, label="Average Latency Per Second")

# Customize the plot
# ax.set_xticks(range(1, n + 1))
# ax.set_xticklabels(sorted(data.keys()))
ax.set_xlabel('Time (Seconds)')
ax.set_ylim(0, 225)
ax.set_ylabel('TCP Packets Received Per Second')
ax2.set_ylabel('Latency (Seconds)')
ax2.set_ylim(0,0.2)
ax.legend(loc='upper center')
ax2.legend(loc='center')


# Show the plot
plt.tight_layout()
# plt.show()
plt.savefig("load.png", dpi=600)
