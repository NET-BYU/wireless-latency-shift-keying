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


test_iter_path_1 = sys.argv[1]
test_iter_path_2= sys.argv[2]

utils = WlskVisualizationUtils()


# Read the Data
data_file = os.path.join(test_iter_path_1, "0.csv")
time_stamps, rtt_values, return_time_stamps = utils.read_saved_data(data_file)
times_from_start = np.array([i - time_stamps[1] for i in time_stamps])

data_file_2 = os.path.join(test_iter_path_2, "0.csv")
time_stamps_2, rtt_values_2, return_time_stamps_2 = utils.read_saved_data(data_file_2)
times_from_start_2 = np.array([i - time_stamps_2[1] for i in time_stamps_2])

# Plot stuff
ax = plt.subplot()
ax2 = plt.subplot()
        
# Overlay a line graph with means
# ax.plot(toa_dist_times_from_start, toa_dist, color="blue", linewidth=0.5, label='TCP Packets Received Per ms')
ax.plot( rtt_values, color="red", linewidth=0.75, label='TCP Packets Received Per Second')
ax2.plot( rtt_values_2, color="blue", linewidth=0.75, label='TCP Packets Received Per Second')


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
plt.show()
# plt.savefig("load.png", dpi=600)
