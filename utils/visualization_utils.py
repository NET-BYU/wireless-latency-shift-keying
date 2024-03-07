import csv
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import style
import os
import pandas as pd

class WlskVisualizationUtils:
    def __init__(self):
        self.initialized = True

    def read_saved_data(self, filename):
        with open(filename) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            time_stamps = []
            rtt_values = []
            return_time_stamps = []
            for row in csv_reader:
                for value in row:
                    if line_count == 0:
                        time_stamps.append(float(value))
                    elif line_count == 1:
                        return_time_stamps.append(float(value))
                    else:
                        rtt_values.append(float(value))
                line_count = line_count + 1

            # print(time_stamps)
            # print(f'Processed {line_count} lines.')
            return time_stamps, rtt_values, return_time_stamps
        
    def toa_distribution(self, toa_array):
        # search for first good data (since sometimes beginning is zeros)
        start_search_idx = 0
        while start_search_idx < len(toa_array):
            if toa_array[start_search_idx] > 0:
                break
            start_search_idx = start_search_idx + 1
        
        start_time = toa_array[start_search_idx]
        # search for last good data (Since sometimes there are 0s at the end)
        end_search_idx = len(toa_array) - 1
        while end_search_idx > 0:
            if toa_array[end_search_idx] > 0:
                break
            end_search_idx = end_search_idx - 1

        end_time = toa_array[end_search_idx]
        bin_width_sec = .001
        
        # print("len {} end at {} Value is {}".format(len(toa_array), end_search_idx, start_time))
        toa_dist_times = np.arange(start_time, end_time, bin_width_sec)
        toa_dist = np.zeros(len(toa_dist_times))

        times_sorted = 0

        for idx, time in enumerate(toa_dist_times):
            if idx >= len(toa_dist_times) - 1:
                break
            if times_sorted >= len(toa_array) - 1:
                break
            while toa_array[times_sorted] < toa_dist_times[idx + 1]:
                if toa_array[times_sorted] > 0:
                    toa_dist[idx] = toa_dist[idx] + 1
                times_sorted = times_sorted + 1
                if times_sorted >= len(toa_array) - 1:
                    break
        return pd.Series(toa_dist), toa_dist_times

    def read_channel_util_data(self, filename):
        with open(filename) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            util_data = []
            util_data_timestamps = []
            for row in csv_reader:
                for value in row:
                    if line_count == 1:
                        util_data.append(float(value))
                    else:
                        util_data_timestamps.append(float(value))
                line_count = line_count + 1

            # print(time_stamps)
            # print(f'Processed {line_count} lines.')
            return util_data, util_data_timestamps