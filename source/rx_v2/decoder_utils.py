import matplotlib.pyplot as plt
from matplotlib import style
import pandas as pd
import numpy as np
import csv
import os
from scipy.signal import correlate as corr

class WlskDecoderUtils:
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
                        rtt_values.append(float(value))
                    else:
                        return_time_stamps.append(float(value))
                line_count = line_count + 1
            return time_stamps, rtt_values, return_time_stamps

    def convert_timestamps_to_time_from_start(self, time_stamps):
        times_from_start = []
        start_time = 0.0
        for time in time_stamps:
            if time > 0:
                start_time = time
                break

        for time in time_stamps:
            times_from_start.append(time - start_time)
        return times_from_start

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
    
    def correlate(self, raw_data, code,window_size, width = 102,put_it_der = -1):
        var_data = raw_data.rolling(window=window_size).var().bfill()
        # print(var_data)
        code_upscaled = []
        upscaled_one = [1 if i < width else put_it_der for i in range(102)]
        upscaled_zero = [put_it_der for i in range(102)]
        for bit in code:
            if bit == 1:
                for bit in upscaled_one:
                    code_upscaled.append(bit)
            else:
                for bit in upscaled_zero:
                    code_upscaled.append(bit)
        # print(code_upscaled)
        conv = np.correlate(var_data,code_upscaled,"full")

        return conv-conv.mean()
    
    def plot_dist_sync_barker(self, toa_dist, xcorr_sync, xcorr_barker, test_dir, test_num, eval_x, test_raw_sample,ones, zeroes, show = False):
        # Plot the TOA Distribution
        style.use('fivethirtyeight')
        fig = plt.figure(figsize=(15, 15))
        fig.suptitle("Results for {}, Test # {}".format(test_dir, test_num), fontsize=30)

        # Raw Time of Arrival Distribution
        ax1 = fig.add_subplot(3, 1, 1)
        ax1.title.set_text('Received Packets per 1 ms Interval')
        ax1.plot(toa_dist, color='black', linewidth=0.5)
        
        # Plot the Sync Word Correlation
        ax2 = fig.add_subplot(3,1,2)
        ax2.plot(xcorr_sync, color='black', linewidth=1)
        ax2.hlines([xcorr_sync.std()*2,xcorr_sync.std()*-2],*ax2.get_xlim())
        ax2.title.set_text("Sync Word MLS Code Correlation")
    
        # Plot Barker Code Correlation
        ax3 = fig.add_subplot(3,1,3)
        ax3.plot(xcorr_barker, color='black', linewidth=1)
        if eval_x is not None:
            
            ax3.vlines(eval_x,ymin=ax3.get_ylim()[0],ymax=ax3.get_ylim()[1], colors="red",lw=1)
            # print(ones)
            ax3.plot(ones,xcorr_barker[ones],"X",color="purple")
            ax3.plot(zeroes,xcorr_barker[zeroes],"X",color="green")
            ax3.plot(eval_x, xcorr_barker[eval_x], "X",color="blue")
            for index,x in enumerate(eval_x):
                ax3.text(x-350,ax3.get_ylim()[0]+50,str(index),fontsize="x-small")
        ax3.title.set_text("Barker Code Correlation")
        
        # Display / Save the figure
        if show:
            plt.show()
        plt.savefig(os.path.join(test_dir, "{}.png".format(test_num)),dpi=600)

