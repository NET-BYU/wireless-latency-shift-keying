from decoder_og import WlskDecoder as WKD
from receiver_v3 import WlskReceiver
import matplotlib.pyplot as plt
from decoder_utils import WlskDecoderUtils
from scipy.signal import find_peaks
import numpy as np
import math as m
import csv
import sys
import os


class SuperGrapher:
    
    def __init__(self,directory="./"):
        
        self.plot_dir = directory
        self.toa_dist = None
        self.rts_array = None
        self.xcorr_sync = None
        self.xcorr_barker = None
        self.sync_indices = []
        self.sync_start = 0
        self.sync_stdev = 2
        self.num_bits = 32
        return
    
    def set_directory(self,directory):
        self.plot_dir = directory
        return
    
    def make_graph(self):
        print("get. graph. good.")
        NUM_OF_GRAPHS = 5
        
        # in units of graphs
        length = m.ceil(m.sqrt(NUM_OF_GRAPHS))
        # in units of figsize
        size = 10 * length
        
        fig = plt.figure(figsize=(size,size))
        fig.suptitle("Testing Results".format(self.plot_dir), fontsize=25)
        
        ax1 = fig.add_subplot(length, length, 1)
        ax1.title.set_text('Received Packets per 1 ms Interval')
        ax1.plot(self.toa_dist, color='black', linewidth=0.5)
        ax1.vlines([self.sync_start+16+102.4*n for n in range(0,32)],ymin=min(self.toa_dist),ymax=max(self.toa_dist),colors=["red"])
        #+102.4*n for n in range(0,32)
        ax2 = fig.add_subplot(length, length, 2)
        ax2.title.set_text('Time of flight by packet')
        ax2.plot(self.rts_array, color='black', linewidth=0.5)        
        
        ax3 = fig.add_subplot(length,length,3)
        ax3.plot(self.xcorr_sync,color='black',linewidth=1)
        ax3.hlines([self.xcorr_sync.std()*self.sync_stdev,self.xcorr_sync.std()*-self.sync_stdev],*ax2.get_xlim())
        ax3.vlines([self.sync_indices],ymin=min(self.xcorr_sync),ymax=max(self.xcorr_sync))
        ax3.title.set_text("Sync word correlation")

        ax4 = fig.add_subplot(length,length,4)
        ax4.plot(self.xcorr_barker,color='black',linewidth=1)
        ax4.hlines([self.xcorr_barker.std()*self.sync_stdev,self.xcorr_barker.std()*-self.sync_stdev],*ax2.get_xlim())
        ax4.vlines([self.sync_start],ymin=min(self.xcorr_barker),ymax=max(self.xcorr_barker))
        ax4.title.set_text("Barker word correlation")
        
        ax5 = fig.add_subplot(length, length, 5)
        ax5.title.set_text('sync indices by index')
        ax5.plot(self.sync_indices, color='black', linewidth=0.5)    
        
        ax6 = fig.add_subplot(length,length,6)
        ax6.plot(self.xcorr_sync,color='black',linewidth=1)
        ax6.hlines([self.xcorr_sync.std()*self.sync_stdev,self.xcorr_sync.std()*-self.sync_stdev],*ax2.get_xlim())
        ax6.vlines([self.sync_indices],ymin=min(self.xcorr_sync),ymax=max(self.xcorr_sync))
        ax6.title.set_text("Sync word correlation")
        
        plt.show()
        # plt.savefig(os.path.join(self.plot_dir, "results.png"),dpi=600)
        print("bye bye.")
        return

    def decode_single_test(self, toa_dist,sync_word,barker_code, util: WlskDecoderUtils = None):
        # toa_dist = toa_dist[0:]
        bit_sequence = []
        # find the sync word in the raw data 
        # print(sync_word)
        self.xcorr_sync = util.correlate(raw_data=toa_dist, code=sync_word,window_size=75)
        # print(f"{xcorr_sync[0]} {xcorr_sync[2]} {xcorr_sync[4]}")

        # print(barker_code)
        # Generate Cross Corelation of Barker Codes with the Received Chips 
        self.xcorr_barker = util.correlate(raw_data=toa_dist, code=barker_code,window_size=75)
        # print(f"{xcorr_barker[0]} {xcorr_barker[2]} {xcorr_barker[4]}")

        # Find the first peak of sync word xcorr - this should be the sync word
        cutoff = m.floor((31 * 0.102) + 4)

        self.sync_indices = np.where(self.xcorr_sync[:cutoff] > self.xcorr_sync.std()*self.sync_stdev)[0]

        print("threshold for sync detect: {}".format(self.xcorr_sync.std()*self.sync_stdev))
        print("cutoff is {}".format(cutoff))

        if len(self.sync_indices) == 0:
            print("Could not find the Sync Word\n")
        try:
            self.sync_start = self.sync_indices[0] if self.xcorr_sync[self.sync_indices[0]] > self.xcorr_sync[self.sync_indices[np.argmax(self.xcorr_sync[self.sync_indices])]]*.5 else self.sync_indices[np.argmax(self.xcorr_sync[self.sync_indices])]
            print("Using Sync Word idx: {}".format(self.sync_start))
            # Get Peaks on the x correlation 
            ones, _ = find_peaks(self.xcorr_barker, height = 500)
            # print(f"{ones[0]} {ones[2]} {ones[4]}")
            zeroes, _ = find_peaks(self.xcorr_barker * -1, height = 500)
        
            # Calculate Bit Decision X-values based on the sync word location.
            timed_xcorr_bit_windows = []
            ori_bit_windows = []
            for bit in range(1, self.num_bits+1):
                xval = self.sync_start + len(barker_code) * 102 * bit+5*bit
                if xval < len(self.xcorr_barker):
                    timed_xcorr_bit_windows.append(xval)
                    ori_bit_windows.append(xval)
            # Finally, make a bit decision at each of the bit window locations. 
            
            bit_x_vals = []
            for index in range(len(timed_xcorr_bit_windows)):
                # Handle case where we get off and are right next to a peak. 
                grace = 200 if index == 0 else 150
                point_to_evaluate = timed_xcorr_bit_windows[index]
                nearby_options = np.arange(point_to_evaluate-grace, point_to_evaluate+grace)
                largest_index_value_pair = [abs(self.xcorr_barker[point_to_evaluate]),point_to_evaluate, 200]
                if index == 0:
                    for option in nearby_options:
                        if (option != point_to_evaluate) and (option in ones ):
                            # print("adjusting the point from {} to {}".format(x, option))
                            # point_to_evaluate = option
                            if (abs(point_to_evaluate -option) < largest_index_value_pair[2] and (abs(self.xcorr_barker[option]) >largest_index_value_pair[0]/1.8)) or (abs(self.xcorr_barker[option]) > 1.5*largest_index_value_pair[0]):
                                
                            # if abs(xcorr_barker[option]) > largest_index_value_pair[0] or (abs(point_to_evaluate -option) < largest_index_value_pair[2] and abs(xcorr_barker[option]) > 200):
                                largest_index_value_pair[0] = abs(self.xcorr_barker[option])
                                largest_index_value_pair[1] = option
                                largest_index_value_pair[2] = abs(point_to_evaluate -option)
                                # print("changing high index:",index,"to",largest_index_value_pair)
                            # break
                        elif (option != point_to_evaluate) and (option in zeroes ):
                            if (abs(point_to_evaluate -option) < largest_index_value_pair[2] and (abs(self.xcorr_barker[option]) >largest_index_value_pair[0]/2)) or abs(self.xcorr_barker[option]) > 1.5*largest_index_value_pair[0]:
                            # if abs(xcorr_barker[option]) > largest_index_value_pair[0]:
                                largest_index_value_pair[0] = abs(self.xcorr_barker[option])
                                largest_index_value_pair[1] = option
                                largest_index_value_pair[2] = abs(point_to_evaluate -option)
                elif abs(self.xcorr_barker[point_to_evaluate]) < 200:
                    
                    check_index = np.argmax(np.abs(self.xcorr_barker[nearby_options]))+nearby_options[0]
                    if abs(self.xcorr_barker[check_index]) > 2 * abs(self.xcorr_barker[largest_index_value_pair[1]]):
                        largest_index_value_pair[1] = check_index
                    adjustment = largest_index_value_pair[1]-timed_xcorr_bit_windows[index]
                    timed_xcorr_bit_windows[index] += adjustment
                    # print(index, adjustment, timed_xcorr_bit_windows[index]) 
                    for i,adjust_index in enumerate(range(index+1,len(timed_xcorr_bit_windows))):
                        timed_xcorr_bit_windows[adjust_index] += int(adjustment)
                point_to_evaluate = largest_index_value_pair[1] # get the index that we found else it is still x
                # adjust where we are sampling
                
                
                adjustment = point_to_evaluate-timed_xcorr_bit_windows[index]
                if index==0:
                    timed_xcorr_bit_windows[index] += adjustment
                    for i,adjust_index in enumerate(range(index+1,len(timed_xcorr_bit_windows))):
                        timed_xcorr_bit_windows[adjust_index] += int(adjustment/((i+2)**2))


                if self.xcorr_barker[point_to_evaluate] > 0:
                    bit_sequence.append(1)
                else:
                    bit_sequence.append(0)

                bit_x_vals.append(point_to_evaluate)
            print("Eval X coordinates: {}\n".format(bit_x_vals))
        except Exception:
            pass
        
        return bit_sequence
    
if __name__ == "__main__":
    decoder = WKD()
    receiver = WlskReceiver("config/wlsk-config-2-1.json")
    utility = WlskDecoderUtils()
    liststack = []
    rstack = []
    graph = SuperGrapher()
    plot_dir = sys.argv[1]
    plot_name = sys.argv[2]
    graph.set_directory(plot_dir)
    sync_word = [1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,0]
    barker_code = [1,1,1,-1,-1,-1,1,-1,-1,1,-1]
    
    filename = os.path.join(graph.plot_dir,plot_name)
    with open(filename,mode='r') as file:
        reader = csv.reader(file)
    
        def convert(value):
            return float(value)
            
        for row in reader:
            liststack.append([convert(value) for value in row])
            rstack.append({int(index): float(value) for index, value in enumerate(row)})
    
    # WINDOW_SIZE = 10
    # stack2 = [[],[],[]]
    # og = stack[0][0]
    # for i,item in enumerate(stack):
    #     stack2[i] = [j for j in stack[i] if (j - og < WINDOW_SIZE)]
    
    graph.rts_array = np.array(liststack[1])
    graph.toa_dist, _ = utility.toa_distribution(graph.rts_array)
    
    found = True
    tbits = graph.decode_single_test(graph.toa_dist,sync_word,barker_code,utility)
    found , rbits = True, [] #receiver._process_window(rstack)
    # bits = decoder.decode_single_test(graph.toa_dist)
    og_bits = [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1]
    
    print("fs: {}\ntb: {}\nrb: {}\nog: {}".format(found,tbits,rbits,og_bits))
    
    graph.make_graph()
    