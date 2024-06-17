from decoder_og import WlskDecoder as WKD
from receiver_v3 import WlskReceiver
import matplotlib.pyplot as plt
from decoder_utils import WlskDecoderUtils
from scipy.signal import find_peaks
import pandas as pd
import numpy as np
import traceback
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
        self.cutoff = 0
        self.compressed = []
        self.sync_start = -1
        self.sync_stdev = 2
        self.num_bits = 32
        self.noise_floor = 0
        self.xcorr_comp = None
        self.comp_start = -1
        self.sync_indices_comp = []
        self.rolling_avg = []
        self.total_avg = 0
        self.the_point = -1
        self.test_points = []
        self.xcorr_tests = []
        self.other_point = 0
        self.the_bits = []
        self.the_sync_bits = []
        self.name = ""
        return
    
    def set_directory(self,directory):
        self.plot_dir = directory
        return
    
    def make_graph(self):
        print("get. graph. good.")
        NUM_OF_GRAPHS = 4
        
        # in units of graphs
        length = m.ceil(m.sqrt(NUM_OF_GRAPHS))
        # in units of figsize
        size = 10 * length
        
        fig = plt.figure(figsize=(size,size))
        fig.suptitle("Results {}".format(self.name), fontsize=25)
        
        ax1 = fig.add_subplot(length, length, 1)
        ax1.title.set_text('Received Packets per 1 ms Interval')
        ax1.minorticks_on()
        ax1.plot(self.toa_dist, color='black', linewidth=0.5)
        ax1.hlines([self.noise_floor],*ax1.get_xlim(),colors=["blue"])
        ax1.vlines(self.the_bits,*ax1.get_ylim(),colors=["gray"],linestyle=':')
        ax1.vlines(self.the_sync_bits,*ax1.get_ylim(),colors=["gold"],linestyle=':')
        ax1.vlines([self.sync_start],*ax1.get_ylim(),colors=["blue"])
        ax1.vlines([self.the_point],*ax1.get_ylim(),colors=["green"],linestyle=':')
        # ax1.vlines([self.sync_start+16+102.4*n for n in range(0,32)],*ax1.get_ylim(),colors=["red"],linestyle=':')
        #+102.4*n for n in range(0,32)
        
        ax2 = fig.add_subplot(length, length, 2)
        ax2.title.set_text('sync indices by index')
        ax2.minorticks_on()
        ax2.scatter(range(0, len(self.sync_indices)), self.sync_indices, s=[3 for val in self.sync_indices],color='black')
        # ax2.vlines(self.test_points,*ax2.get_ylim(),colors=["orange"],linestyle=':')
        # ax2.vlines([self.other_point],*ax2.get_ylim(),colors=["blue"])            
        
        ax3 = fig.add_subplot(length,length,3)
        ax3.title.set_text("Sync word correlation")
        ax3.minorticks_on()
        ax3.plot(self.xcorr_sync,color='black',linewidth=1)
        ax3.hlines([self.xcorr_sync.std()*self.sync_stdev,self.xcorr_sync.std()*-self.sync_stdev],*ax3.get_xlim())
        ax3.vlines(self.the_bits,*ax3.get_ylim(),colors=["gray"],linestyle=':')
        ax3.vlines(self.the_sync_bits,*ax3.get_ylim(),colors=["gold"],linestyle=':')
        ax3.vlines([self.the_point],*ax3.get_ylim(),colors=["green"],linestyle=':')
        # ax3.vlines(self.xcorr_tests,*ax3.get_ylim(),colors=["orange"],linestyle=':')
        ax3.vlines([self.sync_start],*ax3.get_ylim(),colors=["blue"])

        # ax4 = fig.add_subplot(length, length, 4)
        # ax4.title.set_text('Compressed Packets per 1 ms Interval')
        # ax4.plot(self.compressed, color='black', linewidth=0.5)
        # ax4.hlines([self.noise_floor],*ax4.get_xlim())
        # ax4.vlines([self.comp_start+16+102.4*n for n in range(0,32)],ymin=min(self.toa_dist),ymax=max(self.toa_dist),colors=["red"],linestyle=':')
        # ax4.vlines([self.the_point],*ax4.get_ylim(),colors=["blue"],linestyle=':')
 
        # ax5 = fig.add_subplot(length, length, 5)
        # ax5.title.set_text('sync indices by index')
        # ax5.scatter(range(0, len(self.sync_indices_comp)), self.sync_indices_comp, s=[5 for val in self.sync_indices_comp])    
        
        # ax6 = fig.add_subplot(length,length,6)
        # ax6.plot(self.xcorr_comp,color='black',linewidth=1)
        # ax6.hlines([self.xcorr_comp.std()*self.sync_stdev,self.xcorr_comp.std()*-self.sync_stdev],*ax6.get_xlim())
        # # if self.sync_start != -1: ax6.vlines([self.sync_indices],ymin=min(self.xcorr_comp),ymax=max(self.xcorr_comp),linestyle=':')
        # ax6.vlines([self.cutoff],ymin=min(self.xcorr_comp),ymax=max(self.xcorr_comp),colors=["red"],linestyle=':')
        # ax6.vlines([self.comp_start],ymin=min(self.xcorr_comp),ymax=max(self.xcorr_comp),colors=["green"],linestyle=':')
        # ax6.title.set_text("Compressed correlation")
        # ax6.vlines([self.the_point],*ax6.get_ylim(),colors=["blue"],linestyle=':')
        
        # ax7 = fig.add_subplot(length,length,7)
        # ax7.plot(self.xcorr_barker,color='black',linewidth=1)
        # ax7.hlines([self.xcorr_barker.std()*self.sync_stdev,self.xcorr_barker.std()*-self.sync_stdev],*ax4.get_xlim())
        # ax7.vlines([self.sync_start],ymin=min(self.xcorr_barker),ymax=max(self.xcorr_barker),colors=["green"],linestyle=':')
        # ax7.title.set_text("Barker word correlation")
        
        ax8 = fig.add_subplot(length, length, 4)
        ax8.title.set_text('Rolling average of Packets per 1 ms Interval')
        ax8.minorticks_on()
        ax8.plot(self.rolling_avg, color='black', linewidth=0.5)
        ax8.vlines(self.the_bits,*ax8.get_ylim(),colors=["gray"],linestyle=':')
        ax8.vlines(self.the_sync_bits,*ax8.get_ylim(),colors=["gold"],linestyle=':')
        # ax8.vlines([0,self.cutoff],*ax8.get_ylim(),colors=["red"],linestyle=':')
        ax8.hlines([self.total_avg],*ax8.get_xlim(),colors=["red"])
        ax8.vlines([self.the_point],*ax8.get_ylim(),colors=["green"],linestyle=':')
        # ax8.vlines(self.xcorr_tests,*ax8.get_ylim(),colors=["orange"],linestyle=':')
        ax8.vlines([self.sync_start],*ax8.get_ylim(),colors=["blue"])
        
        plt.show()
        # plt.savefig(os.path.join(self.plot_dir, "results.png"),dpi=600)
        print("bye bye.")
        return

    def find_noise_floor(self) -> int:
        '''finds the noise floor, as in the normal amount of packets that get buffered during untouched transmission.'''

        # Create the noise distribution number of receoved pkts per ms (noise floor)
        noise_distribution = [item for item in self.toa_dist if item > 0]
        self.noise_floor = np.mean(noise_distribution) + pd.Series(noise_distribution).std()*10

    def determine_test_points(self):
        idx = 0
        STATE = 0
        
        while idx < len(self.sync_indices)-1:
            if STATE == 0:
                if self.sync_indices[idx] >= self.sync_indices[idx + 1]:
                    STATE = 1

            elif STATE == 1:
                self.test_points.append(idx)
                STATE = 2

            elif STATE == 2:
                if self.sync_indices[idx] < self.sync_indices[idx + 1]:
                    STATE = 0

            idx += 1
        
        for idx in self.test_points:
            self.xcorr_tests.append(np.where(self.xcorr_sync == self.sync_indices[idx])[0][0])
            
        return

    def decode_single_test(self, toa_dist,sync_word,barker_code, corr_width = 102,right_her=-1, util: WlskDecoderUtils = None):
        # toa_dist = toa_dist[0:]
        bit_sequence = []
        found = False
        # find the sync word in the raw data 
        # self.compressed = pd.Series([2 if item < self.noise_floor else item for item in toa_dist ])
        self.xcorr_sync = util.correlate(raw_data=self.toa_dist, code=sync_word,window_size=75,width=corr_width,put_it_der=right_her)
        # self.xcorr_comp = util.correlate(raw_data=self.compressed, code=sync_word,window_size=75,width=corr_width,put_it_der=right_her)
        # print(f"{xcorr_sync[0]} {xcorr_sync[2]} {xcorr_sync[4]}")

        # print(barker_code)
        # Generate Cross Corelation of Barker Codes with the Received Chips 
        self.xcorr_barker = util.correlate(raw_data=toa_dist, code=barker_code,window_size=75)
        # print(f"{xcorr_barker[0]} {xcorr_barker[2]} {xcorr_barker[4]}")

        # Find the first peak of sync word xcorr - this should be the sync word
        self.cutoff = len(toa_dist)#m.floor((31 * 102) + 8000) * 4

        self.sync_indices = np.where(self.xcorr_sync[:self.cutoff] > self.xcorr_sync.std()*self.sync_stdev)[0]
        # self.sync_indices = [item for item in self.xcorr_sync[:self.cutoff] if item > self.xcorr_sync.std()*self.sync_stdev]
        # self.sync_indices_comp = [item for item in self.xcorr_comp[:self.cutoff] if item > self.xcorr_comp.std()*self.sync_stdev]
        
        
        # print(f"da indices: {self.sync_indices}")
        # print(f"Max: {max(self.xcorr_comp[:self.cutoff])} Dev: {self.sync_stdev*self.xcorr_comp.std()}")
        # print("threshold for sync detect: {}".format(self.xcorr_comp.std()*self.sync_stdev))
        # print("cutoff is {}".format(self.cutoff))

        if len(self.sync_indices) == 0:
            print("Could not find the Sync Word\n")
        else:
            found = True
            print(len(self.sync_indices))
        
        try:
            print("---------------")
            self.determine_test_points()
            for test_start in range(1):#range(41790,len(toa_dist)): #self.test_points:
                bit_sequence = []
                # original sync start
                self.sync_start = self.sync_indices[0] if self.xcorr_sync[self.sync_indices[0]] > self.xcorr_sync[self.sync_indices[np.argmax(self.xcorr_sync[self.sync_indices])]]*.5 else self.sync_indices[np.argmax(self.xcorr_sync[self.sync_indices])]
                print(self.sync_start)
                # self.sync_start = np.where(self.xcorr_sync == self.sync_indices[0])[0][0] #np.where(self.xcorr_sync == max(self.sync_indices))[0][0] 
                # self.comp_start = np.where(self.xcorr_comp == self.sync_indices_comp[0])[0][0] #np.where(self.xcorr_comp == max(self.sync_indices_comp))[0][0]
                
                # old sync start for test_start iters 
                #self.sync_start = np.where(self.xcorr_sync == self.sync_indices[test_start])[0][0]
                # self.sync_start = self.the_point - 5000 + test_start
                # self.sync_start = test_start
                
                #old print statements
                # print(f"comp start: {self.comp_start}")
                # print("Using Sync Word idx: {}".format(self.sync_start))
                # Get Peaks on the x correlation 
                ones, _ = find_peaks(self.xcorr_barker, height = 500)
                # print(f"{ones[0]} {ones[2]} {ones[4]}")
                zeroes, _ = find_peaks(self.xcorr_barker * -1, height = 500)
            
                # print("bucket number: {}".format(test_start))
                # Calculate Bit Decision X-values based on the sync word location.
                timed_xcorr_bit_windows = []
                ori_bit_windows = []
                for bit in range(1, self.num_bits+1):
                    xval = self.sync_start + len(barker_code) * 102 * bit+5*bit #################### where the test point is inserted
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
                self.the_bits = bit_x_vals   
                differences = [bit_x_vals[i] - bit_x_vals[i-1] for i,_ in enumerate(bit_x_vals[1:])]
                differences = differences[1:]
                
                # print(f"differences list: {differences}")
                self.the_sync_bits = [(self.sync_start - 51 - i*(m.floor(np.mean(differences)/11))) for i in range(0,31)] 
                print("the sync bits: {}".format(self.the_sync_bits))
                # print("Eval X coordinates: {}\n".format(bit_x_vals))
                og_sequence = [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1]
                matches = True
                for i,bit in enumerate(bit_sequence):
                    if bit != og_sequence[i]: 
                        matches = False
                        break
                if matches:
                    print("Success! We found the message on the following peak:")
                    self.other_point = test_start
                    print(f"sync_idx: {self.sync_start}")
                    print(f"dec bits: {bit_sequence}")
                    print(f"org bits: {og_sequence}")
                    break
                else:
                    print(f"fail strm: {bit_sequence}")
                    
        except Exception as e:
            tb_lines = traceback.extract_tb(e.__traceback__)
            # Get the last line in the traceback, which is where the exception occurred
            last_line = tb_lines[-1]
            print(f"Error occurred on line {last_line.lineno}: {e}")
        print("---------------")
        return found, bit_sequence


    
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
    graph.name = plot_name
    sync_word = [1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,0]
    # [0,0,1,0,0,1,1,1,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,1,1,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,1,1,0,1,0,1,1,1,0,0,1,0,1,0,0,0,1]
    barker_code = [1,1,1,-1,-1,-1,1,-1,-1,1,-1]
    
    def rolling_average(data, window_size):
        if not isinstance(data, np.ndarray):
            data = np.array(data)
        
        # Use numpy's convolution function to compute the rolling average
        cumsum = np.cumsum(np.insert(data, 0, 0))
        return (cumsum[window_size:] - cumsum[:-window_size]) / float(window_size)

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
    
    graph.rolling_avg = rolling_average(graph.toa_dist,50)
    graph.total_avg = np.mean(graph.toa_dist)
    graph.rolling_avg = [item - graph.total_avg if item - graph.total_avg > 0 else 0 for item in graph.rolling_avg]  
    
    graph.the_point = graph.rolling_avg.index([item for item in graph.rolling_avg if item > graph.total_avg][0]) + (31 * 102) + 102
    print(graph.the_point)
    
    CORR_WIDTH = 102
    THIS_HER = -1
    
    graph.find_noise_floor()
    found, tbits = graph.decode_single_test(graph.toa_dist,sync_word,barker_code,corr_width=CORR_WIDTH,right_her=THIS_HER,util=utility)
    # bits = decoder.decode_single_test(graph.toa_dist)
    og_bits = [1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1]
    
    print("fs: {}\ntb: {}\nog: {}".format(found,tbits,og_bits))
    
    graph.make_graph()
    