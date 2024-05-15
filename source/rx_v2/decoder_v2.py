from decoder_utils import WlskDecoderUtils
from scipy.signal import find_peaks
import numpy as np


class WlskDecoder:
    
    def __init__(self,sync_word,barker_code,packet_len):
        self.utils = WlskDecoderUtils()
        self.SYNC_WORD = sync_word
        self.SYNC_WORD_LENGTH = int(len(self.SYNC_WORD) * 102)
        self.BARKER_CODE = barker_code
        self.BARKER_LENGTH = int(len(self.SYNC_WORD) * 11)
        self.PACKET_LENGTH = packet_len
        self.initialized = True
        return

    def decode_single_test(self, toa_dist, test_dir = None, test_num = 0, save_plot = False):
        toa_dist = toa_dist[0:]
        # bit_edges = []
        # x = 0

        # while x < len(toa_dist):
        #     bit_edges.append(x)
        #     x += 102.4

        # find the sync word in the raw data 
        xcorr_sync = self.utils.correlate(raw_data=toa_dist, code=self.SYNC_WORD,window_size=75)

        # Generate Cross Corelation of Barker Codes with the Received Chips 
        barker_code = [1,1,1,-1,-1,-1,1,-1,-1,1,-1]
        xcorr_barker = self.utils.correlate(raw_data=toa_dist, code=barker_code,window_size=75)

        # Find the first peak of sync word xcorr - this should be the sync word
        cutoff = 10000 #len(toa_dist) - self.SYNC_WORD_LENGTH - self.PACKET_LEGNTH * self.BARKER_LENGH
        ones_sync, _ = find_peaks(xcorr_sync, height = 1500)
        sync_indices = np.where(xcorr_sync[:cutoff] > xcorr_sync.std()*2)[0]
        # sync_indices = []
        # sync_threshold = xcorr_sync.std()*2
        # for idx, val in enumerate(xcorr_sync):
        #     if val > sync_threshold:
        #         sync_indices.append(idx)
        print("threshold for sync detect: {}".format(xcorr_sync.std()*2))
        print("cutoff is {}".format(cutoff))
        # print(xcorr_sync[sync_indices])
        # print(np.argmax(xcorr_sync[sync_indices]))
        # print(sync_indices[np.argmax(xcorr_sync[sync_indices])])
        
        
        # print(sync_start)
        # print(xcorr_sync.mean(),xcorr_sync.mean()+xcorr_sync.std()*2.5,xcorr_sync[np.where(xcorr_sync[:cutoff] > xcorr_sync.std()*2.5)])
        if len(sync_indices) == 0:
            print("Could not find the Sync Word\n")
            if save_plot:
                self.utils.plot_dist_sync_barker(toa_dist, xcorr_sync, xcorr_barker, test_dir, test_num, None,None,None,None, False)
            return None
        # if len(ones_sync) == 0 or (len(ones_sync) > 0 and ones_sync[0] > cutoff):
        #     print("Could not find the Sync Word\n")
        #     self.utils.plot_dist_sync_barker(toa_dist, xcorr_sync, xcorr_barker, test_dir, test_num, None,None,None,None, self.single_test)
        #     return None
        # sync_start = ones_sync[0]
        sync_start = sync_indices[0] if xcorr_sync[sync_indices[0]] > xcorr_sync[sync_indices[np.argmax(xcorr_sync[sync_indices])]]*.5 else sync_indices[np.argmax(xcorr_sync[sync_indices])]
        print("Using Sync Word idx: {}".format(sync_start))
        # sync_start = sync_indices[np.argmax(xcorr_sync[sync_indices])]
        # print(ones_sync,sync_start)
        # Get Peaks on the x correlation 
        ones, _ = find_peaks(xcorr_barker, height = 500)
        zeroes, _ = find_peaks(xcorr_barker * -1, height = 500)
            
        # Calculate Bit Decision X-values based on the sync word location.
        timed_xcorr_bit_windows = []
        ori_bit_windows = []
        for bit in range(1, self.PACKET_LENGTH+1):
            xval = sync_start + self.BARKER_LENGTH * bit+5*bit
            if xval < len(xcorr_barker):
                timed_xcorr_bit_windows.append(xval)
                ori_bit_windows.append(xval)
        # print(timed_xcorr_bit_windows)
        # Finally, make a bit decision at each of the bit window locations. 
        bit_sequence = []
        bit_x_vals = []
        for index in range(len(timed_xcorr_bit_windows)):
            # Handle case where we get off and are right next to a peak. 
            grace = 200 if index == 0 else 150
            point_to_evaluate = timed_xcorr_bit_windows[index]
            nearby_options = np.arange(point_to_evaluate-grace, point_to_evaluate+grace)
            # # Don't search past the end of the array. 
            # for idx, val in enumerate(nearby_options):
            #     if val > len(timed_xcorr_bit_windows):
            #         nearby_options[idx] = len(timed_xcorr_bit_windows) - 1
            # find the largest peak not just a peak
            largest_index_value_pair = [abs(xcorr_barker[point_to_evaluate]),point_to_evaluate, 200]
            
            # print(index,xcorr_barker[point_to_evaluate])
            # point_to_evaluate = np.argmax(np.abs(xcorr_barker[nearby_options]))+nearby_options[0]
            # if xcorr_barker[point_to_evaluate] > 0:
                
            #     point_to_evaluate = np.argmax(xcorr_barker[nearby_options])+nearby_options[0]
            # else:
            #     point_to_evaluate = np.argmin(xcorr_barker[nearby_options])+nearby_options[0]
            point_found = False
            if index == 0:
                for option in nearby_options:
                    if (option != point_to_evaluate) and (option in ones ):
                        # print("adjusting the point from {} to {}".format(x, option))
                        # point_to_evaluate = option
                        if (abs(point_to_evaluate -option) < largest_index_value_pair[2] and (abs(xcorr_barker[option]) >largest_index_value_pair[0]/1.8)) or (abs(xcorr_barker[option]) > 1.5*largest_index_value_pair[0]):
                            
                        # if abs(xcorr_barker[option]) > largest_index_value_pair[0] or (abs(point_to_evaluate -option) < largest_index_value_pair[2] and abs(xcorr_barker[option]) > 200):
                            largest_index_value_pair[0] = abs(xcorr_barker[option])
                            largest_index_value_pair[1] = option
                            largest_index_value_pair[2] = abs(point_to_evaluate -option)
                            point_found = True
                            # print("changing high index:",index,"to",largest_index_value_pair)
                        # break
                    elif (option != point_to_evaluate) and (option in zeroes ):
                        if (abs(point_to_evaluate -option) < largest_index_value_pair[2] and (abs(xcorr_barker[option]) >largest_index_value_pair[0]/2)) or abs(xcorr_barker[option]) > 1.5*largest_index_value_pair[0]:
                        # if abs(xcorr_barker[option]) > largest_index_value_pair[0]:
                            largest_index_value_pair[0] = abs(xcorr_barker[option])
                            largest_index_value_pair[1] = option
                            largest_index_value_pair[2] = abs(point_to_evaluate -option)
                            point_found = True
            elif abs(xcorr_barker[point_to_evaluate]) < 200:
                
                check_index = np.argmax(np.abs(xcorr_barker[nearby_options]))+nearby_options[0]
                # print(index,"close to zero",abs(xcorr_barker[check_index]),abs(xcorr_barker[largest_index_value_pair[1]]))
                if abs(xcorr_barker[check_index]) > 2 * abs(xcorr_barker[largest_index_value_pair[1]]):
                    largest_index_value_pair[1] = check_index
                adjustment = largest_index_value_pair[1]-timed_xcorr_bit_windows[index]
                timed_xcorr_bit_windows[index] += adjustment
                print(index, adjustment, timed_xcorr_bit_windows[index])
                for i,adjust_index in enumerate(range(index+1,len(timed_xcorr_bit_windows))):
                    timed_xcorr_bit_windows[adjust_index] += int(adjustment)
            # if not point_found:
            #     slope, intercept, r_value, p_value, std_err = stats.linregress(np.arange(point_to_evaluate-10,point_to_evaluate+10), xcorr_barker[np.arange(point_to_evaluate-10,point_to_evaluate+10)])
            #     if slope > 0:
            #         largest_index_value_pair[1] = np.argmax(xcorr_barker[nearby_options])+nearby_options[0]
            #     if slope < 0:
            #         largest_index_value_pair[1] = np.argmin(xcorr_barker[nearby_options])+nearby_options[0]
            #     print(index, "slope:",slope)
                        # print("changing low index:",index,"to",largest_index_value_pair)
            point_to_evaluate = largest_index_value_pair[1] # get the index that we found else it is still x
            # adjust where we are sampling
            
            
            adjustment = point_to_evaluate-timed_xcorr_bit_windows[index]
            if index==0:
            # if index == 0 or abs(adjustment) > 50:
                # print(index, adjustment, timed_xcorr_bit_windows[index])
                timed_xcorr_bit_windows[index] += adjustment
                for i,adjust_index in enumerate(range(index+1,len(timed_xcorr_bit_windows))):
                    timed_xcorr_bit_windows[adjust_index] += int(adjustment/((i+2)**2))


            if xcorr_barker[point_to_evaluate] > 0:
                bit_sequence.append(1)
            else:
                bit_sequence.append(0)

            bit_x_vals.append(point_to_evaluate)
        
        print("Eval X coordinates: {}\n".format(bit_x_vals))
        # Generate Plot showing raw data
        if save_plot:
            self.utils.plot_dist_sync_barker(toa_dist, xcorr_sync, xcorr_barker, test_dir, test_num, bit_x_vals, timed_xcorr_bit_windows,ones,zeroes, False)
        # self.utils.plot_dist_sync_barker(toa_dist, xcorr_sync, xcorr_barker, test_dir, test_num, bit_x_vals, timed_xcorr_bit_windows,ones,zeroes, self.single_test)
        # print("bit spacing: ",[timed_xcorr_bit_windows[i]-timed_xcorr_bit_windows[i-1] for i in range(1,len(timed_xcorr_bit_windows))])
        return bit_sequence
    
