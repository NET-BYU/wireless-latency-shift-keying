import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.axes import Axes
import pandas as pd
import numpy as np
import csv
import sys

# This is the class that WLSK uses to store a "bucket"
class Bucket:
    def __init__(self,mil: int = None, pkts: int = None):
        self.t: int = mil
        self.c: int = pkts
    def time(self):
        return f"{self.t} ms"
    def __eq__(self, value: 'Bucket') -> bool:
        return self.t == value.t
    def __str__(self) -> str:
        return f"BKT-{self.t}"
    def __iter__(self):
        yield self.t
        yield self.c
    def __lt__(self, other: 'Bucket'):
        return self.t < other.t
    def __le__(self, other: 'Bucket'):
        return self.t <= other.t
    def __gt__(self, other: 'Bucket'):
        return self.t > other.t
    def __ge__(self, other: 'Bucket'):
        return self.t >= other.t
    def __float__(self):
        return float(self.c)
    
def import_csv(csv_path: str) -> tuple[list[int],list[int]]:
    '''takes a path returns a list of times and a list of packets received per millisecond'''
    times: list[int] = []
    packets: list[int] = []
    with open(csv_path,"r") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            times.append(int(row[0]))
            packets.append(int(row[1]))
    return times, packets

# NOTE: This is what the window would look like in the actual FSM: a deque of Bucket objects.
# This file is just a "unit conversion" from that deque to a lists of times and packets,
# but I figured I would put the option to port back here if it helped.
def port_to_Buckets(times: list[int], packets: list[int]) -> list[Bucket]:
    ''' takes a list of times and a list of packets and converts them to a list of bucket objects.'''
    buckets: list[Bucket] = []
    for i,_ in enumerate(times):
        buckets.append(Bucket(mil=times[i],pkts=packets[i]))
    return buckets

def old_correlate(data:list[int],word:list[int]) -> np.ndarray:
    ''' this is the current code ported over from the receiver_v3.py in WLSK'''
    # create the variance data from the normal data
    new_data: pd.Series = pd.Series(data)
    var_data: pd.Series = new_data.rolling(window=75).var().bfill()
    
    # upscale ones and zeros for the word conversion
    upscaled_one: list[int] = [1] * 102
    upscaled_zero: list[int] = [-1] * 102

    # Composite the correlation word into a new, huge upscaled word
    new_word: list[int] = [item for value in word for item in (upscaled_one if value == 1 else upscaled_zero)]

    # create the correlation data
    conv: np.ndarray = np.correlate(var_data,new_word,'valid')
    corr_data: np.ndarray = conv-conv.mean()
    
    # return the correlation array
    # NOTE: this is not the index of the bucket at which the strongest point is. 
    # That requires further calculation not done here.
    return corr_data

def new_correlate(data: list[int],word: list[int]) -> np.ndarray:
    ''' a template function for you to test your own correlation methods.'''
    # create the variance data from the normal data
    new_data: pd.Series = pd.Series(data)
    var_data: pd.Series = new_data.rolling(window=75).var().bfill()
    
    # upscale ones and zeros for the word conversion
    upscaled_one: list[int] = [1] * 102
    upscaled_zero: list[int] = [-1] * 102

    # Composite the correlation word into a new, huge upscaled word
    new_word: list[int] = [item for value in word for item in (upscaled_one if value == 1 else upscaled_zero)]

    # create the correlation data
    conv: np.ndarray = np.correlate(var_data,new_word,'valid')
    corr_data: np.ndarray = conv-conv.mean()
    
    # return the correlation array
    # NOTE: this is not the index of the bucket at which the strongest point is. 
    # That requires further calculation not done here.
    return corr_data

if __name__ == "__main__":
    
    csv_path: str = sys.argv[1]
    
    times: list[int]
    packets: list[int]
    times, packets = import_csv(csv_path)
    
    # Zero out the timescale - makes graphs not lag horribly
    t_start: int = times[0]
    times = [item - t_start for item in times]
    
    # the list of bits that were sent in the messages
    bitstream: list[int] = [1,0,1,0,1,0,1,0,1,1,1,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,1,1,1,0,1,0]
    # the chosen sync word in the messages
    sync_word: list[int] = [1,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,0,0,1,0,1,0,1,1,1,0,1,1,0,0,0]
    # the chosen barker code of the messages
    barker_code: list[int] = [1,1,1,-1,-1,-1,1,-1,-1,1,-1]
    # the first six bits of the message
    preamble: list[int] = [1,0,1,0,1,0]
    
    # TODO: Figure out how to correlate properly!
    # example of testing correlation on the sync word
    old_sync: np.ndarray = old_correlate(packets,sync_word)
    new_sync: np.ndarray = new_correlate(packets,sync_word)
    
    # NOTE: Graph the results. this is just the raw data
    NUM_GRAPHS = 3
    
    fig: Figure
    ax: list[Axes]
    fig, ax = plt.subplots(NUM_GRAPHS)
    ax = [ax[i] for i in range(NUM_GRAPHS)]
    
    ax[0].scatter(times,packets,s=2)
    ax[0].set_title("Packets Per Millisecond Received")
    ax[0].set_xlabel("time (ms)")
    ax[0].set_ylabel("packets received")
    
    ax[1].plot(old_sync)
    ax[1].set_title("Correlation using old method")
    
    ax[2].plot(new_sync)
    ax[2].set_title("Correlation using new method")    
    
    plt.tight_layout()
    plt.show()