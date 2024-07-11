from matplotlib.collections import PathCollection
from matplotlib.figure import Figure
from abc import ABC, abstractmethod
from matplotlib.axes import Axes
import matplotlib.pyplot as plt
import multiprocessing as mlti
from collections import deque
from enum import Enum, auto
import typing as t
import numpy as np
import queue as q

class Packet:
    def __init__(self,seq: int = None, tin: float = None, tout: float = None, rtt: float = None):
        '''WLSK Packet:
        - seq: int - the sequence number of the packet
        - tin: float - the time the packet left the receiver node
        - tout: float - the time that the packet returned to the node
        - rtt: float - the time of flight of the packet'''
        self.s: int = seq
        self.o: float = tout
        self.i: float = tin
        self.r: float = rtt
    def __eq__(self, value: 'Packet') -> bool:
        return self.s == value.s
    def __str__(self) -> str:
        return f"PKT-{self.s}"
    def __iter__(self):
        yield self.s
        yield self.o
        yield self.i
        yield self.r

class Bucket:
    def __init__(self,mil: int = None, pkts: int = None):
        self.t: int = mil
        self.c: int = pkts
                    # with open("./DEBUG.txt","a") as file:
                    #     file.write(f"{sync_mil}\n") = pkts
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

class Message:
    def __init__(self, tstamp: float = None, msg: list[t.Literal[1,0]] = [], valid: bool = False):
        self.timestamp = tstamp
        self.message = msg
        self.len = len(msg)
        self.__valid = valid
    def add_bit(self,bit: int):
        self.message.append(bit)
        self.len += 1
    def check_vs(self,preamble: 'Message'):
        return (str(preamble) == str(self))
    def clear(self):
        self.timestamp = None
        self.message = []
        self.len = 0
        self.__valid = False
    def stamp(self):
        self.__valid = True
    def __bool__(self):
        return self.__valid
    def __len__(self):
        return self.len
    def __eq__(self, value) -> bool:
        if value == None:
            return not self.__valid
        elif type(value) == Message:
            return self.timestamp == value.timestamp
        elif type(value) == str:
            return str(self) == value
        else: return False
    def __str__(self) -> str:
        return ''.join(map(str,self.message)) if self.len > 0 else '<empty>'

class GraphComm(Enum):
    NEWMAX = auto()
    VLINES = auto()
    HLINES = auto()
    WINNUM = auto()
    # UPDATE = auto()
    
class GraphObj(ABC):
    
    def __init__(self) -> None:
        self.input:     q.Queue     = None
        self.figure:    Figure      = None
        self.axis:      Axes        = None
        self.title:     str         = None
        self.xax:       list        = None
        self.yax:       list        = None
        self.xlab:      str         = None
        self.ylab:      str         = None
        self.hlines:    list[int]   = None
        self.vlines:    list[int]   = None
        self.XSZ:       int         = None
        self.ymin:      int         = None
        self.scroll:    int         = None
        self.global_t:  int         = None
        self.graph                  = None
        self.xmax:      int         = None
        self.doUpdate:  bool        = None
        
    @abstractmethod
    def initialize(self):
        pass

    @abstractmethod
    def update(self,frame):
        pass

class UpdatingWindow(GraphObj):
    def __init__(self, xsz=0, title="", xlab="", ylab="", global_t=0) -> None:
        self.input:     q.Queue     = q.Queue()
        self.global_t:  int         = global_t
        self.title:     str         = title
        self.xlab:      str         = xlab
        self.XSZ:       int         = xsz
        self.ylab:      str         = ylab
        self.xmax:      int         = 0
        self.xmax_p:    int         = 0
        self.doUpdate:  bool        = False
        self.figure:    Figure      = None
        self.axis:      Axes        = None
        self.xax:       deque       = deque()
        self.yax:       deque       = deque()
        self.ymin:      int         = 0.1
        self.hlines:    list[int]   = []
        self.vlines:    list[int]   = []
        self.graph:     PathCollection = None
    
    def initialize(self):            
        self.axis.set_title(self.title)
        self.graph = self.axis.scatter(self.xax,self.yax,s=2)
        self.axis.clear()
        self.axis.set_xlim(0,10)
        self.axis.set_ylim(0,15)
        self.axis.set_xlabel(self.xlab)
        self.axis.set_ylabel(self.ylab)

    def update(self):
        # print(self.input.qsize())
        if self.xmax != self.xmax_p or self.hlines or self.vlines:
            self.xmax_p = self.xmax
            bucket: Bucket = self.input.get()
            conv_time = bucket.t - self.global_t
            while bucket.t <= self.xmax:
                self.xax.append(conv_time)
                self.yax.append(bucket.c)
                bucket: Bucket = self.input.get()
                conv_time = bucket.t - self.global_t
            if len(self.xax) > 0:
                while len(self.xax) > self.XSZ:
                    self.xax.popleft()
                    self.yax.popleft()
                self.graph.set_offsets(np.c_[self.xax,self.yax])
                if len(self.hlines) > 0 :
                    self.axis.hlines(self.hlines,*self.axis.get_ylim(),linestyles=['--'],)
                    self.hlines.clear()
                if len(self.vlines) > 0 :
                    self.axis.vlines(self.vlines,*self.axis.get_ylim(),linestyles=['--'])
                    self.vlines.clear()
                self.axis.set_xlim(self.xax[0],max(1,conv_time))
                self.axis.set_ylim(0,max(15,max(self.yax)))
                self.axis.set_xticks(np.arange(min(self.xax), max(self.xax), 100))
                self.axis.set_yticks(np.arange(min(self.yax), max(self.yax)+3, 1))
                self.figure.canvas.draw()
            # self.doUpdate = False
        return self.graph
    
    def __str__(self):
        return self.title
    
    
class CorrelationWindow(GraphObj):
    def __init__(self, xsz=0, title="", xlab="", ylab="", global_t=0) -> None:
        self.input:     q.Queue     = q.Queue()
        self.global_t:  int         = global_t
        self.title:     str         = title
        self.xlab:      str         = xlab
        self.XSZ:       int         = xsz
        self.ylab:      str         = ylab
        self.xmax:      int         = 0
        self.xmax_p:    int         = 0
        self.doUpdate:  bool        = False
        self.figure:    Figure      = None
        self.axis:      Axes        = None
        self.xax:       deque       = deque()
        self.yax:       deque       = deque()
        self.ymin:      int         = 0.1
        self.hlines:    list[int]   = []
        self.vlines:    list[int]   = []
        self.graph:     PathCollection = None
    
    def initialize(self):            
        self.axis.set_title(self.title)
        self.graph = self.axis.scatter(self.xax,self.yax,s=2)
        self.axis.clear()
        self.axis.set_xlim(0,10)
        self.axis.set_ylim(0,15)
        self.axis.set_xlabel(self.xlab)
        self.axis.set_ylabel(self.ylab)

    def update(self):
        # print(self.input.qsize())
        if self.xmax != self.xmax_p or self.hlines or self.vlines:
            self.xmax_p = self.xmax
            bucket: Bucket = self.input.get()
            conv_time = bucket.t - self.global_t
            while bucket.t <= self.xmax:
                self.xax.append(conv_time)
                self.yax.append(bucket.c)
                bucket: Bucket = self.input.get()
                conv_time = bucket.t - self.global_t
            if len(self.xax) > 0:
                while len(self.xax) > self.XSZ:
                    self.xax.popleft()
                    self.yax.popleft()
                self.graph.set_offsets(np.c_[self.xax,self.yax])
                if len(self.hlines) > 0 :
                    self.axis.hlines(self.hlines,*self.axis.get_ylim(),linestyles=['--'],)
                    self.hlines.clear()
                if len(self.vlines) > 0 :
                    self.axis.vlines(self.vlines,*self.axis.get_ylim(),linestyles=['--'])
                    self.vlines.clear()
                self.axis.set_xlim(self.xax[0],max(1,conv_time))
                self.axis.set_ylim(0,max(15,max(self.yax)))
                self.axis.set_xticks(np.arange(min(self.xax), max(self.xax), 100))
                self.axis.set_yticks(np.arange(min(self.yax), max(self.yax)+3, 1))
                self.figure.canvas.draw()
            # self.doUpdate = False
        return self.graph
    
    def __str__(self):
        return self.title