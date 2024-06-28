from abc import ABC, abstractmethod
import matplotlib as plt
import numpy as np
import queue as q

class GraphObj(ABC):
    
    def __init__(self,xsz=0,title="",xlab="",ylab="",axis=None,scroll=0,init_h=0,global_t=0) -> None:
        self.input = q.Queue 
        self.xax: list = []
        self.yax: list = []
        self.ymin: int = init_h
        self.XSZ: int = xsz
        self.title: str = title
        self.xlab: str = xlab
        self.ylab: str = ylab
        self.axis: plt.Axes = axis
        self.graph = None
        self.scroll = scroll
        self.global_t: int = 0

    @abstractmethod
    def initialize(self):
        pass

    @abstractmethod
    def update(self,frame):
        pass

    
class LiveRTTPlot(GraphObj):    
    def initialize(self):            
        self.axis.set_title("Real Time* Graph of Pings Per Millisecond")
        self.scatter = self.axis.scatter(self.xax,self.yax,s=2)
        self.axis.clear()
        self.axis.set_xlim(0,10)
        self.axis.set_ylim(0,15)

    def update(self,frame):
        if self.input.qsize() >= 100:
            last_time = 0
            for _ in range(100):    
                mil_time, ppms = self.input.get()
                conv_time = mil_time - self.global_t
                last_time = conv_time
                self.xax.append(conv_time)
                self.yax.append(ppms)
                if len(self.xax) > 1000:
                    del self.xax[0]
                    del self.yax[0]
            self.scatter.set_offsets(np.c_[self.xax,self.yax])
            self.axis.set_xlim(self.xax[0],max(1,last_time))
            self.axis.set_ylim(0,max(15,max(self.yax)))
            self.axis.set_xlabel('time (ms)')
            self.axis.set_ylabel('ppms (pings)')
            self.axis.set_xticks(np.arange(min(self.xax), max(self.xax), 100))
            self.axis.set_yticks(np.arange(min(self.yax), max(self.yax)+3, 1))
            self.axis.canvas.draw()

class LivePPMSPlot(GraphObj):    
    def initialize(self):            
        self.axis.set_title("Real Time* Graph of Pings Per Millisecond")
        self.scatter = self.axis.scatter(self.xax,self.yax,s=2)
        self.axis.clear()
        self.axis.set_xlim(0,10)
        self.axis.set_ylim(0,15)

    def update(self,frame):
        if self.input.qsize() >= 100:
            last_time = 0
            for _ in range(100):    
                mil_time, ppms = self.input.get()
                conv_time = mil_time - self.global_t
                last_time = conv_time
                self.xax.append(conv_time)
                self.yax.append(ppms)
                if len(self.xax) > 1000:
                    del self.xax[0]
                    del self.yax[0]
            self.scatter.set_offsets(np.c_[self.xax,self.yax])
            self.axis.set_xlim(self.xax[0],max(1,last_time))
            self.axis.set_ylim(0,max(15,max(self.yax)))
            self.axis.set_xlabel('time (ms)')
            self.axis.set_ylabel('ppms (pings)')
            self.axis.set_xticks(np.arange(min(self.xax), max(self.xax), 100))
            self.axis.set_yticks(np.arange(min(self.yax), max(self.yax)+3, 1))
            self.axis.canvas.draw()
            
class SyncWindowPlot(GraphObj):
    def initialize(self):
        return super().initialize()
    
    def update(self, frame):
        return super().update(frame)
    
class BitWindowPlot(GraphObj):
    def initialize(self):
        return super().initialize()
    
    def update(self, frame):
        return super().update(frame)