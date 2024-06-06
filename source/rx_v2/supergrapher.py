import matplotlib.pyplot as plt
import os

class SuperGrapher:
    
    def __init__(self,directory="./"):
        
        self.plot_dir = directory
        self.toa_dist = None
        
        return
    
    def set_directory(self,directory):
        self.plot_dir = directory
        return
    
    def make_graph(self):
        
        fig = plt.figure(figsize=(30, 30))
        fig.suptitle("Testing Results".format(self.plot_dir), fontsize=25)
        
        ax1 = fig.add_subplot(3, 3, 1)
        ax1.title.set_text('Received Packets per 1 ms Interval')
        ax1.plot(self.toa_dist, color='black', linewidth=0.5)
        
        
        plt.savefig(os.path.join(self.plot_dir, "results.png"),dpi=600)
        return