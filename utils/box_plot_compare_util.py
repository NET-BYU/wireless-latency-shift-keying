import matplotlib.pyplot as plt
import numpy as np
import sys
import os
import csv


file_1 = sys.argv[1]
file_2 = sys.argv[2]

def read_channel_util_data(filename):
    with open(filename) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        util_data = []
        for row in csv_reader:
            for value in row:
                if line_count == 1:
                    util_data.append(float(value))
            line_count = line_count + 1

        # print(time_stamps)
        # print(f'Processed {line_count} lines.')
        return util_data

util_data_1 = read_channel_util_data(file_1)
util_avg = np.average(util_data_1)
print("Average Utilization Rate: {}%".format(util_avg))

util_data_2 = read_channel_util_data(file_2)
util_avg = np.average(util_data_2)
print("Average Utilization Rate: {}%".format(util_avg))

arrays = [util_data_1, util_data_2]
n = len(arrays)

# Create a figure and axis
fig, ax = plt.subplots()

# Create box plots for each array
box_plot = ax.boxplot(arrays, patch_artist=False)

# Calculate the means for each array
means = [np.mean(arr) for arr in arrays]

# Overlay a line graph with means
ax.plot(range(1, n + 1), means, marker='o', linestyle='dashed', label='Mean', color="black", linewidth=0.5)

# Add mean values as text annotations
for i, mean in enumerate(means):
    ax.text(i + 1, mean + 0.2, f'{mean:.4f}', ha='right', va='top', color='black')

# Customize the plot
# ax.set_xticks(range(1, n + 1))
ax.set_xticklabels(["Without LSK", "LSK Running"])
# ax.set_xlabel('Channel Utilization Rate (%)')
ax.set_ylabel('Channel Utilization Rate (%)')
# ax.set_title('Box Plot with Mean Overlay')


# Show the plot
plt.tight_layout()
# plt.show()
plt.savefig("box.png", dpi=600)

