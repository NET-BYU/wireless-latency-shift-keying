import matplotlib.pyplot as plt
import numpy as np
import sys
import os

# Replace these with your actual arrays
# n = 5  # Number of arrays
# array_length = 20  # Length of each array
# arrays = [np.random.randn(array_length) for _ in range(n)]  # Example arrays

"""
BER to Box Plot 

This takes a folder output from one or multiple tests, and plots the BER over the test variable. 

Assumes the following: 
You have an arbitrary number of folders beginning with a prefix, and ending with "_<variable>"
Each folder contains an arbitrary number of test folders beginning with "test_iter"
Inside each test iteration folder, are text files named <channel>.txt, that contains a floating point number
that represents the BER for that test iteration for that channel. 

Output is a box plot where each box represents one set of the data, labeled <variable>, where the data from
all channels is collated into a single set. 

For example 
"""

base_path = sys.argv[1]
prefix = sys.argv[2]
print("Searching for {}/{}*".format(base_path, prefix))
matching_folders = [folder for folder in os.listdir(base_path) if folder.startswith(prefix)]
print(matching_folders)
data = {}
plot_labels = []
for folder in matching_folders:
    # Get variable from folder
    plot_labels.append(folder.split("_")[-1])
    # Initialize array using folder as key to data array 
    data[folder] = []
    test_iter_folders = [subfolder for subfolder in os.listdir(os.path.join(base_path, folder)) if subfolder.startswith("test_iter")]

    for test_iter_folder in sorted(test_iter_folders):
        iter_path = os.path.join(base_path, folder, test_iter_folder)

        test_folder_index = int(test_iter_folder[-1])
        print("Processing test_iter_{}".format(test_folder_index))

        channel_files = [filename for filename in os.listdir(iter_path) if filename.endswith(".txt")]
        avg_ber_over_all_channels = 0
        for channel_file in sorted(channel_files):
            channel = os.path.splitext(channel_file)[0]
            channel_path = os.path.join(iter_path, channel_file)
            print("Processing File: {}".format(channel_path))
            
            # Default value is 1.0
            value = 1.0
            with open(channel_path, "r") as f:
                value = float(f.read())
            
            data[folder].append(value)

# Prepare data for plotting
n = len(matching_folders)
test_vars = sorted(data.keys())
arrays = []
for var in test_vars:
    arrays.append(data[var])
    print("Average of {} is {}, raw BERs:".format(var, np.average(data[var])))
    print(data[var])





# Create a figure and axis
fig, ax = plt.subplots()

# Create box plots for each array
box_plot = ax.boxplot(arrays, patch_artist=True)

# Calculate the means for each array
means = [np.mean(arr) for arr in arrays]

# Overlay a line graph with means
ax.plot(range(1, n + 1), means, marker='o', linestyle='dashed', label='Mean', color="black", linewidth=0.5)

# Add mean values as text annotations
for i, mean in enumerate(means):
    ax.text(i + 1, mean - 0.005, f'{mean:.4f}', ha='left', va='center', color='black')

# Customize the plot
ax.set_xticks(range(1, n + 1))
# ax.set_xticklabels([f'Array {i}' for i in range(1, n + 1)])
ax.set_xticklabels(sorted(plot_labels))
ax.set_xlabel('Number of Concurrent LSK Transmissions')
ax.set_ylabel('Bit Error Rate (BER)')
# ax.set_title('Box Plot with Mean Overlay')
ax.legend()

# Adding colors to the box plots
# colors = ['lightblue', 'lightgreen', 'lightcoral', 'lightsalmon', 'lightseagreen']
# for box, color in zip(box_plot['boxes'], colors):
#     box.set_facecolor(color)

# Show the plot
plt.tight_layout()
# plt.show()
plt.savefig("box.png", dpi=600)
