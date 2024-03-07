import matplotlib.pyplot as plt
import numpy as np
import sys
import os
import csv

"""
BER to Box Plot 

"""

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
    
    

util_rates = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
util_ranges = [[i-5, i+5] for i in util_rates]
print(util_ranges)

base_path = sys.argv[1]
prefix = sys.argv[2]
print("Searching for {}/{}*".format(base_path, prefix))
matching_folders = [folder for folder in os.listdir(base_path) if folder.startswith(prefix)]
print(matching_folders)
data = {}
plot_labels = []

# Prep data 
for rate in util_rates:
    data[rate] = []

def get_util_rate_category(rate):
    for idx, range_vals in enumerate(util_ranges):
        print("Checking range {}".format(range_vals))
        if rate >= range_vals[0] and rate < range_vals[1]:
            print("Found range! {}".format(range_vals))
            return util_rates[idx]
        
    print("error {} not in ranges: {}".format(rate, util_ranges))
    return None


for folder in matching_folders:
    # Get variable from folder
    plot_labels.append(folder.split("_")[-1])
    # Initialize array using folder as key to data array 
    test_iter_folders = [subfolder for subfolder in os.listdir(os.path.join(base_path, folder)) if subfolder.startswith("test_iter")]

    for test_iter_folder in sorted(test_iter_folders):
        iter_path = os.path.join(base_path, folder, test_iter_folder)

        test_folder_index = int(test_iter_folder[-1])
        print("Processing test_iter_{}".format(test_folder_index))

        # Check the Channel Utilization Rate. 
        util_filename = os.path.join(iter_path, "util.csv")
        util_data = read_channel_util_data(util_filename)
        util_avg = np.average(util_data)
        print("Average Utilization Rate: {}%".format(util_avg))

        util_rate_category = get_util_rate_category(util_avg)

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
            
            data[util_rate_category].append(value)

# Prepare data for plotting

# remove empty sets from dictionary 
temp = data.copy()
for key in temp.keys():
    if data[key] == []:
        del data[key]

n = len(data.keys())
test_vars = sorted(data.keys())
arrays = []
for var in test_vars:
    arrays.append(data[var])
    # print("Average of {} is {}, raw BERs:".format(var, np.average(data[var])))
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
    ax.text(i + 1, mean - + 0.02, f'{mean:.4f}', ha='left', va='center', color='black')

# Customize the plot
ax.set_xticks(range(1, n + 1))
ax.set_xticklabels(sorted(data.keys()))
ax.set_xlabel('Channel Utilization Rate (%)')
ax.set_ylabel('Bit Error Rate')
# ax.set_title('Box Plot with Mean Overlay')
ax.legend()


# Show the plot
plt.tight_layout()
# plt.show()
plt.savefig("box.png", dpi=600)
