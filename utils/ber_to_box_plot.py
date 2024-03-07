import os
import re
import matplotlib.pyplot as plt
import numpy as np

# Define the path to the directory containing the test folders
base_path = "/path_to_dir/"
prefix = "test_title_"

# Find all folders that match the specified prefix
matching_folders = [folder for folder in os.listdir(base_path) if folder.startswith(prefix)]

# Initialize data storage
data = {}

# Loop through each matching folder
for folder in matching_folders:
    test_iter_folders = [subfolder for subfolder in os.listdir(os.path.join(base_path, folder)) if subfolder.startswith("test_iter_")]
    for test_iter_folder in test_iter_folders:
        iter_path = os.path.join(base_path, folder, test_iter_folder)
        channel_files = [filename for filename in os.listdir(iter_path) if filename.endswith(".txt")]
        
        for channel_file in channel_files:
            channel = os.path.splitext(channel_file)[0]
            channel_path = os.path.join(iter_path, channel_file)
            
            with open(channel_path, "r") as f:
                value = int(f.read())
            
            if test_iter_folder not in data:
                data[test_iter_folder] = {}
            data[test_iter_folder][channel] = value

# Prepare data for plotting
test_iters = sorted(data.keys())
channels = list(data[test_iters[0]].keys())
values = np.array([[data[test_iter][channel] for channel in channels] for test_iter in test_iters])

# Create box plots
plt.figure(figsize=(10, 6))
plt.boxplot(values, labels=test_iters)
plt.xlabel("Test Iteration")
plt.ylabel("Channel Value")
plt.title("Box Plot of Channel Values for Different Test Iterations")
plt.xticks(rotation=45)
plt.tight_layout()

# Show the plot
plt.show()
