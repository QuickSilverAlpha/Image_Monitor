#!/bin/bash

# Check if the script was given two arguments
if [ $# -ne 2 ]; then
  echo "Error: two arguments are required"
  exit 1
fi

# Save the arguments as variables
src=$1
dest=$2

# Print the action that the script is taking
echo "Moving file from $src to $dest"

# Move the file using the mv command
mv $src $dest

# Check if the mv command was successful
if [ $? -eq 0 ]; then
  # Print a success message
  echo "Move complete"
else
  # Print a failure message
  echo "Move failed"
fi

#Author: Ryan Farrior
