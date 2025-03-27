#!/bin/bash

# Directory containing the executable files
TEST_DIR="./build/tests"

# Prompt the user to select a category
echo "Select test category to run:"
echo "1) Plain"
echo "2) HElib"
echo "3) Seal"
echo "4) TFHE"
read -p "Enter choice (1-4): " choice

# Determine the category based on user input
case $choice in
  1) CATEGORY="Plain"; PATTERN="" ;;  # No pattern needed, handle it differently
  2) CATEGORY="HElib"; PATTERN="helib" ;;
  3) CATEGORY="Seal"; PATTERN="seal" ;;
  4) CATEGORY="TFHE"; PATTERN="tfhe" ;;
  *) echo "Invalid choice!"; exit 1 ;;
esac

# Create a results directory for the selected category
RESULTS_DIR="$TEST_DIR/results/$CATEGORY"
mkdir -p "$RESULTS_DIR"

echo "Running tests for category: $CATEGORY"

# Loop through all files in the directory
for file in "$TEST_DIR"/*; do
  # Check if the file is a regular file and executable
  if [[ -f "$file" && -x "$file" ]]; then
    filename=$(basename "$file")

    # Skip source files
    if [[ "$filename" == *.cpp ]]; then
      continue
    fi
    
    # Check if the filename matches the selected category
    if [[ -z "$PATTERN" ]]; then
      # Run if it does NOT contain helib, seal, or tfhe (Plain category)
      if [[ "$filename" != *helib* && "$filename" != *seal* && "$filename" != *tfhe* ]]; then
        echo "---------------------------------"
        echo "Currently running: $filename"
        "$file" > "$RESULTS_DIR/$filename.txt" 2>&1
        echo "Finished running: $filename"
        echo "Output saved to: $RESULTS_DIR/$filename.txt"
      fi
    elif [[ "$filename" =~ $PATTERN ]]; then
      echo "---------------------------------"
      echo "Currently running: $filename"
      "$file" > "$RESULTS_DIR/$filename.txt" 2>&1
      echo "Finished running: $filename"
      echo "Output saved to: $RESULTS_DIR/$filename.txt"
    fi
  fi
done

echo "Finished running all selected tests."
