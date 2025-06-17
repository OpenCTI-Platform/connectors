#!/bin/bash

set -e  # exit on error

current_path=$(find . -name "servicenow" | head -n 1)
echo $current_path

touch $current_path/tmp.py

# Handle error
#while [ "$current_path" != "/" ]; do
#  if [ "$(basename "$current_path")" = "servicenow" ]; then
#    base_dir="$current_path"
#    break
#  fi
#  current_path=$(dirname "$current_path")
#done

#if [ -z "$base_dir" ]; then
#  echo "servicenow base directory not found"
#  exit 1
#fi

# Get Python version
python_version=$(python --version)
echo "Version of Python is: $python_version"

# Install dependencies
requirements_file=$(find $current_path -name "requirements.txt")
echo 'Found requirements.txt file:' "$requirements_file"

venv_name=".temp_venv"
project=$(echo "$requirements_file" | cut -d'/' -f1-3)
echo 'Generate venv in project: ' $project

echo 'Creating isolated virtual environment'
python -m venv "$venv_name"
if [ -f "$venv_name/bin/activate" ]; then
  source "$venv_name/bin/activate"  # Linux/MacOS
elif [ -f "$venv_name/Scripts/activate" ]; then
  source "$venv_name/Scripts/activate"  # Windows
fi

echo 'Installing requirements...'
python -m pip install -q -r "$requirements_file"

# Write Python version to manifest.json in the base directory
echo "Run script and generate schema..."

python $current_path/tmp.py > "$current_path/servicenow.schema.json"
echo "Created manifest.json in $current_path"

echo "cleanup"
rm $current_path/tmp.py
rm $current_path/servicenow.schema.json
echo 'Removing virtual environment'
deactivate
rm -rf "$venv_name"