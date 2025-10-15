#!/bin/bash

set -e  # exit on error

find_connector_directories() {
  # Method to find all directories matching the search term
  
  # Clean the search term (remove leading/trailing slashes)
  search_term=$(echo "$1" | sed 's:^/*::' | sed 's:/*$::')
  
  # If search term contains a slash, treat it as a path pattern
  if echo "$search_term" | grep -q '/'; then
    # First try exact match
    exact_match=$(find . -type d -path "*/$search_term" 2>/dev/null | head -n1)
    
    if [ -n "$exact_match" ]; then
      echo "$exact_match"
    else
      # If no exact match, find the root directory matching the pattern
      # Use -maxdepth to limit how deep we search, then filter
      find . -type d -path "*$search_term" -o -type d -path "*$search_term/*" 2>/dev/null \
        | while read -r dir; do
          # Only output if this is the root match (not a subdirectory of another match)
          parent_match=$(echo "$dir" | grep -o ".*/$search_term")
          if [ -n "$parent_match" ]; then
            echo "$parent_match"
          fi
        done \
        | sort -u \
        | head -n1
    fi
  else
    # Search for directory name - but only connector roots
    # Look for directories with requirements.txt, src/, or __metadata__/
    find . -type d -iname "*$search_term*" 2>/dev/null \
      | while read -r dir; do
          # Check if it's likely a connector root
          if [ -f "$dir/requirements.txt" ] || [ -d "$dir/src" ] || [ -d "$dir/__metadata__" ]; then
            echo "$dir"
          fi
        done \
      | awk -F/ '{print NF, $0}' \
      | sort -n \
      | cut -d' ' -f2-
  fi
}

CONNECTOR_METADATA_DIRECTORY="__metadata__"

echo "Adding metadata info for a connector..."

read -p "In which existing connector? (give connector folder name) " CONNECTOR_NAME

# Find matching connector directories
IFS=$'\n' read -r -d '' -a matching_directories < <(find_connector_directories "$CONNECTOR_NAME" && printf '\0')

if [ ${#matching_directories[@]} -eq 0 ]; then
    echo -e "\033[31mCould not find any directory matching: $CONNECTOR_NAME\033[0m"
    exit 1
fi

# Select the connector directory
CONNECTOR_DIRECTORY=""

if [ ${#matching_directories[@]} -eq 1 ]; then
    # Only one match found
    CONNECTOR_DIRECTORY="${matching_directories[0]}"
    echo -e "\033[33mFound this directory: $CONNECTOR_DIRECTORY\033[0m"
    
    # Ask for confirmation
    read -p "Is this the correct connector? (y/n) " ANSWER

    # ✅ Bash 3.2–compatible lowercase conversion
    ANSWER_LOWER=$(echo "$ANSWER" | tr '[:upper:]' '[:lower:]')
    
    if [[ ! "$ANSWER_LOWER" =~ ^y ]]; then
        echo "OK, then see you :)"
        exit 0
    fi
else
    # Multiple matches found
    echo -e "\033[33mFound multiple connectors matching '$CONNECTOR_NAME':\033[0m"
    echo ""
    
    for i in "${!matching_directories[@]}"; do
        # Remove leading ./ from path for cleaner display
        clean_path=$(echo "${matching_directories[$i]}" | sed 's:^\./::') 
        echo "  [$((i+1))] $clean_path"
    done
    echo "  [0] Cancel"
    echo ""
    
    read -p "Please select the connector you want to process (enter number): " selection
    
    if [ "$selection" = "0" ] || [ -z "$selection" ]; then
        echo "OK, then see you :)"
        exit 0
    fi
    
    # Validate selection is a number and in range
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        index=$((selection - 1))
        if [ $index -ge 0 ] && [ $index -lt ${#matching_directories[@]} ]; then
            CONNECTOR_DIRECTORY="${matching_directories[$index]}"
            echo ""
            echo -e "\033[32mSelected: $CONNECTOR_DIRECTORY\033[0m"
        else
            echo -e "\033[31mInvalid selection.\033[0m"
            exit 1
        fi
    else
        echo -e "\033[31mInvalid selection.\033[0m"
        exit 1
    fi
fi

if [[ "${CONNECTOR_DIRECTORY}" ]]; then
	echo "Adding info file for: " "$CONNECTOR_NAME"
	    mkdir -p "$CONNECTOR_DIRECTORY/$CONNECTOR_METADATA_DIRECTORY"

      # create metadata info
      metadata_path=$(find . -name "connector_manifest.json.sample")
      cp "$metadata_path" "$CONNECTOR_DIRECTORY/$CONNECTOR_METADATA_DIRECTORY/connector_manifest.json"

      echo "You can complete metadata for the connector."

fi
